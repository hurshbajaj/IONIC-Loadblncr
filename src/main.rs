mod utils;
mod structs;
mod proxies;
mod timeline;
use timeline::*;
use utils::*;
use url::Url;
use std::{process::Stdio, sync::{atomic::AtomicU64, Arc}, time::{Duration, Instant}};
use tokio::{io::AsyncReadExt, sync::Mutex};
use hyper::{
    service::{make_service_fn, service_fn}, Client, Response, Server as HyperServer
};
use anyhow::{self};

use hyperlocal::UnixClientExt;

mod CLIclient;
use CLIclient::log;

use std::sync::atomic::Ordering;

use console_subscriber;

use deadpool_redis::{Config as RedisConfig, Pool};

#[tokio::main]
async fn main() {
    let clientRun = tokio::spawn(async {
        let _ = CLIclient::establish().await;
    });
    log("Starting Loadbalancer...");

    let _ = check_startup().await;

    use tokio::fs as async_fs;
    use std::path::Path;
    use tokio::io::AsyncWriteExt; 

    {
        let config_guard = CONFIG.lock().await;
        let config_path = config_guard.redis_config_init.as_str();

        if Path::new(config_path).exists() {
            async_fs::remove_file(config_path).await.expect("Failed to delete Redis config file");
        }

        let mut config_file = async_fs::File::create(config_path)
            .await
            .expect("Failed to create Redis config file");

        let port = format!("{}", config_guard.redis_server);
        let maxmemory = format!("{}", config_guard.max_cache_mem);
        let policy = format!("{}", config_guard.cache_eviction_policy);

        config_file
            .write_all(format!("port {}\n", port).as_bytes())
            .await
            .expect("Failed to write port");

        config_file
            .write_all(format!("maxmemory {}\n", maxmemory).as_bytes())
            .await
            .expect("Failed to write maxmemory");

        config_file
            .write_all(format!("maxmemory-policy {}\n", policy).as_bytes())
            .await
            .expect("Failed to write policy");

        config_file.flush().await.expect("Failed to flush config file");

        log("Redis Config Handled");
    }

    let _redis = tokio::spawn( async {
        use tokio::process::Command as async_Command;

        let h = CONFIG.lock().await.redis_config_init.clone();

        let mut redis_proc = async_Command::new("redis-server")
            .arg(h)
            .stdout(Stdio::null())
            .stderr(Stdio::piped()) 
            .spawn()
            .unwrap_or_else(|err| {
                elog("Failed to open Redis Server connection... Restart Required");
                panic!("Process spawn failed: {}", err);
            });

        let mut stderr = redis_proc.stderr.take().expect("Failed to Capture Error [REDIS]");

        let mut stderr_output = String::new();
        stderr.read_to_string(&mut stderr_output).await.expect("Failed to read stderr");
        
        if !stderr_output.is_empty() {
            elog(stderr_output.as_str());
        }

        log("Connected to Redis Server...");
        redis_proc.wait().await.expect("Failed to wait on Redis");
    });

    {
        let config = CONFIG.lock().await;
        let server = config.servers[0].clone();
        *TARGET.lock().await = Some(server);
    }

    let mut config_guard = CONFIG.lock().await;
    let timeout_dur = config_guard.timeout_dur;
    let dos_thresh = config_guard.dos_sus_threshhold;
    let redis_port = config_guard.redis_server;
    config_guard.servers.drain(1..);

    if config_guard.dynamic{
        if config_guard.ipc{
            at_port.store(0u16, Ordering::SeqCst);
        }else{
            at_port.store(Url::parse(config_guard.servers[0].lock().await.ip.as_str()).unwrap().port().unwrap() as u16, Ordering::SeqCst);
        }
    }

    let pool: Pool = {
        let mut cfg = RedisConfig::from_url(format!("redis://127.0.0.1:{redis_port}/"));
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1)).unwrap()
    };

    log("Connected to Redis via Pool...");

    let ip_mk = [
        config_guard.host.0[0] as u8,
        config_guard.host.0[1] as u8,
        config_guard.host.0[2] as u8,
        config_guard.host.0[3] as u8,
    ];
    let port_mk = config_guard.host.1 as u16;
    let addr = (ip_mk, port_mk).into();
    let mut client;

    if config_guard.ipc{
        client = client_type::Ipc(Arc::new(Client::unix()));
    }else{
        client = client_type::Http(Arc::new(Client::new()));
    }

    drop(config_guard);

    let make_svc = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
        let remote_addr = conn.remote_addr().to_string();
        let client = client.clone();
        let timeout_dur = timeout_dur.clone();

        let pool = pool.clone();
        let thresh = dos_thresh.clone();

        async move {
            Ok::<_, anyhow::Error>(service_fn(move |req| {
                let client = client.clone();
                let remote = remote_addr.clone();

                let pool = pool.clone();
                let thresh = thresh.clone();

                async move {
                    let st = std::time::Instant::now();
                    match proxy(req, client, remote, timeout_dur.clone(), pool.clone(), thresh.clone()).await {
                        Ok(response) => {
                            let duration = st.elapsed();
                            CLIclient::rt_avg_c.write().await.push(duration.as_millis() as u64);
                            Ok::<_, anyhow::Error>(response)
                        },
                        Err(err) => {
                            Ok(Response::builder()
                                .status(hyper::StatusCode::BAD_GATEWAY)
                                .body(hyper::Body::from(err.to_string()))
                                .unwrap())
                        }
                    }
                }
            }))
        }
    });

    let server = HyperServer::bind(&addr).serve(make_svc);

    let ps = tokio::spawn(async {
        let quant = Arc::new(Mutex::new(SlidingQuantile::new(100)));
        let mut last_ban_clear = Instant::now();

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let total = RATE_LIMITS.iter().map(|v| v.value().load(Ordering::SeqCst)).sum::<u32>() as u64;
            let qg_arc = Arc::clone(&quant);
            let mut qg = qg_arc.lock().await;
            let mut cg = CONFIG.lock().await;

            if last_ban_clear.elapsed().as_secs() >= cg.ban_timeout {
                ban_list.write().await.clear();
                last_ban_clear = Instant::now();
            }

            if qg.is_anomaly(total as u32, cg.ddos_grace_factor, cg.ddos_cap, cg.dtp).await {
                CLIclient::total_ddos_a.fetch_add(1, Ordering::SeqCst);
                loop {
                    if !check_and_ban_top_ip(cg.dos_sus_threshhold).await {
                        break;
                    }
                }
            } else {
                qg.record(total as u32);
            }

            *(CLIclient::blocked_ips.write().await) = {
                ban_list.read().await.clone()
            };

            if cg.dynamic {
                if !cg.ipc{
                    if max_res_n.load(Ordering::SeqCst) as f64 > max_res_o.load(Ordering::SeqCst) as f64 * cg.server_spinup_rt_gf && max_res_o.load(Ordering::SeqCst) != 1{
                        'outer: loop{
                            if at_port.load(Ordering::SeqCst) >= cg.max_port {
                                break 'outer;
                            }
                            at_port.fetch_add(1, Ordering::SeqCst);
                            if spawn_server(cg.bin_path.as_str()){
                                let mut NewS = cg.servers.last().unwrap().clone();
                                let mut newS = NewS.lock().await;
                                cg.servers.push(Arc::new(Mutex::new(Server{ip: increment_port(newS.ip.as_str()), weight: 1, is_active: true, res_time: 0, strict_timeout: newS.strict_timeout, timeout_tick: 0, concurrent: AtomicU64::new(0)})));
                                break 'outer;
                            }
                        }
                    }

                    if max_res_o.load(Ordering::SeqCst) as f64 > max_res_n.load(Ordering::SeqCst) as f64 * cg.server_spinup_rt_gf && max_res_n.load(Ordering::SeqCst) != 1{ 
                        if cg.servers.len() > 1{
                            if kill_server().is_ok() {
                                cg.servers.last().unwrap().lock().await;
                                cg.servers.pop();
                            }
                        }
                    }
                }else{
                    if max_res_n.load(Ordering::SeqCst) as f64 > max_res_o.load(Ordering::SeqCst) as f64 * cg.server_spinup_rt_gf && max_res_o.load(Ordering::SeqCst) != 1{
                        'outer: loop{
                            if at_port.load(Ordering::SeqCst) >= cg.max_port {
                                break 'outer;
                            }
                            at_port.fetch_add(1, Ordering::SeqCst);
                            if spawn_socket(cg.bin_path.as_str(), cg.ipc_path.as_str()){
                                let mut NewS = cg.servers.last().unwrap().clone();
                                let mut newS = NewS.lock().await;
                                cg.servers.push(Arc::new(Mutex::new(Server{ip: format!("{}", at_port.load(Ordering::SeqCst)), weight: 1, is_active: true, res_time: 0, strict_timeout: newS.strict_timeout, timeout_tick: 0, concurrent: AtomicU64::new(0)})));
                                break 'outer;
                            }
                        }
                    }

                    if max_res_o.load(Ordering::SeqCst) as f64 > max_res_n.load(Ordering::SeqCst) as f64 * cg.server_spinup_rt_gf && max_res_n.load(Ordering::SeqCst) != 1{ 
                        if cg.servers.len() > 1{
                            if kill_socket(cg.ipc_path.as_str()).is_ok() {
                                cg.servers.last().unwrap().lock().await;
                                cg.servers.pop();
                            }
                        }
                    }
                }
            }

            let mut cli_names = CLIclient::server_names.write().await;
            let mut cli_names_p = vec![];
            for s in cg.servers.clone(){
                let to_push = s.lock().await;
                cli_names_p.push(to_push.ip.clone());
            }
            *cli_names = cli_names_p;
            drop(cli_names);

            let mut cli_rts = CLIclient::server_rts.write().await;
            let mut cli_rts_p = vec![];
            for s in cg.servers.clone(){
                let to_push = s.lock().await;
                cli_rts_p.push(to_push.res_time.to_string().clone());
            }
            *cli_rts = cli_rts_p;
            drop(cli_rts);

            let mut cli_ias = CLIclient::server_is_actives.write().await;
            let mut cli_ias_p = vec![];
            for s in cg.servers.clone(){
                let to_push = s.lock().await;
                cli_ias_p.push(to_push.is_active);
            }
            *cli_ias = cli_ias_p;
            drop(cli_ias);
            
            max_res_o.store(max_res_n.load(Ordering::SeqCst), Ordering::SeqCst);
            max_res_n.store(1, Ordering::SeqCst);

            Arc::clone(&RATE_LIMITS).clear();
        }
    });

    let healthCheck = tokio::spawn(async move {

        let (client, timeout_dur, servers, path, health_interval) = {
            let config = CONFIG.lock().await;
            let client;

            if config.ipc{
                client = client_type::Ipc(Arc::new(Client::unix()));
            }else{
                client = client_type::Http(Arc::new(Client::new()));
            }

            (
                client,
                config.timeout_dur,
                config.servers.clone(),
                config.health_check_path.clone(),
                config.health_check,
            )
        };

        log("Health Checks Running...");

        loop {
            let mut tasks = vec![];

            for server in servers.clone() {
                let client = client.clone();
                let path = path.clone();
                let srv = server.clone();

                tasks.push(tokio::spawn(async move {
                    health_check_proxy(client, timeout_dur, srv, path).await;
                }));
            }

            for task in tasks {
                let _ = task.await;
            }

            if let Err(e) = reorder().await {
                eprintln!("Failed to reorder servers after health check: {:?}", e);
            }
            tokio::time::sleep(Duration::from_secs(health_interval)).await;
        }
    });

    log("Load Balancer Running...");
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
        panic!();
    }
}

use hyper::header::{SET_COOKIE, LOCATION, COOKIE}; 
use urlencoding;

use crate::{proxies::{health_check_proxy, proxy}, structs::{client_type, Config, ErrorTypes, IpStruct, RateLimitMap, Server, SlidingQuantile}};

