use std::fs::{self, File};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicU64};
use std::sync::Arc;

use anyhow::Context;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::structs::{Config, IpStruct, RateLimitMap, Server};
use crate::CLIclient::log;

pub static proc_shutdown: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

pub static CONFIG_pre: Lazy<Mutex<Result<Config, anyhow::Error>>> = Lazy::new(|| Mutex::new(load_from_file("./config.json")));
pub static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(Config::default()));

pub static max_res: Lazy<Mutex<u64>> =  Lazy::new(|| Mutex::new(1u64));

pub static max_res_o:  Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(1));
pub static max_res_n:  Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(1));

pub static ban_list: Lazy<RwLock<Vec<String>>> = Lazy::new(|| RwLock::new(vec![]));

pub static TARGET: Lazy<Mutex<Option<Arc<Mutex<Server>>>>> = Lazy::new(|| Mutex::new(None));

pub static atServerIdx: Lazy<Mutex<[u64; 2]>> = Lazy::new(|| Mutex::new([0u64, 0u64]));

pub static RATE_LIMITS: RateLimitMap = Lazy::new(|| {
    Arc::new(DashMap::new())
});

pub static MaxConcurrent: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0)); 

pub static at_port: Lazy<AtomicU16> = Lazy::new(|| AtomicU16::new(0));

fn load_from_file(file_path: &str) -> anyhow::Result<Config> {
    let mut file = File::open(file_path).context(format!("Failed to open file: {}", file_path))?;
    let mut json_data = String::new();
    file.read_to_string(&mut json_data).context("Failed to read file")?;

    #[derive(Deserialize)]
    struct RawConfig {
        host: IpStruct,
        redis_server: u64,
        timeout_dur: u64,
        health_check: u64,
        health_check_path: String,
        dos_sus_threshhold: u64,
        ddos_cap: u64,
        ddos_grace_factor: f64,
        ban_timeout: u64,
        servers: Vec<Server>,
        Method_hash_check: bool,
        js_challenge: bool,
        challenge_url: String,
        Check_in: bool,
        Check_out: bool, 
        dynamic: bool,
        server_spinup_rt_gf: f64,
        dtp: f64,
        max_port: u16,
        bin_path: String,

        ipc:bool,
        ipc_path:String,

        min_ua_len: u64,
        blocked_uas: Vec<String>,

        max_concurrent_reqs_ps: u64,

        compression: bool,
        max_cache_mem: String,
        cache_eviction_policy: String,
        redis_config_init: String,
    }

    let raw_config: RawConfig =
        serde_json::from_str(&json_data).context("Failed to deserialize JSON from file")?;

    log("Loading from Config...");

    let servers = raw_config
        .servers
        .into_iter()
        .map(|mut s| {s.weight = 1; Arc::new(Mutex::new(s))})
        .collect();

    Ok(Config {
        host: raw_config.host,
        redis_server: raw_config.redis_server,
        timeout_dur: raw_config.timeout_dur,
        health_check: raw_config.health_check,
        health_check_path: raw_config.health_check_path,
        dos_sus_threshhold: raw_config.dos_sus_threshhold,
        ddos_cap: raw_config.ddos_cap,
        ddos_grace_factor: raw_config.ddos_grace_factor,
        ban_timeout: raw_config.ban_timeout,
        Method_hash_check: raw_config.Method_hash_check,
        js_challenge: raw_config.js_challenge,
        challenge_url: raw_config.challenge_url,
        Check_in: raw_config.Check_in,
        Check_out: raw_config.Check_out,
        servers,
        dtp: raw_config.dtp,
        dynamic: raw_config.dynamic,
        server_spinup_rt_gf: raw_config.server_spinup_rt_gf,
        max_port: raw_config.max_port,
        bin_path: raw_config.bin_path,
        
        ipc: raw_config.ipc,
        ipc_path: raw_config.ipc_path,

        min_ua_len: raw_config.min_ua_len,
        blocked_uas: raw_config.blocked_uas,

        max_concurrent_reqs_ps: raw_config.max_concurrent_reqs_ps,
        compression: raw_config.compression,
        max_cache_mem: raw_config.max_cache_mem,
        cache_eviction_policy: raw_config.cache_eviction_policy,
        redis_config_init: raw_config.redis_config_init,

    })
}


pub static error_token: &'static str = "\x1b[31m[ERROR]\x1b[0m";

pub fn elog(value: &str) {
    log(error_token);
    log(format!("{value}").as_str());
    loop{}
}

pub fn glog(value: &str) {
    log(format!("\x1b[92m{value}\x1b[0m").as_str());
}

pub async fn check_startup() -> anyhow::Result<()> {
    let cg_p_guard = CONFIG_pre.lock().await;
    let mut port;

    if let Ok(config) = &*cg_p_guard {
        let mut cg = CONFIG.lock().await;
        *cg = config.clone(); // clone the inner Config
        port = Some(cg.host.clone());
    } else {
        elog("Failed to load from Config... Restart Needed");
        return Err(anyhow::anyhow!("Failed to load config"))
    }

    let arg = [port.clone().unwrap().0[0] as u8, port.clone().unwrap().0[1] as u8, port.clone().unwrap().0[2] as u8, port.clone().unwrap().0[3] as u8];

    if !check_port(arg, port.clone().unwrap().1 as u16){
        elog("Host Port occupied... Restart Needed");
        return Err(anyhow::anyhow!("Port Occupied"))
    }
  
    glog("[Root:Startup-Ready]");
    Ok(())
}

fn check_port(addr: [u8; 4], port: u16) -> bool {
    let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let socket = SocketAddrV4::new(ip, port);

    match TcpListener::bind(socket) {
        Ok(listener) => {
            drop(listener); 
            true
        }
        Err(_) => false,
    }
}

