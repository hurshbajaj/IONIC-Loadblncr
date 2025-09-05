use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::body::to_bytes;
use hyper::header::{HeaderName, HeaderValue, LOCATION};
use hyper::{Body, Request, Response, Uri};
use hyperlocal::Uri as local_uri;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::structs::{client_type, Config, ErrorTypes, Server};
use crate::{timeline::{self, *}, CLIclient::{self, *}};
use crate::utils::{self, *};

use deadpool_redis::Pool;
use deadpool_redis::redis::AsyncCommands;

pub async fn proxy(
    mut req: Request<Body>,
    client: client_type,
    origin_ip: String,
    timeout_dur: u64,
    redis_pool: Pool,
    _dos_threshhold: u64,
) -> Result<Response<Body>, anyhow::Error> {
    let mut config_lock_mutex = CONFIG.lock().await;

    CLIclient::total.fetch_add(1, Ordering::SeqCst);

    dos(origin_ip.clone());

    if ban_list.read().await.contains(&origin_ip.clone()){
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::DDoSsus)))
    }

    let mut check_o = false;
    
    let user_agent = req.headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let Hmac = req.headers()
        .get("X-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let methd = req.method();

    let (min_ua_len, blocked_uas) = (config_lock_mutex.min_ua_len.clone(), config_lock_mutex.blocked_uas.clone());
    if user_agent.len() < min_ua_len as usize || blocked_uas.contains(&(user_agent.to_string())) {
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::InvalidUserAgent)));
    }

    {
        if req.uri().path() == config_lock_mutex.challenge_url && config_lock_mutex.js_challenge{
            match serve_js_challenge("/").await {
                Ok(x) => return Ok(x),
                Err(_) => return Err(anyhow::Error::msg(format_error_type(ErrorTypes::Load_balance_Verification_Fail)))
            }
        }

        if config_lock_mutex.Method_hash_check{
            if config_lock_mutex.Check_in {
                if !verify_hmac_from_env(methd.to_string().as_str(), Hmac) {
                    return Err(anyhow::Error::msg(format_error_type(ErrorTypes::Suspiscious)));
                }
            }
            if config_lock_mutex.Check_out {
                check_o = true;
            }
        }
        if !has_js_challenge_cookie(&req) && config_lock_mutex.js_challenge{
            let redirect_url = format!("{}", config_lock_mutex.challenge_url);
            return Ok(Response::builder()
                .status(302)
                .header(LOCATION, redirect_url)
                .body(Body::empty())
                .unwrap());
        }
    }

    //hence graph only captures "real" reqs
    let mut count = -1;
    let mut X = CLIclient::reqs.write().await;
    *X += 1u64;
    drop(X);
    
    let mut cache_req: Request<Body>;
    (cache_req, req) = clone_request(req).await.unwrap();

    let cache_key = build_cache_key(cache_req, config_lock_mutex.compression).await.unwrap();
    
    {
        let mut conn = redis_pool.get().await?;
        match conn.get::<_, Option<Vec<u8>>>(&cache_key).await {
            Ok(Some(mut cached_value)) => {
                if config_lock_mutex.compression{
                    let decompressed = decompress_bytes(&mut cached_value)?;
                    return Ok(Response::new(Body::from(decompressed)))
                }else{
                    return Ok(Response::new(Body::from(cached_value)))
                }
            }
            _ => {}
        }
    }
    

    loop {
        let req_clone: Request<Body>;
        (req_clone, req) = clone_request(req).await.unwrap();

        if let Err(err) = updateTARGET(config_lock_mutex.clone()).await {
            return Err(err)
        }

        let guard = TARGET.lock().await;
        let target_arc = guard.clone().unwrap();
        let mut target = target_arc.lock().await;

        let mut proxied_req = Request::builder();

        let (ipc, path) = (config_lock_mutex.ipc.clone(), config_lock_mutex.ipc_path.clone());
        if ipc{
            let urii: hyper::Uri = local_uri::new(target.ip.clone(), req_clone.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")).into();
            proxied_req = Request::builder()
                .method(req_clone.method())
                .uri(urii)
                .version(req_clone.version());
        }else{
            let new_uri = format!(
                "{}{}",
                target.ip,
                req_clone.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
            )
                .parse::<Uri>()
                .expect("Failed to parse URI");

            proxied_req = Request::builder()
                .method(req_clone.method())
                .uri(new_uri)
                .version(req_clone.version());
        }

        for (key, value) in req_clone.headers() {
            proxied_req = proxied_req.header(key, value);
        }

        proxied_req = proxied_req.header("X-Forwarded-For", origin_ip.clone());
        if check_o{
            let holdd = methd_hash_from_env(req_clone.method().as_str());
            proxied_req = proxied_req.header("X-secret", holdd.as_str());
        }

        let proxied_req = proxied_req
            .body(req_clone.into_body())
            .expect("Failed to build request");

        let start = Instant::now();

        let mut timeout_result;

        let max_concurrent = config_lock_mutex.max_concurrent_reqs_ps;
        if target.concurrent.load(Ordering::SeqCst) >= max_concurrent{continue;}
        target.concurrent.fetch_add(1, Ordering::SeqCst);
        count += 1;

        match client{
            client_type::Http(ref x) => {timeout_result = timeout(Duration::from_secs(timeout_dur), x.request(proxied_req)).await;},
            client_type::Ipc(ref x) => {timeout_result = timeout(Duration::from_secs(timeout_dur), x.request(proxied_req)).await;},
        }

        target.concurrent.fetch_sub(1, Ordering::SeqCst);

        match timeout_result {
            Ok(result) => match result {
                Ok(mut response) => {
                    // for metrics + weight
                    let mut max = max_res.lock().await;
                    if start.elapsed().as_millis() as u64 > *max as u64 {
                        *max = start.elapsed().as_millis() as u64;
                    }
                    if start.elapsed().as_millis() as u64 > max_res_n.load(Ordering::SeqCst){
                        max_res_n.store(start.elapsed().as_millis() as u64, Ordering::SeqCst);
                    }
                    target.res_time = ((start.elapsed().as_millis() as u64) + target.res_time) / 2 as u64;
                    
                    if count > 0{
                        let ci = find_index::<Server>(&config_lock_mutex.servers, &target).await.unwrap();
                        let cn;
                        if ci - 1 < 0{
                            cn = config_lock_mutex.servers.len() - 1;
                        } else{
                            cn = ci-1;
                        }
                        config_lock_mutex.servers[cn].lock().await.is_active == false;
                    }

                    // cache
                    if let Some(cache_control) = response.headers().get("cache-control") {
                        if let Ok(cc_str) = cache_control.to_str() {
                            if let Ok(max_age_secs) = cc_str.parse::<usize>() {
                                if max_age_secs > 0 {
                                    let status = response.status();
                                    let version = response.version();
                                    let headers = response.headers().clone();

                                    let body_bytes = hyper::body::to_bytes(response.into_body()).await?;
                                    let body_string = String::from_utf8(body_bytes.to_vec())?;

                                    let compressed = compress_str(&body_string)?;

                                    let mut conn = redis_pool.get().await?;
                                    let compression_enable = config_lock_mutex.compression; 
                                    if compression_enable{
                                        let _ = conn.set_ex::<_, _, ()>(&cache_key, compressed, max_age_secs as u64).await;
                                    }else{
                                        let _ = conn.set_ex::<_, _, ()>(&cache_key, body_string.clone(), max_age_secs as u64).await;
                                    }

                                    let mut new_response = Response::builder()
                                        .status(status)
                                        .version(version);

                                    for (k, v) in headers.iter() {
                                        new_response = new_response.header(k, v);
                                    }

                                    let rebuilt = new_response
                                        .body(Body::from(body_string))
                                        .unwrap();

                                    return Ok(rebuilt);
                                }
                            }
                        }
                    }

                    return Ok(response)
                }
                Err(_) => {
                    if count >= 1 {
                        CLIclient::total_bad.fetch_add(1, Ordering::SeqCst);
                        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::BadRequest)))
                    }
                }
            },
            Err(_) => {
                if target.strict_timeout {
                    target.is_active = false;
                } else {
                    target.timeout_tick += 1;
                    if target.timeout_tick >= 3 {
                        target.is_active = false;
                    }
                }
                if count >= 1 {
                    return Err(anyhow::Error::msg(format_error_type(ErrorTypes::TimeoutError)))
                }
            }
        }
    };
}

async fn find_index<T>(vec: &[Arc<Mutex<T>>], target: &T) -> Option<usize>
where
    T: PartialEq + Send + Sync,
{
    for (i, item) in vec.iter().enumerate() {
        let value = item.lock().await;
        if &(*value) == target {
            return Some(i);
        }
    }
    None
}

pub async fn health_check_proxy(
    client: client_type,
    timeout_dur: u64,
    server: Arc<Mutex<Server>>,
    health_check_path: String
) -> Result<Response<Body>, anyhow::Error> {

    let target_arc = server.clone();
    let mut target = target_arc.lock().await; 

    let mut req = Request::builder().body(Body::empty()).unwrap();

    let ipc = {
        let g = CONFIG.lock().await;
        g.ipc.clone()
    };

    if ipc{
        let urii: hyper::Uri = local_uri::new(target.ip.clone(), health_check_path.as_str()).into();
        req = Request::builder()
            .method("GET")
            .uri(urii)
            .body(Body::empty())
            .unwrap();
    }else{
        let new_uri = format!(
            "{}{}",
            target.ip,
            health_check_path
            )
            .parse::<Uri>()
            .expect("Failed to parse URI");

        req = Request::builder()
            .method("GET")
            .uri(new_uri)
            .body(Body::empty())
            .unwrap();
    }

    let timeout_result;

    match client{
        client_type::Http(ref x) => {timeout_result = timeout(Duration::from_secs(timeout_dur), x.request(req)).await;},
        client_type::Ipc(ref x) => {timeout_result = timeout(Duration::from_secs(timeout_dur), x.request(req)).await;},
    }

    match timeout_result {
        Ok(result) => match result {
            Ok(response) => {
                target.is_active = true;
                if *max_res.lock().await != 0{
                    target.weight = ( ( 1-(target.res_time / *(max_res.lock().await) as u64 ) ) * 10 ) as u64;
                }
                Ok(response)
            }
            
            Err(_) => {target.is_active = false; Err(anyhow::Error::msg(format_error_type(ErrorTypes::HealthCheckFailed)))}, 
        },
        Err(_) => {
            target.is_active = false;
            Err(anyhow::Error::msg(format_error_type(ErrorTypes::TimeoutError)))
        }
    }
}

fn dos(ip: String){
    let now = Instant::now();

    let mut entry = RATE_LIMITS.entry(ip.clone()).or_insert_with(|| AtomicU32::new(0));

    entry.fetch_add(1, Ordering::SeqCst);
}

async fn clone_request(req: Request<Body>) -> Result<(Request<Body>, Request<Body>), hyper::Error> {

    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body).await.unwrap();

    let mut req1 = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version.clone())
        .body(Body::from(bytes.clone()))
        .unwrap();

    let mut req2 = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version.clone())
        .body(Body::from(bytes.clone()))
        .unwrap();

    for (key, value) in parts.headers.clone() {
        let header_name = HeaderName::from_str(key.unwrap().to_string().as_str()).unwrap();
        let header_value = HeaderValue::from_str(value.to_str().unwrap()).unwrap();
        req1.headers_mut().insert(
            header_name.clone(),
            header_value.clone(),
        );
        req2.headers_mut().insert(
            header_name,
            header_value,
        );
    }

    Ok((req1, req2))
} 

async fn updateTARGET(config: Config) -> anyhow::Result<()> {
    let (servers, mut at_idx) = {
        let mut at_server_idx = atServerIdx.lock().await;

        if proc_shutdown.lock().await.clone() {
            return Err(anyhow::anyhow!("No available server"));
        }
        if config.servers.is_empty() {
            return Err(anyhow::anyhow!("No servers available in config."));
        }

        if at_server_idx[1] >= config.servers[at_server_idx[0] as usize].lock().await.weight {
            at_server_idx[1] = 0;
            at_server_idx[0] = (at_server_idx[0] + 1) % config.servers.len() as u64;
        } else {
            at_server_idx[1] += 1;
        }

        (config.servers.clone(), *at_server_idx)
    };

    let mut found_healthy = false;
    let mut checked = 0;
    let mut current_idx = at_idx[0];

    while !found_healthy && checked < servers.len() {
        let server = servers[current_idx as usize].clone();
        {
            let server_guard = server.lock().await;
            if server_guard.is_active {
                found_healthy = true;
            }
        } 

        if found_healthy {
            *TARGET.lock().await = Some(server);
            let mut at_server_idx = atServerIdx.lock().await;
            *at_server_idx = [current_idx, 0];
            return Ok(());
        }

        current_idx = (current_idx + 1) % servers.len() as u64;
        checked += 1;
    }

    Err(anyhow::anyhow!(format_error_type(ErrorTypes::NoHealthyServerFound)))
}

