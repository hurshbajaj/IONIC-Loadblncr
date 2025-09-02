use std::sync::Arc;
use std::{env, fs};
use std::io::{Cursor, Read, Write};
use std::process::Command;
use std::sync::atomic::Ordering;

use base64::engine::general_purpose;
use base64::Engine;
use flate2::write::{GzDecoder, GzEncoder};
use flate2::Compression;
use hmac::{Hmac, Mac};
use hyper::body::to_bytes;
use hyper::header::COOKIE;
use hyper::{Body, Request, Response};
use sha2::Sha256;
use tokio::sync::Mutex;
use url::Url;

use crate::structs::{ErrorTypes, Server};
use crate::timeline::{self, *};

use dotenv::dotenv;

type HmacSha256 = Hmac<Sha256>;

pub async fn serve_js_challenge(red: &str) -> Result<Response<Body>, hyper::Error> {
    let html = format!(
        r#"
        <html>
        <head><title>Checking your browser...</title></head>
        <body style="background-color: #0D0E11">
        <script>
          document.cookie = "jschallenge=1; path=/";
          window.location = decodeURIComponent("{}");
        </script>
        <noscript>
          <p>Please enable JavaScript to pass this challenge.</p>
        </noscript>
        </body>
        </html>
        "#,
        red
    );
    Ok(Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body(Body::from(html))
        .unwrap())
}

pub fn has_js_challenge_cookie(req: &Request<Body>) -> bool {
    if let Some(cookie_header) = req.headers().get(COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            return cookie_str.split(';').any(|kv| kv.trim_start().starts_with("jschallenge=1"));
        }
    }
    false
}

pub fn kill_server() -> anyhow::Result<()> {
    let output = Command::new("lsof")
        .arg("-t")             
        .arg(format!("-i:{}", at_port.load(Ordering::SeqCst) as u16)) 
        .output()?;            

    if output.status.success() {
        let pids = String::from_utf8_lossy(&output.stdout);
        let mut status: Option<std::process::ExitStatus> = None;

        for pid in pids.lines() {
            status = Some(Command::new("kill")
                .arg("-9")        
                .arg(pid)
                .status()?);       
        }
        if status.is_some(){
            if status.unwrap().success(){
                at_port.fetch_sub(1, Ordering::SeqCst);
            }else{
                return Err(anyhow::Error::msg(""));
            }
        }else{
            return Err(anyhow::Error::msg(""));
        }
    }

    Ok(())
}

pub fn spawn_server(bin_path: &str) -> bool {
    let port = at_port.load(Ordering::SeqCst).to_string();
    let child = Command::new(bin_path)
        .arg("--port")
        .arg(&port)
        .spawn()
        .is_ok();

    child
}

pub fn increment_port(url_str: &str) -> String {
    let mut url = Url::parse(url_str).unwrap();
    let port = url.port().unwrap();
    url.set_port(Some(port + 1)).unwrap();
    url.to_string()
}

pub fn spawn_socket(bin_path: &str, spawn_path: &str) -> bool {
    let port = at_port.load(Ordering::SeqCst).to_string();
    let child = Command::new(bin_path)
        .arg("--socket")
        .arg(format!("{}{}.sock", &spawn_path, at_port.load(Ordering::SeqCst)))
        .spawn()
        .is_ok();

    child
}

pub fn kill_socket(path: &str) -> anyhow::Result<()> {

    fs::remove_file(format!("{}{}.sock", path, at_port.load(Ordering::SeqCst)));
    at_port.fetch_sub(1, Ordering::SeqCst);
    Ok(())
}


pub fn compress_str(data: &str) -> Result<Vec<u8>, anyhow::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data.as_bytes())?;
    Ok(encoder.finish()?)
}

pub fn decompress_bytes(data: &mut [u8]) -> Result<String, anyhow::Error> {
    let cursor = Cursor::new(data);
    let mut decoder = GzDecoder::new(cursor);
    let mut decoded = String::new();
    decoder.read_to_string(&mut decoded)?;
    Ok(decoded)
}

pub async fn build_cache_key(mut req: Request<Body>, compress: bool) -> Result<Vec<u8>, anyhow::Error> {
    dotenv::dotenv().ok();

    let method = req.method().clone();
    let uri = req.uri().to_string();

    let whole_body = to_bytes(req.body_mut()).await?;
    *req.body_mut() = Body::from(whole_body.clone());

    let composite = format!(
        "CACHE:{}:{}:{}",
        method,
        uri,
        String::from_utf8_lossy(&whole_body)
    );

    if !compress{
        return Ok(composite.into_bytes())
    }

    compress_str(&composite)
}

pub fn verify_hmac_from_env(message: &str, provided_hash: &str) -> bool {
    dotenv().ok();
    let secret = match env::var("secret") {
        Ok(val) => val,
        Err(_) => return false,
    };

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let calculated_hash = general_purpose::STANDARD.encode(code_bytes);

    calculated_hash == provided_hash
}

pub fn methd_hash_from_env(message: &str) -> String {
    dotenv().ok();
    let secret = match env::var("secret") {
        Ok(val) => val,
        Err(_) => return String::new(),
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap(); 
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let calculated_hash = general_purpose::STANDARD.encode(code_bytes);

    calculated_hash
}

pub async fn check_and_ban_top_ip(max_per: u64) -> bool {
    let mut entries: Vec<_> = RATE_LIMITS
        .iter()
        .map(|kv| (kv.key().clone(), kv.value().load(Ordering::SeqCst)))
        .collect();

    entries.sort_by(|a, b| b.1.cmp(&a.1));

    // Check the top entry
    if let Some((ip, count)) = entries.first() {
        if *count as u64 > max_per {
            RATE_LIMITS.remove(ip);
            if !ban_list.read().await.contains(ip) {
                ban_list.write().await.push(ip.clone());
            }
            return true;
        }
    }
    false
}

pub async fn reorder() -> anyhow::Result<()> {
    let servers_snapshot = {
        let config = CONFIG.lock().await;
        config.servers.clone()
    };

    let mut weighted_servers: Vec<(u64, Arc<Mutex<Server>>)> = Vec::new();

    for server_arc in &servers_snapshot {
        let server = server_arc.lock().await;
        let weight = if server.is_active { server.weight } else { 0 };
        weighted_servers.push((weight, server_arc.clone()));
    }

    weighted_servers.sort_by(|a, b| b.0.cmp(&a.0));

    {
        let mut config = CONFIG.lock().await;
        config.servers = weighted_servers.into_iter().map(|(_, srv)| srv).collect();
    }

    let mut idx = atServerIdx.lock().await;
    *idx = [0, 0];

    Ok(())
}

pub fn format_error_type(err: ErrorTypes) -> String {
    format!("{:?}", err)
}
