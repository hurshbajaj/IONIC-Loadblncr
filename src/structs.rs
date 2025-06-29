
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use hyper::client::HttpConnector;
use hyper::{Body, Client};
use hyperlocal::UnixConnector;
use once_cell::sync::Lazy;
use serde::Deserialize;
use tokio::sync::Mutex;

pub type RateLimitMap = Lazy<Arc<DashMap<String, AtomicU32>>>;

#[derive(Deserialize, Clone, Default)]
pub struct IpStruct(pub [u64; 4], pub u64);

#[derive(Deserialize, Debug)]
pub struct Server {
    pub ip: String,

    #[serde(skip)]
    pub concurrent: AtomicU64,

    #[serde(skip)]
    pub weight: u64,
    pub is_active: bool,

    #[serde(skip)]
    pub res_time: u64,

    pub strict_timeout: bool,

    #[serde(skip)]
    pub timeout_tick: u16,
}

impl PartialEq for Server {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Self {
            ip: self.ip.clone(),
            concurrent: AtomicU64::new(self.concurrent.load(Ordering::Relaxed)),
            weight: self.weight,
            is_active: self.is_active,
            res_time: self.res_time,
            strict_timeout: self.strict_timeout,
            timeout_tick: self.timeout_tick,
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            ip: String::default(),

            concurrent: AtomicU64::new(0),

            weight: 0,
            is_active: false,

            res_time: 0,

            strict_timeout: false,

            timeout_tick: 0,
        }
    }
}

#[derive(Deserialize, Clone, Default)]
pub struct Config {
    pub host: IpStruct,
    pub redis_server: u64,
    pub timeout_dur: u64,
    
    pub health_check: u64,
    pub health_check_path: String,
    
    pub dos_sus_threshhold: u64,
    pub ddos_cap: u64,
    pub ddos_grace_factor: f64,
    pub ban_timeout: u64,

    pub Method_hash_check: bool, 
    pub js_challenge: bool,

    pub dynamic: bool,
    pub server_spinup_rt_gf: f64, //server spin up restime grace factor

    pub challenge_url: String,
    pub Check_out: bool,
    pub Check_in: bool,
    pub dtp: f64, //ddos threshold percentile

    #[serde(skip)]
    pub servers: Vec<Arc<Mutex<Server>>>,
    pub bin_path: String,
    pub max_port: u16,
    pub ipc_path: String,
    pub ipc: bool,

    pub min_ua_len: u64,
    pub blocked_uas: Vec<String>,
    pub max_concurrent_reqs_ps: u64,
    pub compression: bool,
    pub max_cache_mem: String,
    pub cache_eviction_policy: String,
    pub redis_config_init: String,
}

#[derive(Debug)]
pub enum ErrorTypes {
    UpstreamServerFailed,
    TimeoutError,
    NoHealthyServerFound,
    HealthCheckFailed,
    DoSsus,
    DDoSsus,
    InvalidUserAgent,
    Suspiscious,
    Load_balance_Verification_Fail,
    BadRequest,
}

pub struct SlidingQuantile {
    pub window: VecDeque<u32>,
    pub max_size: usize,
}

impl SlidingQuantile {
    pub fn new(size: usize) -> Self {

        let mut deque: VecDeque<u32> = VecDeque::with_capacity(size);
        deque.extend(std::iter::repeat(1).take(size));

        Self { window: deque, max_size: size } // vec![1, 1, 1, 1, ..]
    }

    pub fn record(&mut self, value: u32) {
        if self.window.len() == self.max_size {
            self.window.pop_front();
        }
        self.window.push_back(value.max(1)); //vec![1, 1, 1, 2]
    }

    pub fn quantile(&self, q: f64) -> u32 {
        let mut sorted: Vec<u32> = self.window.iter().cloned().collect(); //
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64) * q).floor() as usize;
        sorted.get(idx.min(sorted.len()-1)).cloned().unwrap_or(0)
    }

    pub async fn is_anomaly(&self, current: u32, threshold: f64, cap: u64, dtp: f64) -> bool {
        let q = self.quantile(dtp).min(cap as u32);
        current as f64 > (q as f64) * threshold
    }
}

#[derive(Clone)]
pub enum client_type{
    Http(Arc<Client<HttpConnector, Body>>),
    Ipc(Arc<Client<UnixConnector, Body>>)
}
