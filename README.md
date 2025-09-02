# ✨ IONIC-Loadblncr

### 👋 Welcome
To the one of the most **Featureful** loadbalancers you will ever see... **Strong** enough  
    to balance as many servers you would want to throw at it under conditions absurd enough to your heart's desire- but **lightweight** enough to be suited to all your needs- even for just a hobby project!

Complete with

    - Health Checks
    - Fastest Server First Ideolegy
    - Timeouts
        * Strict
        * Lenient
    - Weighted Round Robin
    - Safe Request Handling with Arc / Async Mutex
    - Custom Reverse Proxy
    - Inactive Servers due to Timeout Window revaluation
    - Failovers
    - DDoS / Dos Proofing
    - DDoS threshold via | Sliding Quantile | & | dynamic |
    - Dos threshold | manual | & | static |
    - Redis Cache
    - Method Hash Verification (HMAC) | JS challenge
    - IPC support
    - A full fledged Metrics-System
    - Graceful Shutdown with Proper Cleanup procedures... And MUCH MORE!
Feel free to scroll to the bottom for a little sneak-peak of the Loadbalancer's CLI in action 🔥

## 📦 Use

**To get started, feel free to use any terminal you're comfortable in. Although the reccomended one would be WSL : This setup guide assumes you have git installed**

Now we need to make sure Rust / Cargo are installed.
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Add it to your path if you need to. Now to clone this repo
```bash
git clone https://github.com/hurshbajaj/IONIC-Loadblncr
```
Next add the following Rust-Flag to your environment variable for the loadbalancer to function neatly

```bash
export RUSTFLAGS="--cfg tokio_unstable"
```

After this simply build the program using

```
cargo build --release
```
Navigate to *Target > Release* and run the binary.

## ⚙️ Config

The Config you'll find will probably look something like 
```json
"host": [[127, 0, 0, 1], 3000],

"redis_server": 3005,
"compression": true,
"max_cache_mem": "100000000000mb",
"cache_eviction_policy": "allkeys-lru",
"redis_config_init": "/tmp/lb/redis_lb.conf",

"health_check": 5,
"health_check_path": "/",

"min_ua_len":0,
"blocked_uas": [],

"dos_sus_threshhold": 12,

"ddos_cap": 150,
"ddos_grace_factor": 8,
"dtp": 0.99,

"ban_timeout": 300,

"Method_hash_check": true,
"Check_in": false,
"Check_out": true,

"js_challenge": false,
"challenge_url": "/js-challenge",

"dynamic": false,
"server_spinup_rt_gf": 2, 
"max_port": 6000,
"bin_path": "./intrasudo25",

"ipc": true,
"ipc_path": "/tmp/test/",

"max_concurrent_reqs_ps": 160,
"timeout_dur": 10,

"servers": [
    {
        "ip": "/tmp/intrasudo25.sock",
        "is_active": true,
        "strict_timeout": false
    } 
]
```

Don't get overwhelmed- once you know what each field does you'll realize that the loadbalaner takes care of all the nerdy stuff anyways 🤓

```json
"host": [[127, 0, 0, 1], 3000] #localhost
```
Pretty self explanatory.

```json
"redis_server": 3005,
```
The Load balancer required a redis to be running locally at all times for internal processes, including a cache; this field simply lets you specify a port for the same; to use the cache simply add the **cache-control** header to your responses with the value being the **TTL** in seconds.
```json
"compression": true,
"max_cache_mem": "100000000000mb",
"cache_eviction_policy": "allkeys-lru",
"redis_config_init": "/tmp/lb/redis_lb.conf",
```
These are your cache settings... Most of these are simple enough. For the cache_eviction_policy possible values refer to the **Redis CLI Docs** for a full explanation.  

*Note, the config_init path isn't your redis config or the one you use, instead, it should be a brand new file which the Loadbalancer can write to / mutate as it desires. It will be cleared at the start of each iteration.*

```json
"health_check": 5,
"health_check_path": "/",
```
Next we have the Health Check Config Settings; Once again pretty simple; The number is just the amount of time between each health check in seconds.

```json
"min_ua_len":0,
"blocked_uas": [],
```
The first field asks for a minimum user agent length... if the request UA is smaller than the same it will be marked as suspiscious and in most circumstanses be declined. The second one is pretty straightforward too. This helps reduce bot traffic if that's something you're willing to do. Ofcourse this check is fairly naive and that's precisely why we have the following ;)

```json
"dos_sus_threshhold": 12,
"ddos_cap": 150,
"ddos_grace_factor": 8,
"dtp": 0.99,
"ban_timeout": 300,
```
Now this is where things start getting epic. The first field asks for a threshold, an rps PER ip after which the loadbalancer blocks it for #ban_timeout seconds. However don't worry too much about it as this check isn't triggered every second, the loadbalncer only goes through each IP once things start getting suspiscious, that is, when there is a sudden spike in traffic. This is detected via the sliding quantile system in place. Feel free to google the terminology for its a fairly simple concept, or personally mail me your query if any as I'll be happy to explain it to you, but to operate this mechanism, you already know what [dos_sus_threshhold] does... Just read the following for the rest~

> **DDOS CAP**  

this is the maximum rps across *All Ips* after which the loadbalancer will start making checks per IP and blocking the same more frequent. Note that I've used **maximum** here, as this value is infact dynamic and keeps changing according to the current traffic state the loadbalancer is experiencing.
 > **GRACE FACTOR**  
   
The bigger the number, the more lenient the check becomes.

>**DTP**  
  
  Or DDOS Threshhold Percentile. **MUST** be ```[> 0] [< 1]```  
  The bigger this number is, the quicklier the LB will catch any anomolies. But make sure it isn't too high, infact even 0.99 is just for example purposes, or the LB may react to even the smallest and more temporary spikes, which might not even be intended to cause a DDOS.

```json
"Method_hash_check": true,
"Check_in": false,
"Check_out": true,
```
This is an optional setting; a simple check to verify the origin of requests for your loadbalancer or target servers. To use it change the first field to true; now check_in will make the loadbalancer expect a ```X-secret``` header on incoming requests which should be equal to the method of the request hashed with ```secret``` [from env] into base64.For Check_out the LB sends out the request to the target servers with the header and value. 

```json
"js_challenge": false,
"challenge_url": "/js-challenge"
```
Fairly Straightforward, just google the same if you're unaware of the terminology.

```json
"dynamic": false,
"server_spinup_rt_gf": 2, 
"max_port": 6000,
"bin_path": "./intrasudo25",
```
```dynamic``` turned on lets the LoadBalancer to start spinning up servers incase of high traffic itself.The ```server spinup response-time gracefector``` set to **X** tell the LB to spin up a new server if the response time of the target-servers shoot up to [Previous RT mean] * X; ```max_port``` is pretty straightforward, say the first server's port is 5000, the Loadbalancer with the current config will be able to make a maximum of 1000 additional servers; In case you're in IPC mode (more on that later), the server will be able to write 6000 more sockets (files) with the current config. And finally, the ```binary_path``` simply gives the LB the location of the binary which it can use to spin up new servers.

```json
"ipc": true,
"ipc_path": "/tmp/test/"
```
Turning on IPC tells the Loadbalancer that the target servers infact run over IPC protocols. This does NOT make the loadbalancer run on IPC itself. the IPC path is the location where if ```dynamic``` turned on, the LB will spawn new sockets. This is NOT the server socket location.

```json
"max_concurrent_reqs_ps": 160,
"timeout_dur": 10,
```
**ps: per_server**  
Incase this value is exceeded the LB does NOT panic, it instead looks for the next available server.  
**timeout_dur**  
Is the maximum time in seconds the LB will wait for a server to respond before giving up to avoid hangup.

```json
"servers": [
    {
        "ip": "/tmp/intrasudo25.sock",
        "is_active": true,
        "strict_timeout": false
    } 
]
```
This is your servers' list. Incase ```dynamic``` is turned ON, only the first server will be used for referance, the rest will be ignored. Most Settings are fairly clear... strict_timeout if turned on will mark a server unactive the second it exceeds the timeout-limit explained in the previous code block, given that the request was valid (The server after it was able to respond to it according to standards [FAILOVER] ). If turned off, the LB lets the server do this thrice before executing protocol. Moreover if you're not in IPC mode, make sure your IP is a proper http url. Feel free to add as many servers as you want in here.

## 🐼 Sneak Peak 
```Enter``` To switch screens.
```CTRL + p``` To execute Cleanup [Prepare for a Graceful Shutdown] .
```CTRL + q``` followed by ```CTRL + C``` To quit.  

<img src="/sneakpeaks/1.png" alt="Main" width="800"/>
<hr>
<img src="/sneakpeaks/2.png" alt="Second_Screen" width="800"/>
<hr>
<img src="/sneakpeaks/3.png" alt="Thrid_Screen" width="800"/>

