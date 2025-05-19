import time
import statistics
from datetime import datetime
from collections import defaultdict
from queue import Queue
import requests
import math

anomaly_queue = Queue()

ANOMALY_FILE = "anomaly_logs.txt"
ALL_DOMAINS_FILE = "all_domains.log"
ABUSEIPDB_API_KEY = "3856068116967885b54e954f68b6f52940f9efc2bab3b8f1e0a2463a4cb667a6712018d2406a166f"

RARE_COUNTRIES = {"North Korea", "Russia", "Iran", "Belarus"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".zip", ".rest"}
SUSPICIOUS_PORTS = {4444, 1337, 8081, 6969, 2222, 9001, 8443, 4443, 8888, 8080, 82, 23, 2323, 52869, 49152, 0}

SAFE_KEYWORDS = [
    "ip-api.com", "ipinfo.io", "abuseipdb.com", "1.1.1.1", "localhost", "127.0.0.1",
    "clients4.google.com", "clients2.google.com", "googleapis.com", "dns.google",
    "microsoft.com", "dl.delivery.mp.microsoft.com", "cloudflare-dns.com",
    "doubleclick.net", "akamai", "ocsp.digicert.com", ".whatsapp.net" , "www.speedtest.net", "ookla.mobitel.lk",
    "192.168.8.1", "sp1.hutch.lk" ,"192.168.8.1"
]

beaconing_history = defaultdict(list)
last_beacon_log_time = {}
already_logged = set()
logged_flags = defaultdict(set)
logged_flags_ip = defaultdict(set)
checked_abuseip_ips = set()
abuseipdb_quota_exceeded = False

TRAFFIC_SPIKE_WINDOW = 10
TRAFFIC_SPIKE_THRESHOLD = 50
traffic_history = defaultdict(list)
last_spike_log_time = {}

def is_ip_only(domain):
    return all(part.isdigit() or part == '.' for part in domain.split('.'))

def should_ignore_domain(domain):
    domain = domain.lower()
    return any(bad in domain for bad in SAFE_KEYWORDS)

def log_anomaly(message):
    now = datetime.now().strftime("[%d/%m/%Y %I:%M %p]")
    final_message = f"{now} {message}"
    anomaly_queue.put(final_message)
    if final_message not in already_logged:
        try:
            with open(ANOMALY_FILE, "a", encoding="utf-8") as f:
                f.write(final_message + "\n")
        except Exception as e:
            print("[ERROR] Writing to log failed:", e)
        already_logged.add(final_message)

def check_abuseipdb(ip):
    global abuseipdb_quota_exceeded
    if ip in checked_abuseip_ips or abuseipdb_quota_exceeded:
        return
    checked_abuseip_ips.add(ip)
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 429:
            abuseipdb_quota_exceeded = True
            log_anomaly("⚠️ AbuseIPDB quota exceeded – further lookups skipped for today.")
            return
        data = response.json()
        if data.get("data", {}).get("abuseConfidenceScore", 0) >= 50:
            score = data["data"]["abuseConfidenceScore"]
            log_anomaly(f"⚠️ AbuseIPDB: Malicious IP Detected: {ip} (Score: {score}%)")
            logged_flags_ip[ip].add("abuseipdb")
    except Exception as e:
        print(f"[ERROR] AbuseIPDB check failed: {e}")

def check_tld(domain):
    if "tld" in logged_flags[domain]:
        return
    tld = "." + domain.split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        log_anomaly(f"Suspicious TLD detected: {domain}")
        logged_flags[domain].add("tld")

def check_country(domain, country):
    if "rare_country" in logged_flags[domain]:
        return
    if country in RARE_COUNTRIES:
        log_anomaly(f"Domain {domain} resolves to rare country: {country}")
        logged_flags[domain].add("rare_country")

def check_port(domain, port):
    if "port" in logged_flags[domain]:
        return
    if port in SUSPICIOUS_PORTS:
        log_anomaly(f"Connection to {domain} uses suspicious port: {port}")
        logged_flags[domain].add("port")

def check_beaconing(domain):
    now = time.time()
    if domain in last_beacon_log_time and now - last_beacon_log_time[domain] < 60:
        return
    timestamps = beaconing_history[domain]
    if len(timestamps) < 3:
        return
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    interval_mean = statistics.mean(intervals)
    interval_stdev_ms = statistics.stdev(intervals) * 1000 if len(intervals) > 1 else 0
    print(f"[DEBUG] Beaconing check: {domain} → {len(timestamps)} hits, mean={interval_mean:.1f}s, stdev={interval_stdev_ms:.0f}ms")
    if 4 <= interval_mean <= 10 and interval_stdev_ms < 4000:
        message = f"⚠️ Possible Beaconing Detected: {domain} (Interval ≈ {interval_mean:.1f}s, Stdev: {interval_stdev_ms:.0f}ms)"
        log_anomaly(message)  # ✅ Logs to file + queue for GUI
        last_beacon_log_time[domain] = now


def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def check_dns_tunneling(domain):
    if "dns_tunnel" in logged_flags[domain]:
        return
    if len(domain) <= 50:
        return
    entropy = shannon_entropy(domain)
    if entropy > 2.5:
        log_anomaly(f"⚠️ Possible DNS Tunneling Detected: {domain} (Length: {len(domain)}, Entropy: {entropy:.2f})")
    else:
        log_anomaly(f"⚠️ Suspiciously Long Subdomain Detected: {domain} (Length: {len(domain)}, Entropy: {entropy:.2f})")
    logged_flags[domain].add("dns_tunnel")

def check_traffic_spike(domain):
    now = time.time()
    traffic_history[domain].append(now)
    traffic_history[domain] = [t for t in traffic_history[domain] if now - t <= TRAFFIC_SPIKE_WINDOW]
    if len(traffic_history[domain]) >= TRAFFIC_SPIKE_THRESHOLD:
        if domain in last_spike_log_time and (now - last_spike_log_time[domain] < 60):
            return
        log_anomaly(f"⚠️ Traffic Spike Detected: {domain} had {len(traffic_history[domain])} requests in {TRAFFIC_SPIKE_WINDOW}s")
        last_spike_log_time[domain] = now

def check_http_usage(domain, port=None, protocol=None):
    if protocol == "http" and "http" not in logged_flags[domain]:
        log_anomaly(f"⚠️ Unencrypted HTTP detected to {domain}")
        logged_flags[domain].add("http")
        tld = "." + domain.split(".")[-1].lower()
        if tld in SUSPICIOUS_TLDS and "http_tld" not in logged_flags[domain]:
            log_anomaly(f"⚠️ HTTP used with suspicious TLD: {domain}")
            logged_flags[domain].add("http_tld")
    if protocol == "https" and port in {8080, 8443, 4443} and "https_port" not in logged_flags[domain]:
        log_anomaly(f"⚠️ Suspicious HTTPS port used for {domain}: port {port}")
        logged_flags[domain].add("https_port")

def parse_log_line(line):
    try:
        right = line.strip().split("] ")[-1]
        parts = right.split()
        if len(parts) == 3:
            domain, ip, country = parts
        else:
            domain, ip = parts
            country = None
        return domain.strip(), ip.strip(), country
    except:
        return None, None, None

def analyze_connection(domain, ip, country=None, port=None, protocol=None):
    # ✅ Always run beaconing/spike before skipping
    beaconing_history[domain].append(time.time())
    check_beaconing(domain)
    check_traffic_spike(domain)

    if should_ignore_domain(domain):
        return

    if is_ip_only(domain):
        check_abuseipdb(ip)
        return
    check_tld(domain)
    if country:
        check_country(domain, country)
    if port:
        check_port(domain, port)
    check_abuseipdb(ip)
    check_dns_tunneling(domain)
    check_http_usage(domain, port, protocol)

def start_anomaly_monitoring():
    print("🔍 Anomaly monitor started...")
    try:
        with open(ALL_DOMAINS_FILE, "r", encoding="utf-8") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                domain, ip, country = parse_log_line(line)
                if not domain or not ip:
                    continue
                analyze_connection(domain, ip, country)
    except KeyboardInterrupt:
        print("🛑 Anomaly monitoring stopped by user.")
