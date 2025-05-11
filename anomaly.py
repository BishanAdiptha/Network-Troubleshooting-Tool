import time
import statistics
from datetime import datetime
from collections import defaultdict
from queue import Queue
import requests
import math

anomaly_queue = Queue()

# === Config ===
ANOMALY_FILE = "anomaly_logs.txt"
ALL_DOMAINS_FILE = "all_domains.log"
ABUSEIPDB_API_KEY = "3856068116967885b54e954f68b6f52940f9efc2bab3b8f1e0a2463a4cb667a6712018d2406a166f"

RARE_COUNTRIES = {"North Korea", "Russia", "Iran", "Belarus"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".zip", ".rest"}
SUSPICIOUS_PORTS = {4444, 1337, 8081, 6969, 2222, 9001,}

# === Beaconing Detection ===
BEACON_THRESHOLD = 3
BEACON_VARIANCE_MS = 1500
BEACON_MIN_INTERVAL = 5
BEACON_MAX_INTERVAL = 10
BEACON_COOLDOWN = 60  # seconds

beaconing_history = defaultdict(list)
last_beacon_log_time = {}
already_logged = set()

# === Traffic Spike Detection ===
TRAFFIC_SPIKE_WINDOW = 10  # seconds
TRAFFIC_SPIKE_THRESHOLD = 50  # number of requests in window
traffic_history = defaultdict(list)
last_spike_log_time = {}

def is_ip_only(domain):
    return all(part.isdigit() or part == '.' for part in domain.split('.'))

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

def check_tld(domain):
    tld = "." + domain.split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        log_anomaly(f"Suspicious TLD detected: {domain}")

def check_country(domain, country):
    if country in RARE_COUNTRIES:
        log_anomaly(f"Domain {domain} resolves to rare country: {country}")

def check_port(domain, port):
    if port in SUSPICIOUS_PORTS:
        log_anomaly(f"Connection to {domain} uses suspicious port: {port}")

def check_abuseipdb(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers, timeout=5)
        data = response.json()
        if data.get("data", {}).get("abuseConfidenceScore", 0) >= 50:
            score = data["data"]["abuseConfidenceScore"]
            log_anomaly(f"⚠️ AbuseIPDB: Malicious IP Detected: {ip} (Score: {score}%)")
    except Exception as e:
        print(f"[ERROR] AbuseIPDB check failed: {e}")

def check_beaconing(domain):
    now = time.time()
    if domain in last_beacon_log_time:
        if now - last_beacon_log_time[domain] < BEACON_COOLDOWN:
            return

    timestamps = beaconing_history[domain]
    if len(timestamps) < BEACON_THRESHOLD:
        return

    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    interval_mean = statistics.mean(intervals)
    interval_stdev_ms = statistics.stdev(intervals) * 1000 if len(intervals) > 1 else 0

    if BEACON_MIN_INTERVAL <= interval_mean <= BEACON_MAX_INTERVAL and interval_stdev_ms < BEACON_VARIANCE_MS:
        log_anomaly(f"⚠️ Possible Beaconing Detected: {domain} (Interval ≈ {interval_mean:.1f}s, Stdev: {interval_stdev_ms:.0f}ms)")
        last_beacon_log_time[domain] = now

def shannon_entropy(data):
    if not data:
        return 0
    length = len(data)
    entropy = 0
    for x in set(data):
        p_x = data.count(x) / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def check_dns_tunneling(domain):
    if len(domain) <= 50:
        return
    entropy = shannon_entropy(domain)
    if entropy > 2.5:
        log_anomaly(f"⚠️ Possible DNS Tunneling Detected: {domain} (Length: {len(domain)}, Entropy: {entropy:.2f})")
    else:
        log_anomaly(f"⚠️ Suspiciously Long Subdomain Detected: {domain} (Length: {len(domain)}, Entropy: {entropy:.2f})")

def check_traffic_spike(domain):
    now = time.time()
    traffic_history[domain].append(now)
    traffic_history[domain] = [t for t in traffic_history[domain] if now - t <= TRAFFIC_SPIKE_WINDOW]

    print(f"[DEBUG] Spike check: {domain} has {len(traffic_history[domain])} hits")

    if len(traffic_history[domain]) >= TRAFFIC_SPIKE_THRESHOLD:
        if domain in last_spike_log_time and (now - last_spike_log_time[domain] < 60):
            return
        log_anomaly(f"⚠️ Traffic Spike Detected: {domain} had {len(traffic_history[domain])} requests in {TRAFFIC_SPIKE_WINDOW}s")
        last_spike_log_time[domain] = now

def check_http_usage(domain, port=None, protocol=None):
    if protocol == "http":
        log_anomaly(f"⚠️ Unencrypted HTTP detected to {domain}")

        # TLDs with HTTP
        tld = "." + domain.split(".")[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            log_anomaly(f"⚠️ HTTP used with suspicious TLD: {domain}")

    if protocol == "https" and port in {8080, 8443, 4443}:
        log_anomaly(f"⚠️ Suspicious HTTPS port used for {domain}: port {port}")

def parse_log_line(line):
    try:
        right = line.strip().split("] ")[-1]
        domain, ip = right.rsplit(" ", 1)
        return domain.strip(), ip.strip()
    except:
        return None, None

def analyze_connection(domain, ip, country=None, port=None, protocol=None):
    if is_ip_only(domain):
        return
    check_tld(domain)
    if country:
        check_country(domain, country)
    if port:
        check_port(domain, port)
    check_abuseipdb(ip)
    check_dns_tunneling(domain)
    beaconing_history[domain].append(time.time())
    check_beaconing(domain)
    check_traffic_spike(domain)
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
                domain, ip = parse_log_line(line)
                if not domain or not ip:
                    continue
                # For now, protocol and port are unknown unless passed from monitor.py
                analyze_connection(domain, ip)
    except KeyboardInterrupt:
        print("🛑 Anomaly monitoring stopped by user.")
