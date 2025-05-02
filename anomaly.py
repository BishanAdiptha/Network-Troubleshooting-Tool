#anomaly.py

import time
import statistics
from datetime import datetime
from collections import defaultdict
from queue import Queue
import requests

# === Public interfaces ===
anomaly_queue = Queue()

# === Config ===
ANOMALY_FILE = "anomaly_logs.txt"
ALL_DOMAINS_FILE = "all_domains.log"
ABUSEIPDB_API_KEY = "3856068116967885b54e954f68b6f52940f9efc2bab3b8f1e0a2463a4cb667a6712018d2406a166f"

RARE_COUNTRIES = {"North Korea", "Russia", "Iran", "Belarus"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".zip", ".rest"}
SUSPICIOUS_PORTS = {4444, 1337, 8081, 6969, 2222, 9001}

BEACON_THRESHOLD = 3
BEACON_VARIANCE_MS = 1500
BEACON_MIN_INTERVAL = 5
BEACON_MAX_INTERVAL = 10

beaconing_history = defaultdict(list)
already_logged = set()  # Avoid duplicate logs in file, but still show in UI

def is_ip_only(domain):
    return all(part.isdigit() or part == '.' for part in domain.split('.'))

def log_anomaly(message):
    now = datetime.now().strftime("[%d/%m/%Y %I:%M %p]")
    final_message = f"{now} {message}"

    if final_message not in already_logged:
        try:
            with open(ANOMALY_FILE, "a", encoding="utf-8") as f:
                f.write(final_message + "\n")
        except Exception as e:
            print("[ERROR] Writing to log failed:", e)
        already_logged.add(final_message)

    anomaly_queue.put(final_message)

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
    timestamps = beaconing_history[domain]
    if len(timestamps) < BEACON_THRESHOLD:
        return

    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    interval_mean = statistics.mean(intervals)
    interval_stdev_ms = statistics.stdev(intervals) * 1000 if len(intervals) > 1 else 0

    if BEACON_MIN_INTERVAL <= interval_mean <= BEACON_MAX_INTERVAL:
        if interval_stdev_ms < BEACON_VARIANCE_MS:
            log_anomaly(f"⚠️ Possible Beaconing Detected: {domain} (Interval ≈ {interval_mean:.1f}s, Stdev: {interval_stdev_ms:.0f}ms)")

def parse_log_line(line):
    try:
        right = line.strip().split("] ")[-1]
        domain, ip = right.rsplit(" ", 1)
        return domain.strip(), ip.strip()
    except:
        return None, None

def analyze_connection(domain, ip, country=None, port=None):
    if is_ip_only(domain):
        return
    check_tld(domain)
    if country:
        check_country(domain, country)
    if port:
        check_port(domain, port)
    check_abuseipdb(ip)
    check_beaconing(domain)

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

                beaconing_history[domain].append(time.time())
                analyze_connection(domain, ip)
    except KeyboardInterrupt:
        print("🛑 Anomaly monitoring stopped by user.")
