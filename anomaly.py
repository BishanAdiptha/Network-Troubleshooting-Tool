# ============================== anomaly.py ==============================

import requests
from datetime import datetime

anomaly_callback = None

ANOMALY_FILE = "anomaly_logs.txt"
ABUSEIPDB_API_KEY = "3856068116967885b54e954f68b6f52940f9efc2bab3b8f1e0a2463a4cb667a6712018d2406a166f"

RARE_COUNTRIES = {"North Korea", "Russia", "Iran", "Belarus"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".zip", ".tk", ".ml"}
SUSPICIOUS_PORTS = {4444, 1337, 8081, 6969, 2222, 9001}

def is_ip_only(domain):
    return all(part.isdigit() or part == '.' for part in domain)

def log_anomaly(message):
    now = datetime.now().strftime("[%d/%m/%Y %I:%M %p]")
    final_message = f"{now} {message}"
    print("[DEBUG] Anomaly Logged:", final_message)

    try:
        with open(ANOMALY_FILE, "a", encoding="utf-8") as f:
            f.write(final_message + "\n")
    except Exception as e:
        print(f"Error writing anomaly log: {e}")

    if anomaly_callback:
        anomaly_callback(final_message)

def check_tld(domain):
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            log_anomaly(f"Suspicious Domain Detected: {domain} (TLD {tld})")

def check_country(domain, country):
    if country in RARE_COUNTRIES:
        log_anomaly(f"Rare Country Connection: {domain} ({country})")

def check_port(domain, port):
    if port in SUSPICIOUS_PORTS:
        log_anomaly(f"Suspicious Port Usage: {domain} (Port {port})")

def check_ip_only(domain):
    if is_ip_only(domain):
        log_anomaly(f"Direct IP Contact Detected: {domain}")

def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 30}
        response = requests.get(url, headers=headers, params=params, timeout=3)
        data = response.json()
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        if score >= 60:
            log_anomaly(f"Malicious IP Found: {ip} (Abuse Score {score})")
    except Exception:
        pass

def analyze_connection(domain, ip, country, port=None):
    check_ip_only(domain)
    check_tld(domain)
    check_country(domain, country)
    if port:
        check_port(domain, port)
    check_abuseipdb(ip)