#anomaly.py

import requests
import time

# Optional: store previously alerted IPs/domains to avoid repeating
_alerted = set()

# Add your keys here
ABUSEIPDB_API_KEY = "3856068116967885b54e954f68b6f52940f9efc2bab3b8f1e0a2463a4cb667a6712018d2406a166f" 
OTX_API_KEY = "ca3dccbe826f52b6a3664cc98167efd2be0c845a007fca34a80ee2e7155d8048"              # Optional for AlienVault

# Suspicious indicators
RARE_COUNTRIES = {"North Korea", "Russia", "Iran", "Belarus"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".zip", ".tk", ".ml"}
SUSPICIOUS_PORTS = {4444, 1337, 8081, 6969, 2222, 9001}

def is_ip_only(domain):
    return all(part.isdigit() or part == '.' for part in domain)

def print_alert(msg):
    print("\n🚨 " + msg + "\n")

def check_tld(domain):
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            print_alert(f"Suspicious Domain: {domain} — flagged due to TLD {tld}")

def check_country(domain, country):
    if country in RARE_COUNTRIES:
        print_alert(f"Rare Country Alert: {domain} connected to {country}")

def check_port(domain, port):
    if port in SUSPICIOUS_PORTS:
        print_alert(f"Suspicious Port: {domain} connected via unusual port {port}")

def check_ip_only(domain):
    if is_ip_only(domain):
        print_alert(f"Direct IP Contact: {domain} may be a backdoor/beacon")

def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 30}
        response = requests.get(url, headers=headers, params=params, timeout=3)
        data = response.json()
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        if score >= 60:
            print_alert(f"Malicious IP: {ip} has AbuseIPDB score {score}")
    except Exception as e:
        pass  # fail silently

def analyze_connection(domain, ip, country, port=None):
    key = f"{domain}:{ip}"
    if key in _alerted:
        return
    _alerted.add(key)

    check_tld(domain)
    check_country(domain, country)
    check_ip_only(domain)
    if port:
        check_port(domain, port)
    check_abuseipdb(ip)
