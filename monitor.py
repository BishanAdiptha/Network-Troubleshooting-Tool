#monitor.py

import pyshark
from scapy.all import sniff, DNS, DNSQR
import threading
import time
from datetime import datetime
from collections import defaultdict
import socket
import os
import asyncio
import requests
from anomaly import analyze_connection




# ─── Initialization ───────────────────────────────────────────────
asyncio.set_event_loop(asyncio.new_event_loop())
domain_stats = defaultdict(lambda: {"bytes": 0})
seen_domains = set()
lock = threading.Lock()
SEEN_FILE = "first_network_connections.txt"
IPINFO_TOKEN = "d075f74a07df28"

# ─── Helpers ───────────────────────────────────────────────────────
def simplify_domain(d: str) -> str:
    parts = d.strip('.').split('.')
    return ".".join(parts[-2:]) if len(parts) >= 2 else d

def load_seen_domains():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            return set(line.strip() for line in f.readlines())
    return set()

def save_seen_domain(domain):
    with open(SEEN_FILE, "a") as f:
        f.write(domain + "\n")

def get_country_from_ip(ip):
    # 1. Try IPInfo
    try:
        import ipinfo
        handler = ipinfo.getHandler(IPINFO_TOKEN)
        details = handler.getDetails(ip)
        country = details.country_name or details.country
        if country and country.lower() != "unknown":
            return country
    except:
        pass

    # 2. Fallback to ip-api
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = res.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"

def announce_first_connection(domain, ip):
    if domain in seen_domains:
        return
    seen_domains.add(domain)
    save_seen_domain(domain)

    country = get_country_from_ip(ip)
    now = datetime.now().strftime("%I:%M %p")
    print(f"{domain} initiated the first network connection with {country} at {now}")

     # 🚨 Call anomaly check here
    analyze_connection(domain, ip, country, port=None)  # we'll handle port as optional

# ─── Packet Monitors ───────────────────────────────────────────────
def dns_sniffer(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        try:
            dom = pkt[DNSQR].qname.decode().rstrip('.')
            base = simplify_domain(dom)
            if pkt.haslayer("IP"):
                dst_ip = pkt["IP"].dst  # ✅ use destination IP
            else:
                return
        except:
            return
        with lock:
            announce_first_connection(base, dst_ip)

def start_dns_sniff():
    sniff(filter="udp port 53", prn=dns_sniffer, store=0)

def tls_sni_monitor(interface):
    asyncio.set_event_loop(asyncio.new_event_loop())
    try:
        cap = pyshark.LiveCapture(interface=interface, display_filter='tls.handshake.extensions_server_name')
        for pkt in cap.sniff_continuously():
            try:
                sni = pkt.tls.handshake_extensions_server_name
                base = simplify_domain(sni)
                dst_ip = pkt.ip.dst  # ✅ use destination IP
            except:
                continue
            with lock:
                announce_first_connection(base, dst_ip)
    except Exception as e:
        print(f"[TLS SNI Error] {e}")

def http_host_monitor(interface):
    asyncio.set_event_loop(asyncio.new_event_loop())
    try:
        cap = pyshark.LiveCapture(interface=interface, display_filter='http.request')
        for pkt in cap.sniff_continuously():
            try:
                host = pkt.http.host
                base = simplify_domain(host)
                dst_ip = pkt.ip.dst  # ✅ use destination IP
            except:
                continue
            with lock:
                announce_first_connection(base, dst_ip)
    except Exception as e:
        print(f"[HTTP Host Error] {e}")

# ─── Main Monitor Launcher ─────────────────────────────────────────
def start_monitoring(interface):
    global seen_domains
    seen_domains = load_seen_domains()



    threading.Thread(target=start_dns_sniff, daemon=True).start()
    threading.Thread(target=tls_sni_monitor, args=(interface,), daemon=True).start()
    threading.Thread(target=http_host_monitor, args=(interface,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user.")
