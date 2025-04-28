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

first_connection_callback = None  # For Step08 GUI

# ─── Helpers ───────────────────────────────────────────────────────
def simplify_domain(d: str) -> str:
    parts = d.strip('.').split('.')
    return ".".join(parts[-2:]) if len(parts) >= 2 else d

def load_seen_domains():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            return set(line.strip().split('] ')[-1].split(' - ')[0] for line in f.readlines())
    return set()

def save_seen_domain(domain, country):
    now = datetime.now().strftime("%d/%m/%Y %I:%M %p")
    with open(SEEN_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now}] {domain} - {country}\n")

def get_country_from_ip(ip):
    try:
        import ipinfo
        handler = ipinfo.getHandler(IPINFO_TOKEN)
        details = handler.getDetails(ip)
        country = details.country_name or details.country
        if country and country.lower() != "unknown":
            return country
    except:
        pass

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = res.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"

def announce_first_connection(domain, ip):
    global seen_domains
    country = get_country_from_ip(ip)
    now = datetime.now().strftime("%d/%m/%Y %I:%M %p")
    output = f"[{now}] {domain} - {country}"

    new_connection = domain not in seen_domains

    if new_connection:
        seen_domains.add(domain)
        save_seen_domain(domain, country)
        print(output)

        # Update GUI (First Connection Monitoring)
        if first_connection_callback:
            first_connection_callback(output)

    # Always analyze anomalies EVERY TIME
    analyze_connection(domain, ip, country, port=None)

# ─── Packet Monitors ───────────────────────────────────────────────
def dns_sniffer(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        try:
            dom = pkt[DNSQR].qname.decode().rstrip('.')
            base = simplify_domain(dom)
            if pkt.haslayer("IP"):
                dst_ip = pkt["IP"].dst
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
                dst_ip = pkt.ip.dst
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
                dst_ip = pkt.ip.dst
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
