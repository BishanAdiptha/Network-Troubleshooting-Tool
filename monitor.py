from scapy.all import sniff, IP, TCP, UDP
import ipinfo
import psutil
import threading
import time
import os
from collections import defaultdict
from socket import getfqdn

# IPInfo Access Token
access_token = 'd075f74a07df28'
ipinfo_handler = ipinfo.getHandler(access_token)

# Cache for process names by port
def get_local_port_process_map():
    port_map = {}
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr and conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
                port_map[conn.laddr.port] = proc_name
            except Exception:
                continue
    return port_map

# Cache organization info
ip_cache = {}

def get_org_and_country(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        details = ipinfo_handler.getDetails(ip)
        org = details.org or "Unknown"
        country = details.country_name or "Unknown"
        ip_cache[ip] = (org, country)
        return org, country
    except Exception:
        ip_cache[ip] = ("Unknown", "Unknown")
        return "Unknown", "Unknown"

# Traffic Tracker
traffic_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "org": "", "country": "", "app": "Unknown"})

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        dst = ip_layer.dst
        pkt_len = len(packet)

        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport
        else:
            dport = None

        # Get org and country
        org, country = get_org_and_country(dst)

        # Get app name from port (local apps)
        process_map = get_local_port_process_map()
        app = process_map.get(dport, "Unknown")

        key = (proto, dst, org, country, app)
        traffic_stats[key]["packets"] += 1
        traffic_stats[key]["bytes"] += pkt_len
        traffic_stats[key]["org"] = org
        traffic_stats[key]["country"] = country
        traffic_stats[key]["app"] = app

def display_stats():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("📊 Live Network Traffic Monitoring (GlassWire-style)\n")
        print(f"{'Proto':<6} {'IP Address':<40} {'Packets':>8} {'Data':>10} {'Organization':<30} {'Country':<15} {'App'}")
        print("=" * 120)
        for (proto, dst, org, country, app), stats in sorted(traffic_stats.items(), key=lambda x: -x[1]['bytes']):
            print(f"[{proto}] {dst:<40} {stats['packets']:>8} {stats['bytes']/1024:9.1f} KB  "
                  f"{org[:30]:<30} {country:<15} {app}")
        time.sleep(2)

print("🔍 Monitoring started with live GlassWire-style stats (Press Ctrl+C to stop)...")

# Start display in a separate thread
display_thread = threading.Thread(target=display_stats, daemon=True)
display_thread.start()

# Start sniffing packets
sniff(prn=process_packet, store=0)
