import pyshark
from scapy.all import sniff, DNS, DNSQR
import threading
import time
from datetime import datetime
from collections import defaultdict
import socket
import os
import psutil
import asyncio

ALL_DOMAINS_FILE = "all_domains.log"
SEEN_FILE = "first_network_connections.txt"
ip_country_cache = {}
domain_stats = defaultdict(lambda: {"bytes": 0})
seen_domains = set()
lock = threading.Lock()

first_connection_callback = None  # GUI callback

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

def append_to_all_domains(domain, ip):
    now = datetime.now().strftime("%d/%m/%Y %I:%M %p")
    with open(ALL_DOMAINS_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now}] {domain} {ip}\n")

def get_country_from_ip(ip):
    if ip in ip_country_cache:
        return ip_country_cache[ip]
    try:
        import ipinfo
        handler = ipinfo.getHandler("d075f74a07df28")
        details = handler.getDetails(ip)
        country = details.country_name or details.country
        if country and country.lower() != "unknown":
            ip_country_cache[ip] = country
            return country
    except:
        pass
    try:
        import requests
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = res.json()
        country = data.get("country", "Unknown")
        ip_country_cache[ip] = country
        return country
    except:
        ip_country_cache[ip] = "Unknown"
        return "Unknown"

def is_ip_address(text):
    try:
        socket.inet_aton(text)
        return True
    except:
        return False

def announce_first_connection(domain, ip):
    if is_ip_address(domain) or domain == ip:
        return

    domain_lower = domain.lower()

    # ✅ Filter out specific internal/log-cluttering domains
    excluded_domains = [
        "in-addr.arpa",
        "api.abuseipdb.com",
        "ipinfo.io",
        "mobile.events.data.microsoft.com"
    ]
    if any(domain_lower.endswith(excl) or domain_lower == excl for excl in excluded_domains):
        return

    now = datetime.now().strftime("%d/%m/%Y %I:%M %p")
    country = get_country_from_ip(ip)
    output = f"[{now}] {domain} - {country}"

    append_to_all_domains(domain, ip)

    with lock:
        if domain in seen_domains:
            return
        seen_domains.add(domain)

    print(output)
    save_seen_domain(domain, country)
    if first_connection_callback:
        first_connection_callback(output)

def dns_sniffer(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        try:
            dom = pkt[DNSQR].qname.decode().rstrip('.')
            dst_ip = pkt["IP"].dst if pkt.haslayer("IP") else "0.0.0.0"  # Fallback for unknown
            announce_first_connection(dom, dst_ip)
        except Exception as e:
            print("[DNS SNIF ERROR]", e)


def start_dns_sniff():
    while True:
        try:
            sniff(filter="udp port 53", prn=dns_sniffer, store=0, timeout=0.5)
        except Exception as e:
            print(f"[DNS Sniff Error] {e}")
            time.sleep(0.1)

def run_tls_sni_monitor(interface):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        try:
            cap = pyshark.LiveCapture(interface=interface, display_filter='tls.handshake.extensions_server_name')
            for pkt in cap.sniff_continuously():
                try:
                    sni = pkt.tls.handshake_extensions_server_name
                    dst_ip = pkt.ip.dst
                    announce_first_connection(sni, dst_ip)
                except Exception:
                    continue
        except Exception as e:
            print(f"[TLS SNI Error] {e}")
            time.sleep(1)

def run_http_host_monitor(interface):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        try:
            cap = pyshark.LiveCapture(interface=interface, display_filter='http.request')
            for pkt in cap.sniff_continuously():
                try:
                    host = pkt.http.host
                    dst_ip = pkt.ip.dst
                    announce_first_connection(host, dst_ip)
                except Exception:
                    continue
        except Exception as e:
            print(f"[HTTP Host Error] {e}")
            time.sleep(1)

def get_windows_interfaces():
    interfaces = []
    stats = psutil.net_if_stats()
    for iface in stats:
        if stats[iface].isup:
            interfaces.append((iface, iface))
    interfaces += [
        ("\\Device\\NPF_{9B7022FB-816F-4531-9F36-50BAC4D71CBB}", "OpenVPN TAP-Windows6"),
        ("\\Device\\NPF_{35BCF50A-157E-4A7D-B37E-A7623C7B2825}", "OpenVPN Wintun")
    ]
    return interfaces

monitored_ifaces = set()

def monitor_new_interfaces():
    global monitored_ifaces
    while True:
        try:
            interfaces = get_windows_interfaces()
            for iface_tuple in interfaces:
                iface, friendly_name = iface_tuple
                if iface not in monitored_ifaces:
                    monitored_ifaces.add(iface)
                    print(f"🟢 New interface detected: {friendly_name}, starting monitors...")
                    threading.Thread(target=run_tls_sni_monitor, args=(iface,), daemon=True).start()
                    threading.Thread(target=run_http_host_monitor, args=(iface,), daemon=True).start()
        except Exception as e:
            print(f"[Monitor Interface Error] {e}")
        time.sleep(5)

def start_monitoring(selected_interface=None):
    global seen_domains
    seen_domains = load_seen_domains()
    print("Starting real-time network monitoring...")

    threading.Thread(target=start_dns_sniff, daemon=True).start()
    threading.Thread(target=monitor_new_interfaces, daemon=True).start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user.")
