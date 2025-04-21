# monitor.py

import pyshark
from scapy.all import sniff, DNS, DNSQR
import threading
import time
from collections import defaultdict
from network_activity import start_network_activity_monitor
from network_activity import get_recent_connections

domain_stats   = defaultdict(lambda: {"bytes": 0})
lock           = threading.Lock()
header_printed = False

def simplify_domain(d: str) -> str:
    parts = d.strip('.').split('.')
    return ".".join(parts[-2:]) if len(parts) >= 2 else d

def print_stats():
    """Print header once, then update only the domain rows every 2 seconds."""
    global header_printed
    while True:
        time.sleep(2)
        with lock:
            items = sorted(domain_stats.items(), key=lambda x: -x[1]["bytes"])
            if not header_printed:
              print("\n📊 Passive App & Domain Monitoring (Live View)\n")
              print(f"{'Host':<40} {'Data':>8}   |  First-time Connections")
              print("=" * 95)
              print("\n" * 5)  # Add enough spacing (5–8 lines is usually enough)
              header_printed = True



            prev = getattr(print_stats, "prev_count", 0)
            if prev:
                # Move cursor up to overwrite previous rows
                print(f"\033[{prev}A", end="")

            count = 0
            conns = get_recent_connections()
            for i, (host, stat) in enumerate(items):
                kb = stat["bytes"] / 1024
                conn = conns[i] if i < len(conns) else ""
                print(f"{host:<40} {kb:>6.1f} KB  |  {conn}")
                count += 1


            print_stats.prev_count = count

def dns_sniffer(pkt):
    """Accumulate bytes per simplified domain from DNS queries."""
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        try:
            dom  = pkt[DNSQR].qname.decode().rstrip('.')
            base = simplify_domain(dom)
            size = len(pkt)
        except:
            return
        with lock:
            domain_stats[base]["bytes"] += size

def start_dns_sniff():
    sniff(filter="udp port 53", prn=dns_sniffer, store=0)

def tls_sni_monitor(interface):
    """Accumulate bytes per domain from TLS SNI (handshake)."""
    try:
        cap = pyshark.LiveCapture(
            interface=interface,
            display_filter='tls.handshake.extensions_server_name'
        )
        for pkt in cap.sniff_continuously():
            try:
                sni  = pkt.tls.handshake_extensions_server_name
                base = simplify_domain(sni)
                size = int(pkt.length)
            except:
                continue
            with lock:
                domain_stats[base]["bytes"] += size

    except Exception as e:
        print(f"[TLS SNI Error] {e}")

def http_host_monitor(interface):
    """Accumulate bytes per domain from HTTP Host header."""
    try:
        cap = pyshark.LiveCapture(
            interface=interface,
            display_filter='http.request'
        )
        for pkt in cap.sniff_continuously():
            try:
                host = pkt.http.host
                base = simplify_domain(host)
                size = int(pkt.length)
            except:
                continue
            with lock:
                domain_stats[base]["bytes"] += size

    except Exception as e:
        print(f"[HTTP Host Error] {e}")




def start_monitoring(interface):
    """Launch live stats printer plus DNS, TLS SNI, HTTP monitors and also new connection log."""
    print("\n📊 Loading the Live Monitoring\n")
    threading.Thread(target=start_network_activity_monitor, daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()
    threading.Thread(target=start_dns_sniff, daemon=True).start()
    threading.Thread(target=tls_sni_monitor, args=(interface,), daemon=True).start()
    threading.Thread(target=http_host_monitor, args=(interface,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user.")

