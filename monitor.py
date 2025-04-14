from scapy.all import sniff, IP, TCP, UDP, Raw
from socket import getservbyport
from urllib.parse import urlparse
import re
import time
from datetime import datetime

log_entries = []

def extract_hostname_from_tls(packet):
    try:
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if raw_data[0] == 0x16 and raw_data[5] == 0x01:
                sni_match = re.search(
                    b'\x00\x00[\x00-\xff]{1,2}[\x00-\xff]{1,2}\x00\x00[\x00-\xff]{1,2}([\x00-\xff]{1,2})([\x00-\xff]+)',
                    raw_data
                )
                if sni_match:
                    potential = sni_match.group(2)
                    hostname = re.findall(b'([\w.-]+\.[a-zA-Z]{2,})', potential)
                    if hostname:
                        return hostname[0].decode(errors='ignore')
    except:
        pass
    return None

def get_protocol(port):
    try:
        return getservbyport(port)
    except:
        return f"Port:{port}"

def simplify_app_name(hostname):
    if not hostname or hostname == "N/A":
        return "Unknown"
    root = ".".join(hostname.split(".")[-2:])
    return root.split('.')[0].capitalize()

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
    sport = pkt.sport
    dport = pkt.dport
    src = ip_layer.src
    dst = ip_layer.dst
    size = len(pkt)

    hostname = extract_hostname_from_tls(pkt) or "N/A"
    proto_name = get_protocol(dport)
    app_name = simplify_app_name(hostname)

    line = f"[{proto:<4}] {proto_name:<8} | {app_name:<12} | {src}:{sport} → {dst}:{dport} | Host: {hostname:<30} | Size: {size} B"
    print(line)
    log_entries.append(line)

def write_log_to_file():
    filename = "traffic_log.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"📄 Traffic Summary Log\n")
            f.write(f"🕒 Captured on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for entry in log_entries:
                f.write(entry + "\n")
        print(f"\n✅ Log saved to: {filename}")
    except Exception as e:
        print(f"\n❌ Failed to write log file: {e}")

def monitor():
    print("\n🌐 Real-Time Traffic Monitor ▶ Press Ctrl+C to stop\n")
    try:
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped.")
        write_log_to_file()

if __name__ == "__main__":
    monitor()
