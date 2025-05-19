import os
import socket
import platform
import subprocess
from scapy.all import sniff, IP, ARP, Ether, srp
import dns.resolver
from monitor import start_monitoring

# ========== STEP 1: Physical Connectivity ==========

def list_interfaces():
    if platform.system() == "Windows":
        result = subprocess.getoutput("netsh interface show interface")
        print(result)

def follow_up_questions(interface):
    interface_lower = interface.lower()
    if "ethernet" in interface_lower:
        input("🧩 Ethernet cable plugged in? ")
        input("💡 Are the port LEDs blinking? ")
    if "wi-fi" in interface_lower or "wifi" in interface_lower:
        input("📶 Is Wi-Fi connected to correct network? ")
    input("✈️ Is Airplane mode OFF? ")

def check_cable_or_wifi_gui(target_interface):
    result_text = ""
    guidance = []
    if platform.system() == "Windows":
        result = subprocess.getoutput("netsh interface show interface")
        for line in result.splitlines():
            if target_interface.lower() in line.lower():
                if "Connected" in line:
                    result_text = f"✅ {target_interface} is connected."
                else:
                    result_text = f"⚠️ {target_interface} is not connected."
                    if "ethernet" in target_interface.lower():
                        guidance = ["🧩 Check cable", "💡 Check port LEDs"]
                    elif "wi-fi" in target_interface.lower():
                        guidance = ["📶 Check Wi-Fi connection", "✈️ Check Airplane mode"]
                break
    return result_text, guidance

# ========== STEP 2: IP & DHCP Diagnostics ==========

def check_ip_and_dhcp_info(selected_interface):
    if platform.system() != "Windows":
        return "⚠️ IP/DHCP checks are Windows-only."

    output = subprocess.getoutput("ipconfig /all")
    lines = output.splitlines()
    adapter_section = False
    ip_valid = False
    dhcp_enabled = None
    ip_address = ""
    gateway = ""
    dns_servers = []
    messages = []

    for i, line in enumerate(lines):
        line = line.strip()
        if "adapter" in line.lower():
            adapter_name = line.split("adapter")[-1].strip(": ").strip()
            adapter_section = selected_interface.lower() in adapter_name.lower()
            continue
        if not adapter_section:
            continue
        if "DHCP Enabled" in line:
            dhcp_enabled = "Yes" in line
        if "IPv4 Address" in line:
            ip_address = line.split(":")[-1].split("(")[0].strip()
            ip_valid = not ip_address.startswith("169.254")
        if "Default Gateway" in line and ":" in line:
            gateway = line.split(":")[-1].strip()
        if "DNS Servers" in line:
            dns_servers.append(line.split(":")[-1].strip())
            j = i + 1
            while j < len(lines) and lines[j].startswith(" "):
                dns_servers.append(lines[j].strip())
                j += 1
        if dhcp_enabled is not None and ip_address and gateway:
            break

    if not ip_address:
        return f"⚠️ Could not determine IP for {selected_interface}"

    if dhcp_enabled:
        messages.append(f"✅ Valid DHCP IP: {ip_address}" if ip_valid else f"⚠️ Invalid DHCP IP: {ip_address}")
    else:
        messages.append(f"⚠️ DHCP disabled. Static IP: {ip_address}")
        if not gateway:
            messages.append("❌ No default gateway.")
        if not dns_servers:
            messages.append("❌ No DNS servers.")

    return "\n".join(messages)

# ========== STEP 3: Router Ping ==========

def ping_router(gateway="192.168.1.1"):
    output = os.popen(f"ping -n 4 {gateway}" if os.name == "nt" else f"ping -c 4 {gateway}").read()
    success = "TTL=" in output or "bytes from" in output
    return output.strip(), success

# ========== STEP 4/5: DNS and Internet ==========

def check_dns_resolution():
    try:
        dns.resolver.resolve("google.com")
        return True, None
    except dns.resolver.NoNameservers:
        return False, "No DNS servers."
    except dns.resolver.NXDOMAIN:
        return False, "Domain not found."
    except dns.resolver.Timeout:
        return False, "DNS timeout."
    except Exception:
        return False, "Unknown DNS error."

def ping_external():
    output = os.popen(f"ping -n 2 8.8.8.8" if os.name == "nt" else f"ping -c 2 8.8.8.8").read()
    return "TTL=" in output or "bytes from" in output

# ========== STEP 6: Speed Test ==========

def speed_test():
    try:
        import speedtest
        st = speedtest.Speedtest()
        st.get_best_server()
        down = st.download() / 1_000_000
        up = st.upload() / 1_000_000
        print(f"⬇ {down:.2f} Mbps | ⬆ {up:.2f} Mbps")
    except Exception as e:
        print("❌ Speed test failed:", e)

# ========== STEP 7: Connected Devices ==========

TRUSTED_MACS_FILE = "trusted_macs.txt"

def get_default_gateway():
    if platform.system() == "Windows":
        output = subprocess.getoutput("ipconfig")
        capture = False
        for line in output.splitlines():
            line = line.strip()
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    ip = parts[-1].strip()
                    if ip:
                        return ip
    return None  # Avoid fallback

def get_connected_devices_with_ip(ip_range=None):
    if ip_range is None:
        gateway = get_default_gateway()
        if gateway:
            ip_prefix = ".".join(gateway.split(".")[:3])
            ip_range = f"{ip_prefix}.0/24"
        else:
            print("❌ Could not detect gateway. Please connect to a network.")
            return []

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    ignore_mac_prefixes = {"01:00:5e", "33:33", "ff:ff", "00:00:00"}
    for snd, rcv in result:
        mac = rcv.hwsrc.lower()
        if any(mac.startswith(pfx) for pfx in ignore_mac_prefixes):
            continue
        devices.append((mac.upper(), rcv.psrc))

    if len(devices) < 2:
        print("⚠️ ARP returned few devices, sniffing instead...")
        passive = passive_sniff_devices()
        for mac, ip in passive:
            if (mac, ip) not in devices:
                devices.append((mac, ip))

    try:
        with open("passive_sniff.log", "w") as f:
            for mac, ip in devices:
                f.write(f"{mac},{ip}\n")
    except Exception as e:
        print("Error writing sniff log:", e)

    return devices

def passive_sniff_devices(duration=10):
    print(f"🔍 Passive sniffing {duration}s...")
    seen = set()

    def handle(pkt):
        if Ether in pkt and IP in pkt:
            mac = pkt[Ether].src
            ip = pkt[IP].src
            if not any(mac.lower().startswith(p) for p in ("01:00:5e", "33:33", "ff:ff", "00:00")):
                seen.add((mac.upper(), ip))

    sniff(filter="ip", prn=handle, timeout=duration, store=0)
    return list(seen)

def load_trusted_macs():
    if os.path.exists(TRUSTED_MACS_FILE):
        with open(TRUSTED_MACS_FILE, "r") as f:
            return [line.strip().lower() for line in f]
    return []

def save_trusted_macs(new_macs):
    existing = load_trusted_macs()
    updated = list(set(existing + new_macs))
    with open(TRUSTED_MACS_FILE, "w") as f:
        for mac in updated:
            f.write(mac + "\n")

# ========== STEP 8: Monitoring ==========

def run_traffic_monitor(interface):
    start_monitoring(interface)

# ========== MAIN ==========

def run_diagnostics():
    input("🔘 Press Enter to begin...\n")
    list_interfaces()
    interface = input("💬 Interface to troubleshoot: ").strip()
    if not check_cable_or_wifi_gui(interface): return
    if not check_ip_and_dhcp_info(interface): return
    if not ping_router(): return
    if not check_dns_resolution(): return
    if not ping_external(): return
    speed_test()
    run_traffic_monitor(interface)
