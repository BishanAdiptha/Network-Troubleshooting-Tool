import os
import socket
import time
import platform
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, srp
import numpy as np
from sklearn.ensemble import IsolationForest

TRUSTED_MACS = ["22:33:44:55:66:77"]

# ========== STEP 1: INTERFACE & PHYSICAL CONNECTIVITY ==========
def list_interfaces():
    print("\n🔌 Step 1: Physical Connectivity - Available Network Interfaces")
    if platform.system() == "Windows":
        result = subprocess.getoutput("netsh interface show interface")
        print(result)
    else:
        print("⚠ Interface listing is only supported on Windows.")

def follow_up_questions(interface):
    print("\n📋 Additional Physical Checks:")
    interface_lower = interface.lower()
    if "ethernet" in interface_lower:
        input("🧩 Is the Ethernet cable plugged in properly? (Press Enter to continue)")
        input("💡 Are the LEDs blinking on the port or router? (Press Enter to continue)")
    if "wi-fi" in interface_lower or "wifi" in interface_lower:
        input("📶 Is Wi-Fi turned ON and connected to the correct network? (Press Enter to continue)")
    input("✈️ Is Airplane mode OFF on your device? (Press Enter to continue)")

def check_cable_or_wifi(target_interface):
    print(f"\n🔍 Checking connectivity for: {target_interface}")
    is_connected = False
    if platform.system() == "Windows":
        result = subprocess.getoutput("netsh interface show interface")
        lines = result.splitlines()
        for line in lines:
            if target_interface.lower() in line.lower():
                if "Connected" in line:
                    print(f"✅ {target_interface} is connected.")
                    is_connected = True
                else:
                    print(f"⚠️ {target_interface} is not connected.")
                    is_connected = False
                break
        if not is_connected:
            follow_up_questions(target_interface)
        return is_connected
    else:
        print("⚠ Unsupported OS for interface checking.")
        return True

# ========== STEP 2: IP & DHCP CHECK ==========
def check_ip_and_dhcp(selected_interface):
    print("\n📡 Step 2: IP Address & DHCP Configuration Check")
    if platform.system() != "Windows":
        print("⚠️ IP/DHCP checks are only supported on Windows.")
        return True

    output = subprocess.getoutput("ipconfig /all")
    lines = output.splitlines()
    adapter_section = False
    ip_valid = False
    dhcp_enabled = None
    ip_address = ""
    gateway = ""
    dns_servers = []

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
        if "IPv4 Address" in line or "IPv4-Adresse" in line:
            ip_address = line.split(":")[-1].strip().split("(")[0].strip()
            if ip_address.startswith("169.254"):
                ip_valid = False
            else:
                ip_valid = True
        if "Default Gateway" in line and line.split(":")[-1].strip():
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
        print(f"⚠️ Could not determine IP address for {selected_interface}")
        return False

    if dhcp_enabled:
        if ip_valid:
            print(f"✅ Valid IP assigned via DHCP on {selected_interface}: {ip_address}")
        else:
            print(f"⚠️ DHCP is enabled but an invalid IP was assigned: {ip_address}")
            print("👉 Try resetting your IP settings or network adapter in Windows settings.")
    else:
        print(f"⚠️ DHCP is disabled on {selected_interface}.")
        print(f"ℹ️ Static IP is set to: {ip_address}")
        if not gateway:
            print("❌ Default gateway is missing.")
        if not dns_servers or all(d.startswith("0.") for d in dns_servers):
            print("❌ No valid DNS servers configured.")
        print("👉 Please check your static IP configuration in Windows network settings.")

    return ip_valid and (dhcp_enabled or gateway)

# ========== STEP 3: PING ROUTER ==========
def ping_router(gateway="192.168.1.1"):
    print("\n📶 Step 3: Pinging Router...")
    output = os.popen(f"ping -n 2 {gateway}" if os.name == "nt" else f"ping -c 2 {gateway}").read()
    print(output)
    if "TTL=" in output or "bytes from" in output:
        print("✅ Router is reachable.")
        return True
    else:
        print("❌ Router is unreachable.")
        print("\n💡 Troubleshooting Steps:")
        input("1️⃣ Ensure Ethernet/Wi-Fi is properly connected. (Press Enter to continue)")
        input("2️⃣ Check your IP settings are correct. (Press Enter to continue)")
        input("3️⃣ Restart your router or modem. (Press Enter to continue)")
        input("4️⃣ Disconnect and reconnect Ethernet or Wi-Fi. (Press Enter to continue)")
        input("5️⃣ Contact your Internet Service Provider if problem persists. (Press Enter to continue)")
        return False

# ========== STEP 4: DNS RESOLUTION ==========
def dns_check():
    print("\n🌐 Step 4: DNS Resolution...")
    try:
        socket.gethostbyname("google.com")
        print("✅ DNS is working.")
        return True
    except:
        print("❌ DNS resolution failed.")
        return False

# ========== STEP 5: INTERNET ACCESS ==========
def ping_external():
    print("\n🌎 Step 5: Internet Access Check...")
    output = os.popen("ping -n 2 8.8.8.8" if os.name == "nt" else "ping -c 2 8.8.8.8").read()
    print(output)
    if "TTL=" in output or "bytes from" in output:
        print("✅ Internet is accessible.")
        return True
    else:
        print("❌ Unable to access the internet.")
        return False

# ========== STEP 6: SPEED TEST ==========
def speed_test():
    print("\n🚀 Step 6: Speed Test...")
    try:
        import speedtest
        st = speedtest.Speedtest()
        st.get_best_server()
        down = st.download() / 1_000_000
        up = st.upload() / 1_000_000
        print(f"⬇ {down:.2f} Mbps | ⬆ {up:.2f} Mbps")
        if down < 5 or up < 1:
            print("⚠️ Internet speed is very slow.")
        return True
    except Exception as e:
        print(f"❌ Speed test error: {e}")
        return False

# ========== STEP 7: UNAUTHORIZED DEVICES ==========
def get_connected_devices(ip_range="192.168.1.1/24"):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]
    return [rcv.hwsrc for snd, rcv in result]

def check_unauthorized_devices():
    print("\n🔒 Step 7: Unauthorized Devices...")
    connected = get_connected_devices()
    unauthorized = list(set(connected) - set(TRUSTED_MACS))
    if unauthorized:
        print("🚨 Unauthorized Devices Detected:")
        for mac in unauthorized:
            print(f" - {mac}")
    else:
        print("✅ No unauthorized devices found.")

# ========== STEP 8: PACKET SNIFFING & ML ==========
def analyze_packet(pkt):
    if IP in pkt:
        ip = pkt[IP]
        proto = pkt.proto if hasattr(pkt, 'proto') else -1
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
        print(f"📦 {ip.src}:{sport} → {ip.dst}:{dport} (Proto: {proto})")
        return [time.time(), len(pkt), proto]
    return None

def sniff_and_detect(interface):
    print("\n🎯 Sniffing Packets for Anomaly Detection...")
    captured = []
    sniff(iface=interface, prn=lambda pkt: captured.append(analyze_packet(pkt)), store=0, count=50)
    captured = [p for p in captured if p]
    if not captured:
        print("❌ No packets captured.")
        return
    X = np.array([[p[1], p[2]] for p in captured if isinstance(p[2], (int, float))])
    if len(X) < 5:
        print("⚠️ Not enough data for anomaly detection.")
        return
    model = IsolationForest(contamination=0.1)
    model.fit(X)
    preds = model.predict(X)
    anomalies = sum(preds == -1)
    print(f"🔍 Anomalies Detected: {anomalies}")
    if anomalies > 5:
        print("🚨 Possible network congestion or attack.")

# ========== RUN DIAGNOSTICS ==========
def run_diagnostics():
    input("\n🔘 Press Enter to run full Network Troubleshooter...\n")
    list_interfaces()
    interface = input("\n💬 Enter the interface name you want to troubleshoot (e.g., Ethernet, Wi-Fi): ").strip()

    if not check_cable_or_wifi(interface): return
    if not check_ip_and_dhcp(interface): return
    if not ping_router(): return
    dns_ok = dns_check()
    net_ok = ping_external()

    if not dns_ok and net_ok:
        print("🧠 Internet is reachable but DNS resolution is failing → DNS issue.")
        input("💡 Try changing DNS to 8.8.8.8 or enabling automatic DNS. (Press Enter to continue)")
    elif not net_ok:
        input("📶 Internet is not reachable. Try restarting your router. (Press Enter to continue)")

    speed_test()
    check_unauthorized_devices()

    sniff_choice = input("\n🔍 Do you want to run packet sniffing + anomaly detection? (y/n): ")
    if sniff_choice.lower() == "y":
        sniff_and_detect(interface)

    print("\n✅ Troubleshooting complete.")

if __name__ == "__main__":
    run_diagnostics()
