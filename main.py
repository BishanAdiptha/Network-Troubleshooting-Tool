import os
import socket
import time
import platform
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, srp
import numpy as np
from sklearn.ensemble import IsolationForest

TRUSTED_MACS = ["22:33:44:55:66:77"]

# ============================== STEP 1: Physical Connectivity ==============================

def list_interfaces():
    print("\n🔌 Step 1: Physical Connectivity - Available Network Interfaces")
    if platform.system() == "Windows":
        result = subprocess.getoutput("netsh interface show interface")
        print(result)
    else:
        print("⚠ Interface listing is only supported on Windows for now.")

def follow_up_questions(interface):
    print("\n📋 Additional Physical Checks:")
    interface_lower = interface.lower()
    if "ethernet" in interface_lower:
        input("🧩 Is the Ethernet cable plugged in properly? (Press Enter to continue) ")
        input("💡 Are the LEDs blinking on the port or router? (Press Enter to continue) ")
    if "wi-fi" in interface_lower or "wifi" in interface_lower:
        input("📶 Is Wi-Fi turned ON and connected to the correct network? (Press Enter to continue) ")
    input("✈️ Is Airplane mode OFF on your device? (Press Enter to continue) ")

def check_cable_or_wifi(target_interface):
    print(f"\n🔍 Checking connectivity for: {target_interface}")
    is_connected = False
    if platform.system() == "Windows":
        result = subprocess.getoutput("netsh interface show interface")
        for line in result.splitlines():
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
        print("⚠ Cannot verify connectivity on non-Windows systems.")
        return True

# ============================== STEP 2: IP Address & DHCP ==============================

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
            print(f"⚠️ DHCP is enabled but IP is invalid: {ip_address}")
            input("💡 Suggested Steps:\n"
                  " - Check your IP settings\n"
                  " - Reset adapter or restart PC\n"
                  " - Try 'ipconfig /release' then 'ipconfig /renew'\n"
                  "Press Enter to continue.")
    else:
        print(f"⚠️ DHCP is disabled on {selected_interface}")
        print(f"ℹ️ Static IP assigned: {ip_address}")
        if not gateway:
            print("❌ Default gateway is missing.")
        if not dns_servers:
            print("❌ No DNS servers configured.")
        input("💡 Please reconfigure IP or enable DHCP in adapter settings.\n"
              "Press Enter to continue.")
    return ip_valid and (dhcp_enabled or gateway)

# ============================== STEP 3: Ping Router ==============================

def ping_router(gateway="192.168.1.1"):
    print("\n📶 Step 3: Pinging Router...")
    output = os.popen(f"ping -n 2 {gateway}" if os.name == "nt" else f"ping -c 2 {gateway}").read()
    print(output)
    if "TTL=" in output or "bytes from" in output:
        print("✅ Router is reachable.")
        return True
    else:
        input("❌ Router is unreachable.\n"
              "💡 Suggested Steps:\n"
              " - Ensure router is powered on\n"
              " - Check cable/Wi-Fi connection\n"
              " - Restart router and PC\n"
              " - Verify gateway IP is correct\n"
              "Press Enter to continue.")
        return False

# ============================== STEP 4: DNS Resolution ==============================

def dns_check():
    print("\n🌐 Step 4: DNS Resolution...")
    try:
        socket.gethostbyname("google.com")
        print("✅ DNS is working.")
        return True
    except:
        input("❌ DNS Resolution Failed.\n"
              "💡 Try switching to public DNS like 8.8.8.8 or 1.1.1.1\n"
              " - Recheck adapter DNS settings\n"
              " - Restart router/PC\n"
              "Press Enter to continue.")
        return False

# ============================== STEP 5: Internet Access ==============================

def ping_external():
    print("\n🌎 Step 5: Internet Access Check...")
    output = os.popen(f"ping -n 2 8.8.8.8" if os.name == "nt" else f"ping -c 2 8.8.8.8").read()
    print(output)
    if "TTL=" in output or "bytes from" in output:
        print("✅ Internet is accessible.")
        return True
    else:
        input("❌ Cannot reach the internet.\n"
              "💡 Suggested Steps:\n"
              " - Check your IP settings are correct\n"
              " - Restart router/modem\n"
              " - Reconnect Ethernet or Wi-Fi\n"
              " - Contact your ISP if issue persists\n"
              "Press Enter to continue.")
        return False

# ============================== STEP 6: Speed Test ==============================

def speed_test():
    print("\n🚀 Step 6: Speed Test...")
    try:
        import speedtest
        st = speedtest.Speedtest()
        st.get_best_server()
        down = st.download() / 1_000_000
        up = st.upload() / 1_000_000

        print(f"\n⬇ Download Speed: {down:.2f} Mbps")
        print(f"⬆ Upload Speed: {up:.2f} Mbps")

        if down < 2:
            print("⚠️ Very Slow Download Speed.")
            input("💡 May affect streaming/browsing.\n"
                  " - Restart router\n"
                  " - Reduce other users/devices\n"
                  "Press Enter to continue.")
        elif down < 5:
            print("⚠️ Slow Download Speed.")
            input("💡 Try limiting bandwidth usage.\nPress Enter to continue.")
        elif down < 25:
            print("✅ Acceptable Download Speed.")
        elif down < 100:
            print("✅ Good Download Speed.")
        else:
            print("🚀 Excellent Download Speed!")
            print("💡 Great for 4K streaming, gaming, backups.")

        if up < 0.5:
            print("⚠️ Very Slow Upload Speed.")
            input("💡 Affects calls/uploads.\n"
                  " - Close background uploads\n"
                  " - Contact ISP if needed\n"
                  "Press Enter to continue.")
        elif up < 2:
            print("⚠️ Slow Upload Speed.")
            input("💡 May affect video calls.\nPress Enter to continue.")
        elif up < 10:
            print("✅ Upload Speed is Good.")
        else:
            print("🚀 Excellent Upload Speed!")
            print("💡 Ideal for conferencing and cloud sync.")
    except Exception as e:
        print(f"❌ Speed test error: {e}")
        input("⚠️ Try running again later.\nPress Enter to continue.")

# ============================== STEP 7: Unauthorized Devices ==============================

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
        input("⚠️ Secure your Wi-Fi or change your password.\nPress Enter to continue.")
    else:
        print("✅ No unauthorized devices found.")

# ============================== STEP 8: Anomaly Detection ==============================

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
        input("🚨 Multiple anomalies found!\n"
              "💡 Possible congestion or attack.\n"
              "Press Enter to continue.")

# ============================== MAIN =============================

def run_diagnostics():
    input("\n🔘 Press Enter to begin full Network Troubleshooter...\n")
    list_interfaces()
    interface = input("\n💬 Enter the interface name to troubleshoot (e.g., Ethernet, Wi-Fi): ").strip()
    if not check_cable_or_wifi(interface): return
    if not check_ip_and_dhcp(interface): return
    if not ping_router(): return
    if not dns_check(): return
    if not ping_external(): return
    speed_test()
    check_unauthorized_devices()
    sniff_choice = input("\n🔬 Run packet sniffing & anomaly detection? (y/n): ")
    if sniff_choice.lower() == "y":
        sniff_and_detect(interface)
    print("\n✅ Network troubleshooting complete.")

if __name__ == "__main__":
    run_diagnostics()
