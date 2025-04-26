#main.py

import os
import socket
import time
import platform
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, srp
from monitor import start_monitoring

import subprocess






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

def check_cable_or_wifi_gui(target_interface):
    result_text = ""
    guidance = []
    is_connected = False

    if platform.system() == "Windows":
        result = subprocess.getoutput("netsh interface show interface")
        for line in result.splitlines():
            if target_interface.lower() in line.lower():
                if "Connected" in line:
                    result_text = f"✅ {target_interface} is connected."
                    is_connected = True
                else:
                    result_text = f"⚠️ {target_interface} is not connected."
                    if "ethernet" in target_interface.lower():
                        guidance = [
                            "🧩 Is the Ethernet cable plugged in properly?",
                            "💡 Are the LEDs blinking on the port or router?"
                        ]
                    elif "wi-fi" in target_interface.lower() or "wifi" in target_interface.lower():
                        guidance = [
                            "📶 Is Wi-Fi turned ON and connected to the correct network?",
                            "✈️ Is Airplane mode OFF on your device?"
                        ]
                break
    return result_text, guidance





# ============================== STEP 2: IP Address & DHCP (GUI Version) ==============================

def check_ip_and_dhcp_info(selected_interface):
    if platform.system() != "Windows":
        return "⚠️ IP/DHCP checks are only supported on Windows."

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
        if "IPv4 Address" in line or "IPv4-Adresse" in line:
            ip_address = line.split(":")[-1].strip().split("(")[0].strip()
            ip_valid = not ip_address.startswith("169.254")
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
        return f"⚠️ Could not determine IP address for {selected_interface}"

    if dhcp_enabled:
        if ip_valid:
            messages.append(f"✅ Valid IP assigned via DHCP on {selected_interface}: {ip_address}")
        else:
            messages.append(f"⚠️ DHCP is enabled but IP is invalid: {ip_address}")
            messages.append("💡 Suggested Steps:")
            messages.append("   - Check your IP settings")
            messages.append("   - Reset adapter or restart PC")
            messages.append("   - Try 'ipconfig /release' then 'ipconfig /renew'")
    else:
        messages.append(f"⚠️ DHCP is disabled on {selected_interface}")
        messages.append(f"ℹ️ Static IP assigned: {ip_address}")
        if not gateway:
            messages.append("❌ Default gateway is missing.")
        if not dns_servers:
            messages.append("❌ No DNS servers configured.")
        messages.append("💡 Please reconfigure IP or enable DHCP in adapter settings.")

    return "\n".join(messages)







# ============================== STEP 3: Ping Router ==============================



def ping_router(gateway="192.168.1.1"):
    output = os.popen(f"ping -n 4 {gateway}" if os.name == "nt" else f"ping -c 4 {gateway}").read()
    success = "TTL=" in output or "bytes from" in output
    return output.strip(), success







# ============================== STEP 4 & 5: DNS + Internet ==============================

def dns_check():
    print("\n🌐 Step 4: DNS Resolution...")
    try:
        socket.gethostbyname("google.com")
        print("✅ DNS is working.")
        return True
    except:
        input("❌ DNS Resolution Failed.\n"
              "💡 Try using 8.8.8.8 or 1.1.1.1 in adapter settings.\n"
              "Press Enter to continue.")
        return False

def ping_external():
    print("\n🌎 Step 5: Internet Access Check...")
    output = os.popen(f"ping -n 2 8.8.8.8" if os.name == "nt" else f"ping -c 2 8.8.8.8").read()
    print(output)
    if "TTL=" in output or "bytes from" in output:
        print("✅ Internet is accessible.")
        return True
    else:
        input("❌ Cannot reach the internet.\n"
              "💡 Check your connection or contact ISP.\n"
              "Press Enter to continue.")
        return False





# ============================== STEP 6: Speed Test =============================

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
            if down < 2: input("⚠️ Very slow download. Try limiting devices.\nPress Enter to continue.")
            elif down < 5: input("⚠️ Slow download speed.\nPress Enter to continue.")
            else: print("✅ Download speed is good.")
            if up < 0.5: input("⚠️ Very slow upload.\nPress Enter to continue.")
            elif up < 2: input("⚠️ Slow upload speed.\nPress Enter to continue.")
            else: print("✅ Upload speed is good.")
        except Exception as e:
            print(f"❌ Speed test failed: {e}")
            input("Try again later. Press Enter to continue.")






# ============================== STEP 7: Connected Devices ==============================

TRUSTED_MACS_FILE = "trusted_macs.txt"

def get_connected_devices_with_ip(ip_range="192.168.1.1/24"):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]
    return [(rcv.hwsrc.lower(), rcv.psrc) for snd, rcv in result]

def get_default_gateway():
    if platform.system() == "Windows":
        output = subprocess.getoutput("ipconfig")
        for line in output.splitlines():
            if "Default Gateway" in line and ":" in line:
                parts = line.split(":")
                if len(parts) > 1 and parts[-1].strip():
                    return parts[-1].strip()
    return "192.168.1.1"

def load_trusted_macs():
    if os.path.exists(TRUSTED_MACS_FILE):
        with open(TRUSTED_MACS_FILE, "r") as f:
            return [line.strip().lower() for line in f.readlines()]
    return []

def save_trusted_macs(new_macs):
    existing = load_trusted_macs()
    updated = list(set(existing + new_macs))
    with open(TRUSTED_MACS_FILE, "w") as f:
        for mac in updated:
            f.write(mac + "\n")

def check_unauthorized_devices():
    print("\n🔒 Step 7: Connected Devices Scan...")
    gateway = get_default_gateway()
    ip_prefix = ".".join(gateway.split(".")[:3]) + ".1/24"
    devices = get_connected_devices_with_ip(ip_prefix)

    if not devices:
        print("⚠️ No devices detected.")
        return

    trusted_macs = load_trusted_macs()

    # Show all connected devices first
    print("📋 All Connected Devices:")
    for i, (mac, ip) in enumerate(devices, 1):
        label = " (Router)" if ip == gateway else ""
        print(f"{i}. MAC: {mac} | IP: {ip}{label}")

    # Filter out already trusted MACs
    untrusted_devices = [(i+1, mac, ip) for i, (mac, ip) in enumerate(devices) if mac not in trusted_macs]

    if not untrusted_devices:
        print("✅ No new untrusted devices detected.")
    else:
        print("\n🆕 New Untrusted Devices:")
        for index, mac, ip in untrusted_devices:
            print(f"{index}. MAC: {mac} | IP: {ip}")

        input_str = input("\n💬 Select which of the above are trusted (e.g., 1 2 ): ").strip()
        selected = [int(i) for i in input_str.split() if i.isdigit()]
        newly_trusted = [devices[i - 1][0] for i in selected if 0 < i <= len(devices)]

        if newly_trusted:
            save_trusted_macs(newly_trusted)
            print("✅ Trusted MACs updated.")

    # Reload final list and show remaining unauthorized
    trusted_macs = load_trusted_macs()
    unauthorized = [(mac, ip) for (mac, ip) in devices if mac not in trusted_macs]

    if unauthorized:
        print("\n🚨 Unauthorized Devices Detected:")
        for mac, ip in unauthorized:
            label = " (Router)" if ip == gateway else ""
            print(f" - MAC: {mac} | IP: {ip}{label}")
        input("⚠️ Consider changing your Wi-Fi password.\nPress Enter to continue.")
    else:
        print("✅ No unauthorized devices found.")








# ============================== STEP 8: TRAFFIC MONITORING ==============================



def run_traffic_monitor(interface):
    print("\n📊 Step 8: New Connections Monitoring...")
    start_monitoring(interface)








# ==================== STEP 9: First-Time Connection Log ====================

















# ============================== MAIN ==============================

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
    run_traffic_monitor(interface)

    print("\n✅ Network troubleshooting complete.")

if __name__ == "__main__":
    run_diagnostics()

