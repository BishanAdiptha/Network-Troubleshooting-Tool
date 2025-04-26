# network_activity.py

import psutil
import socket
import threading
import time
import ipinfo
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
IPINFO_ACCESS_TOKEN = "d075f74a07df28"
IPINFO = ipinfo.getHandler(IPINFO_ACCESS_TOKEN)  # optional
POLL_INTERVAL = 2.0

# ── Globals ────────────────────────────────────────────────────────────────────
_seen = set()
_lock = threading.Lock()

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def get_country_flag(ip: str) -> str:
    try:
        det = IPINFO.getDetails(ip)
        return det.country_name or det.country or "Unknown"
    except:
        return "Unknown"

def describe_protocol(conn: psutil._common.sconn) -> str:
    if conn.type == socket.SOCK_STREAM:
        return "TCP"
    if conn.type == socket.SOCK_DGRAM:
        return "UDP"
    return str(conn.type)

# Global list for live display
recent_connections = []

def scan_connections():
    print("\n🔍 Step 9: Network Activity (First-time connections)...\n")
    while True:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            proto = describe_protocol(conn)
            pid   = conn.pid or 0
            rip   = conn.raddr.ip
            rport = conn.raddr.port
            key   = (pid, rip, rport, proto)

            with _lock:
                if key in _seen:
                    continue
                _seen.add(key)

            try:
                pname = psutil.Process(pid).name()
            except:
                pname = f"<pid {pid}>"

            host    = resolve_hostname(rip)
            country = get_country_flag(rip)
            ts      = datetime.now().strftime("%I:%M %p")
            msg = f"{pname:<15} → {host} ({rip}:{rport}) [{proto}, {country}] at {ts}"


            with _lock:
                recent_connections.append(msg)
                if len(recent_connections) > 5:  # Only show latest 5
                    recent_connections.pop(0)


# At bottom of network_activity.py
def start_network_activity_monitor():
    """Starts background thread for first‑time connection logs."""
    t = threading.Thread(target=scan_connections, daemon=True)
    t.start()


def get_recent_connections():
    with _lock:
        return list(recent_connections)

