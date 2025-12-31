# compatibility.py
import socket
import time
import subprocess
import psutil

# ---------------- Availability Checks ----------------

def ping_host(host, count=3):
    try:
        out = subprocess.check_output(
            f"ping -n {count} {host}",
            shell=True, stderr=subprocess.DEVNULL
        ).decode(errors="ignore")

        latencies = []
        for line in out.splitlines():
            if "time=" in line:
                latencies.append(
                    int(line.split("time=")[1].split("ms")[0])
                )

        return {
            "reachable": True if latencies else False,
            "avg_latency_ms": sum(latencies)//len(latencies) if latencies else None
        }
    except:
        return {"reachable": False, "avg_latency_ms": None}


def tcp_port_check(host, port, timeout=3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return "OPEN"
    except:
        return "CLOSED"


def dns_check(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

# ---------------- Bandwidth Test (No iperf) ----------------

def estimate_bandwidth():
    try:
        before = psutil.net_io_counters().bytes_sent
        time.sleep(1)
        after = psutil.net_io_counters().bytes_sent
        mbps = round(((after - before) * 8) / (1024 * 1024), 2)
        return mbps
    except:
        return None

# ---------------- Product Requirements ----------------

PRODUCTS = {
    "waf": {
        "min_ram": 4,
        "min_cpu": 2,
        "ports": [80, 443]
    },
    "ddos": {
        "min_cpu": 4,
        "min_bandwidth": 100
    },
    "vulnerability_scanner": {
        "min_ram": 2,
        "admin_required": True
    }
}

def recommend_best(products):
    for p, v in products.items():
        if v["compatible"]:
            return p
    return None
def evaluate_products(system, security, bandwidth):
    results = {}

    for product, req in PRODUCTS.items():
        missing = []

        if "min_ram" in req and system["ram_total_gb"] < req["min_ram"]:
            missing.append("RAM")

        if "min_cpu" in req and system["cpu_cores"] < req["min_cpu"]:
            missing.append("CPU")

        if "ports" in req:
            open_ports = set(security.get("open_ports", []))
            for p in req["ports"]:
                if p not in open_ports:
                    missing.append(f"Port {p}")

        if "min_bandwidth" in req and (bandwidth is None or bandwidth < req["min_bandwidth"]):
            missing.append("Bandwidth")

        results[product] = {
            "compatible": len(missing) == 0,
            "missing": missing
        }

    return results
