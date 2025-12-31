import websocket
import json
import platform
import socket
import requests
import psutil
import subprocess
import os
import time
import logging
import threading
from queue import Queue
import sys
from datetime import datetime
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("soc_agent.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

BACKEND = "http://localhost:3000"
WS_BACKEND = "ws://localhost:3000"


# -------------------- Helpers --------------------

def cmd(c):
    try:
        return subprocess.check_output(
            c, shell=True, stderr=subprocess.DEVNULL, timeout=30
        ).decode(errors="ignore")
    except subprocess.TimeoutExpired:
        logging.warning(f"Command timeout: {c[:50]}...")
        return ""
    except Exception as e:
        logging.debug(f"Command failed: {c[:50]}... - {e}")
        return ""


def get_scan_id():
    """Get or create scan session with retry logic"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Try existing browser session
            r = requests.get(f"{BACKEND}/api/active-session", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if "scan_id" in data:
                    return data["scan_id"]

            # Fallback: create new session
            logging.info("No active session found, creating new scan session")
            r2 = requests.post(f"{BACKEND}/api/create-session", timeout=5)
            data2 = r2.json()

            if "scan_id" not in data2:
                raise RuntimeError(f"Failed to create scan session: {data2}")

            return data2["scan_id"]
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                logging.warning(f"Connection attempt {attempt + 1} failed, retrying...")
                time.sleep(2)
            else:
                raise RuntimeError(f"Failed to connect to backend after {max_retries} attempts: {e}")


def calculate_file_hash(filepath, algorithm='sha256'):
    """Calculate hash of a file"""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        return f"Error: {e}"


# -------------------- WebSocket Progress --------------------

ws = None
scan_id = None
ws_lock = threading.Lock()

def init_ws():
    global ws
    try:
        ws = websocket.create_connection(WS_BACKEND, timeout=5)
        ws.send(json.dumps({
            "type": "REGISTER_AGENT",
            "scan_id": scan_id
        }))
        logging.info("WebSocket connection established")
    except Exception as e:
        logging.error(f"WebSocket disabled: {e}")
        ws = None

def progress(msg):
    logging.info(msg)
    if not ws:
        return
    with ws_lock:
        try:
            ws.send(json.dumps({
                "type": "PROGRESS",
                "scan_id": scan_id,
                "message": msg,
                "timestamp": datetime.now().isoformat()
            }))
        except Exception as e:
            logging.debug(f"WebSocket send failed: {e}")


# -------------------- Security Checks --------------------

def firewall_status():
    """Check Windows Firewall status"""
    result = cmd("netsh advfirewall show allprofiles")
    return "ON" if "State" in result and "ON" in result else "OFF"

def defender_status():
    """Check Windows Defender status"""
    out = cmd(
        'powershell "Get-MpComputerStatus | '
        'Select-Object -ExpandProperty RealTimeProtectionEnabled"'
    )
    return "ENABLED" if "True" in out else "DISABLED"

def defender_threats():
    """NEW: Check recent Windows Defender threat detections"""
    progress("Checking Windows Defender threat history")
    out = cmd(
        'powershell "Get-MpThreatDetection | Select-Object -First 10 | '
        'Format-List ThreatName, DetectionTime, ActionSuccess"'
    )
    return out if out else "No recent threats detected"

def rdp_enabled():
    """Check if RDP is enabled"""
    out = cmd(
        'reg query '
        '"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" '
        '/v fDenyTSConnections'
    )
    return "YES" if "0x0" in out else "NO"

def smb_v1():
    """Check if SMBv1 is enabled"""
    result = cmd(
        'powershell "Get-WindowsOptionalFeature '
        '-Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State"'
    )
    return "ENABLED" if "Enabled" in result else "DISABLED"

def failed_logins():
    """Count failed login attempts"""
    out = cmd(
        'powershell "Get-WinEvent -LogName Security -MaxEvents 100 -ErrorAction SilentlyContinue | '
        'Where-Object {$_.Id -eq 4625} | Measure-Object | Select-Object -ExpandProperty Count"'
    )
    try:
        return int(out.strip()) if out.strip() else 0
    except:
        return 0

def check_uac_status():
    """NEW: Check User Account Control status"""
    progress("Checking UAC status")
    out = cmd(
        'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" '
        '/v EnableLUA'
    )
    return "ENABLED" if "0x1" in out else "DISABLED"

def check_auto_updates():
    """NEW: Check Windows Update auto-update status"""
    progress("Checking Windows Update configuration")
    out = cmd(
        'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" '
        '/v NoAutoUpdate'
    )
    # NoAutoUpdate=1 means disabled, 0 or missing means enabled
    return "DISABLED" if "0x1" in out else "ENABLED"

def check_installed_av():
    """NEW: Detect installed antivirus software"""
    progress("Detecting installed antivirus products")
    out = cmd(
        'powershell "Get-CimInstance -Namespace root/SecurityCenter2 '
        '-ClassName AntivirusProduct | Select-Object -ExpandProperty displayName"'
    )
    av_list = [line.strip() for line in out.splitlines() if line.strip()]
    return av_list if av_list else ["None detected"]


# -------------------- System Info --------------------

def system_info():
    """Gather comprehensive system information"""
    progress("Collecting system information")
    
    # BUG FIX: Handle division by zero for disk usage
    try:
        disk_usage = psutil.disk_usage("/")
        disk_total_gb = round(disk_usage.total / (1024**3), 2)
        disk_percent = disk_usage.percent
    except:
        disk_total_gb = 0
        disk_percent = 0
    
    return {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "uptime_hours": round((time.time() - psutil.boot_time()) / 3600, 2),
        "cpu_cores": psutil.cpu_count(),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "ram_usage": psutil.virtual_memory().percent,
        "disk_total_gb": disk_total_gb,
        "disk_usage": disk_percent,
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "logged_in_users": len(psutil.users()),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
        "scan_timestamp": datetime.now().isoformat()
    }

def network_info():
    """NEW: Gather network interface information"""
    progress("Collecting network interface information")
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        iface_info = {"interface": iface, "addresses": []}
        for addr in addrs:
            iface_info["addresses"].append({
                "family": str(addr.family),
                "address": addr.address,
                "netmask": addr.netmask
            })
        interfaces.append(iface_info)
    return interfaces

def running_processes():
    """NEW: Get list of running processes with high CPU/memory"""
    progress("Analyzing running processes")
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                # Only include processes with significant resource usage
                if info['cpu_percent'] > 5 or info['memory_percent'] > 5:
                    processes.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "cpu_percent": round(info['cpu_percent'], 2),
                        "memory_percent": round(info['memory_percent'], 2)
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        return processes[:20]  # Top 20 processes
    except Exception as e:
        logging.error(f"Error getting processes: {e}")
        return []


# -------------------- Nmap Scan --------------------

def nmap_scan(target="127.0.0.1"):
    """Perform network port scan with PROPER detection and error handling"""
    progress("Running Nmap port scan")
    
    try:
        # First, check if nmap is installed
        nmap_check = cmd("nmap --version")
        logging.info(f"Nmap check output: {nmap_check[:100]}")
        
        # Check for common "not found" indicators
        if not nmap_check:
            logging.warning("Nmap check returned empty string")
            return {
                "status": "NOT_INSTALLED",
                "open_ports": [],
                "ports_count": 0,
                "raw_output": "Nmap command returned no output",
                "error": "Nmap not found in PATH",
                "target": target
            }
        
        if any(x in nmap_check.lower() for x in ["not recognized", "not found", "no such file"]):
            logging.warning("Nmap is not installed or not in PATH")
            return {
                "status": "NOT_INSTALLED",
                "open_ports": [],
                "ports_count": 0,
                "raw_output": nmap_check,
                "error": "Nmap is not installed or not in PATH",
                "target": target
            }
        
        # If we got here, nmap exists - now run the actual scan
        logging.info("Nmap found, starting scan...")
        progress(f"Scanning {target} with Nmap...")
        
        result = cmd(f"nmap -T4 -F {target}")
        
        if not result:
            logging.error("Nmap scan returned no output")
            return {
                "status": "ERROR",
                "open_ports": [],
                "ports_count": 0,
                "raw_output": "",
                "error": "Nmap scan returned no output",
                "target": target
            }
        
        # Parse the results
        open_ports = []
        for line in result.splitlines():
            line_lower = line.lower()
            if "/tcp" in line_lower and "open" in line_lower:
                # Parse the line: "80/tcp    open  http"
                parts = line.strip().split()
                if len(parts) >= 2:
                    port_info = {
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    open_ports.append(port_info)
                    logging.info(f"Found open port: {port_info}")
        
        progress(f"Nmap completed - {len(open_ports)} open ports found")
        
        return {
            "status": "COMPLETED",
            "open_ports": open_ports,
            "ports_count": len(open_ports),
            "raw_output": result,
            "target": target,
            "scan_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        logging.error(f"Nmap error: {e}")
        return {
            "status": "ERROR",
            "error": str(e),
            "open_ports": [],
            "ports_count": 0,
            "raw_output": "",
            "target": target
        }


# -------------------- ClamAV Scan --------------------

def clamav_scan():
    """Perform malware scan with ClamAV"""
    progress("Initializing ClamAV malware scan")

    clamav_dir = r"C:\Program Files\ClamAV"
    scan_target = r"C:\Users\manoj\Downloads\agent-test"

    base_dir = os.path.dirname(
        sys.executable if getattr(sys, 'frozen', False) else __file__
    )
    report_path = os.path.join(base_dir, "clamav_report.txt")

    # BUG FIX: Check if ClamAV is installed
    if not os.path.exists(clamav_dir):
        progress("ClamAV not installed, skipping scan")
        return {
            "status": "NOT_INSTALLED",
            "infected_files": [],
            "infected_count": 0,
            "files_scanned": 0,
            "report": "ClamAV not installed",
            "errors": ["ClamAV directory not found"]
        }

    if not os.path.exists(scan_target):
        progress("ClamAV scan path not found, skipping scan")
        return {
            "status": "PATH_NOT_FOUND",
            "infected_files": [],
            "infected_count": 0,
            "files_scanned": 0,
            "report": "Scan path not found",
            "errors": ["Scan path not found"]
        }

    infected = []
    errors = []
    files_scanned = 0

    # BUG FIX: Handle case where scan_target has no subdirectories
    try:
        subdirs = [
            os.path.join(scan_target, d)
            for d in os.listdir(scan_target)
            if os.path.isdir(os.path.join(scan_target, d))
        ]
        
        # If no subdirectories, scan the target directory itself
        if not subdirs:
            subdirs = [scan_target]
    except Exception as e:
        logging.error(f"Error listing directories: {e}")
        return {
            "status": "ERROR",
            "infected_files": [],
            "infected_count": 0,
            "files_scanned": 0,
            "report": f"Error accessing scan directory: {e}",
            "errors": [str(e)]
        }

    q = Queue()
    for s in subdirs:
        q.put(s)

    files_scanned_lock = threading.Lock()

    def scan_subdir(subdir):
        nonlocal files_scanned
        progress(f"Scanning directory: {subdir}")
        scan_cmd = f'"{clamav_dir}\\clamscan.exe" -r --infected "{subdir}"'
        try:
            proc = subprocess.Popen(
                scan_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            for line in proc.stdout:
                decoded = line.decode(errors="ignore").strip()
                if decoded:
                    with files_scanned_lock:
                        files_scanned += 1
                    if decoded.endswith("FOUND"):
                        infected.append(decoded)
                        progress(f"INFECTED FILE FOUND: {decoded}")
            proc.wait()
        except Exception as e:
            errors.append(f"Error scanning {subdir}: {str(e)}")
            logging.error(f"Scan error in {subdir}: {e}")

    def worker():
        while not q.empty():
            try:
                subdir = q.get_nowait()
            except:
                break
            scan_subdir(subdir)
            q.task_done()

    # BUG FIX: Handle case with no subdirectories
    num_threads = min(10, max(1, q.qsize()))
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Write report
    try:
        with open(report_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(f"ClamAV Scan Report - {datetime.now().isoformat()}\n")
            f.write(f"Scan Target: {scan_target}\n")
            f.write(f"Files Scanned: {files_scanned}\n")
            f.write(f"Infected Files: {len(infected)}\n\n")
            for i in infected:
                f.write(i + "\n")

        with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
            report_text = f.read()
    except Exception as e:
        report_text = f"Error writing report: {e}"
        logging.error(f"Report write error: {e}")

    progress(
        f"ClamAV completed — {files_scanned} files scanned, "
        f"{len(infected)} infected"
    )

    return {
        "status": "OK" if not infected else "INFECTED",
        "infected_files": infected[:100],  # Limit to first 100 for payload size
        "infected_count": len(infected),
        "files_scanned": files_scanned,
        "report": report_text,
        "errors": errors,
        "scan_time": datetime.now().isoformat()
    }


# -------------------- Startup Programs --------------------

def check_startup_programs():
    """NEW: Check programs configured to run at startup"""
    progress("Checking startup programs")
    startup_items = []
    
    # Check Registry Run keys
    reg_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    ]
    
    for key in reg_keys:
        out = cmd(f'reg query "{key}"')
        if out:
            startup_items.append({"location": key, "items": out})
    
    # Check Startup folder
    startup_folder = cmd(
        'powershell "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"'
    )
    if startup_folder:
        startup_items.append({"location": "Startup Folder", "items": startup_folder})
    
    return startup_items


# -------------------- MAIN FLOW --------------------

if __name__ == "__main__":
    try:
        logging.info("=" * 60)
        logging.info("SOC Agent Enhanced - Starting Security Scan")
        logging.info("=" * 60)
        
        logging.info("Requesting scan session from backend")
        scan_id = get_scan_id()
        logging.info(f"Scan ID: {scan_id}")

        init_ws()

        # System Information
        system = system_info()

        # Security Configuration
        progress("Collecting security configuration")
        security = {
            "firewall": firewall_status(),
            "defender": defender_status(),
            "defender_threats": defender_threats(),
            "rdp": rdp_enabled(),
            "smb_v1": smb_v1(),
            "failed_logins": failed_logins(),
            "uac_status": check_uac_status(),
            "auto_updates": check_auto_updates(),
            "installed_av": check_installed_av(),
            "open_ports": list(
                set(
                    c.laddr.port
                    for c in psutil.net_connections()
                    if c.status == "LISTEN"
                )
            )
        }

        # Network scan
        security["nmap"] = nmap_scan()
        
        # Malware scan
        security["clamav"] = clamav_scan()
        
        # Additional scans
        security["startup_programs"] = check_startup_programs()

        # System details
        system["network_interfaces"] = network_info()
        system["top_processes"] = running_processes()

        progress("Finalizing and sending results to SOC backend")

        payload = {
            "scan_id": scan_id,
            "system": system,
            "security": security,
            "agent_version": "2.0.0",
            "scan_completed_at": datetime.now().isoformat()
        }

        resp = requests.post(
            f"{BACKEND}/api/scan-result",
            json=payload,
            timeout=200
        )

        progress("Scan completed successfully")
        logging.info(f"Backend response: {resp.status_code} {resp.text}")
        
        # Close WebSocket
        if ws:
            with ws_lock:
                ws.close()

    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
    except Exception as e:
        logging.exception("Agent crashed")
        if ws:
            with ws_lock:
                try:
                    ws.close()
                except:
                    pass
        input("Agent crashed. Press ENTER to exit...")