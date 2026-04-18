import urllib.request
import json
import re
import time
import subprocess
import socket
import uuid
import os
import sys

DJANGO_URL = "http://127.0.0.1:3000/api/agent/logs"
SOAR_URL = "http://127.0.0.1:3000/api/soar/pending"

def get_device_id():
    return f"{socket.gethostname()}-{uuid.getnode()}"

# 🔥 Ignore heavy Apple noise
IGNORE_KEYWORDS = [
    "com.apple", "duetactivity", "analyticsd", "suggestd",
    "photolibrary", "spotlight", "runningboard", "coreanalytics",
    "bluetooth", "locationd", "music:", "coreaudiod"
]

# 🧠 dedup
RECENT = []

def is_duplicate(log):
    if log in RECENT:
        return True
    RECENT.append(log)
    if len(RECENT) > 100:
        RECENT.pop(0)
    return False

def has_ip(text):
    return re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

# ======================
# 🔥 LOG FILTER (simple)
# ======================
def is_suspicious_log(log):
    lower = log.lower()
    if any(k in lower for k in IGNORE_KEYWORDS):
        return False
    if "failed login" in lower or "invalid password" in lower:
        return True
    if "permission denied" in lower:
        return True
    if "usb" in lower and ("attached" in lower or "detached" in lower):
        return True
    return False

# ======================
# 🔥 PROCESS DETECTION
# ======================
def scan_processes():
    try:
        output = subprocess.check_output(["ps", "aux"]).decode().lower()
        alerts = []
        if "curl" in output:
            alerts.append(("PROCESS", "curl command execution detected", "MEDIUM"))
        if "ssh " in output:
            alerts.append(("PROCESS", "ssh process connection out", "HIGH"))
        if "osascript" in output:
            alerts.append(("PROCESS", "osascript execution detected", "HIGH"))
        return alerts
    except:
        return []

# ======================
# 🚀 MAIN
# ======================
if __name__ == "__main__":
    print("🚀 Hybrid Mac Security Agent Started")
    print("Capturing Live Streams and Process Monitoring...")

    try:
        process = subprocess.Popen(
            ["log", "stream", "--level", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
    except:
        print("Required root or sudo privileges for log stream. Falling back to basic process monitoring.")
        process = None

    buffer = []
    last_scan = time.time()

    def send_buffer():
        global buffer
        if not buffer: return
        payload = {
            "logs": buffer,
            "device_name": socket.gethostname(),
            "device_id": get_device_id()
        }
        try:
            req = urllib.request.Request(
                DJANGO_URL,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=1) as res:
                print(f"✅ Sent {len(buffer)} logs to Aegis")
        except Exception as e:
            pass
        buffer = []

    try:
        while True:
            # Try to read line without blocking forever if no process
            if process:
                line = process.stdout.readline()
                if line:
                    line = line.strip()
                    if is_suspicious_log(line) and not is_duplicate(line):
                        buffer.append({
                            "pattern": line,
                            "category": "OS_LOG",
                            "risk": "MEDIUM",
                            "ip": "127.0.0.1",
                            "user": os.getlogin()
                        })

            if time.time() - last_scan > 2:
                # 🛡️ SOAR ACTIVE RESPONSE POLL
                try:
                    req = urllib.request.Request(SOAR_URL, method='GET')
                    with urllib.request.urlopen(req, timeout=1) as res:
                        actions = json.loads(res.read().decode())
                        for action in actions:
                            if action.get("action") == "ISOLATE_SYSTEM" or action.get("action") == "BLOCK_IP":
                                target = action.get("target")
                                SAFE = ["127.0.0.1", "localhost"]
                                if target in SAFE: continue
                                print(f"🔥 SOAR: Aegis SIEM triggered block for -> {target}")
                except Exception as soar_e:
                    pass

                for cat, msg, risk in scan_processes():
                    if not is_duplicate(msg):
                        buffer.append({
                            "pattern": msg,
                            "category": cat,
                            "risk": risk,
                            "ip": "127.0.0.1",
                            "user": os.getlogin()
                        })

                send_buffer()
                last_scan = time.time()

            time.sleep(0.01)
    except KeyboardInterrupt:
        print("\nAgent Terminated.")
        if process: process.terminate()
        sys.exit(0)
