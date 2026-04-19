import urllib.request
import json
import time
import random
import socket
import sys
from datetime import datetime

# dynamic URL from command line or default localhost
BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
if BASE_URL.endswith('/'): BASE_URL = BASE_URL[:-1]

DJANGO_URL = f"{BASE_URL}/api/agent/logs"
SOAR_URL = f"{BASE_URL}/api/firewall/active"

USERS = ["root", "admin", "vansh"]
IPS = ["192.168.1.5", "45.67.89.10", "185.23.44.12"]
PROCESSES = ["bash", "ssh", "curl", "osascript"]

def now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def send(event):
    payload = {
        "logs": [event],
        "device_name": socket.gethostname(),
        "device_id": f"{socket.gethostname()}-sim"
    }
    try:
        req = urllib.request.Request(
            DJANGO_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=1) as res:
            print(f"Sent → {event['category']} payload")
    except Exception as e:
        print("Error sending:", e)

def build_event(action, status, category, risk, ip=None, user=None):
    return {
        "ip": ip or random.choice(IPS),
        "user": user or random.choice(USERS),
        "pattern": action,
        "status": status,
        "category": category,
        "risk": risk,
        "timestamp": now()
    }

def attack_sequence():
    attacker_ip = random.choice(IPS)
    return [
        build_event("failed login", "FAILURE", "AUTH", "MEDIUM", ip=attacker_ip, user="root"),
        build_event("failed login", "FAILURE", "AUTH", "MEDIUM", ip=attacker_ip, user="root"),
        build_event("SPAWN_SHELL", "SUCCESS", "EXPLOIT", "HIGH", ip=attacker_ip, user="root"),
        build_event("curl outbound connection", "DENIED", "NETWORK", "MEDIUM", ip=attacker_ip, user="www-data"),
        build_event("EXPORT_DB", "DENIED", "EXFILTRATION", "HIGH", ip=attacker_ip, user="vansh")
    ]

def check_soar_kill():
    try:
        req = urllib.request.Request(SOAR_URL, method='GET')
        with urllib.request.urlopen(req, timeout=1) as res:
            blocks = json.loads(res.read().decode())
            for block in blocks:
                # Only care about actual active firewall blocks
                target = block.get("ip")
                if target and target in IPS:
                    # Ensure we don't trip on an old pending block randomly
                    print(f"\n💀 [FATAL] SOAR ACTIVE RESPONSE TRIGGERED (Target: {target})! 💀")
                    print("🛑 Threat Blocked! Exiting Simulator...\n")
                    sys.exit(0)
    except SystemExit:
        sys.exit(0)
    except:
        pass

print("🚨 Aegis Realistic Attack Simulator Running (Press Ctrl+C to exit)...\n")

try:
    while True:
        check_soar_kill()
        
        mode = random.choice(["normal", "attack"])

        if mode == "normal":
            event = random.choice([
                build_event("failed login", "FAILURE", "AUTH", "LOW"),
                build_event("usb attached", "SUCCESS", "USB", "LOW"),
                build_event("normal login", "SUCCESS", "AUTH", "LOW")
            ])
            send(event)
            time.sleep(random.uniform(1.0, 2.5))
        else:
            print("\n⚠️ Simulating ATTACK sequence...\n")
            for event in attack_sequence():
                check_soar_kill()
                send(event)
                time.sleep(0.7)
            time.sleep(3)
except KeyboardInterrupt:
    print("\nSimulator stopped.")
    sys.exit(0)
