import urllib.request
import json
import time
import random
import socket
from datetime import datetime

DJANGO_URL = "http://localhost:3000/api/logs"

USERS = ["root", "admin", "vansh"]
IPS = ["192.168.1.5", "45.67.89.10", "185.23.44.12"]
PROCESSES = ["bash", "ssh", "curl", "osascript"]

def now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def send(event):
    payload = {
        "type": "INGESTION",
        "source": f"Attacker_Sim [{socket.gethostname()}]",
        "details": event
    }
    
    try:
        req = urllib.request.Request(
            DJANGO_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=1) as res:
            print(f"Sent → {event['event_type']} simulation step: HTTP {res.status}")
    except Exception as e:
        print("Error sending sequence:", e)

def failed_login():
    return {
        "ip": random.choice(IPS), "user": random.choice(USERS), "action": "LOGIN",
        "status": "FAILURE", "event_type": "auth", "timestamp": now()
    }

def suspicious_command():
    return {
        "ip": random.choice(IPS), "user": "root", "action": "PRIVILEGE_ESCALATION",
        "status": "SUCCESS", "event_type": "exploit", "timestamp": now()
    }

def network_connection():
    return {
        "ip": random.choice(IPS), "user": "www-data", "action": "DOWNLOAD",
        "status": "DENIED", "event_type": "malware", "timestamp": now()
    }

def unauthorized_access():
    return {
        "ip": random.choice(IPS), "user": "vansh", "action": "EXPORT_DB",
        "status": "DENIED", "event_type": "exfiltration", "timestamp": now()
    }

def attack_sequence():
    return [failed_login(), failed_login(), suspicious_command(), network_connection(), unauthorized_access()]

print("🚨 Aegis Attack Simulator Running (Press Ctrl+C to stop)...\n")

while True:
    mode = random.choice(["normal", "attack"])

    if mode == "normal":
        send(failed_login())
        time.sleep(random.uniform(1.0, 2.5))
    else:
        print("\n⚠️ Simulating ATTACK sequence...\n")
        for event in attack_sequence():
            send(event)
            time.sleep(0.7)
        time.sleep(3)
