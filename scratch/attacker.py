import requests
import time
import random
import socket
from datetime import datetime

DJANGO_URL = "http://localhost:3000/api/logs/"

USERS = ["root", "admin", "vansh"]
IPS = ["192.168.1.5", "45.67.89.10", "185.23.44.12"]
PROCESSES = ["bash", "ssh", "curl", "osascript"]

def now():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

def send(event):
    # Formatted exactly like Aegis expects SIEM logs!
    formatted_log = {
        "ip": event["ip"],
        "user": event["user"],
        "action": event["action"],
        "status": event["status"],
        "event_type": event["category"],
        "timestamp": now()
    }
    
    try:
        # Pushing straight to Aegis Ingest format internally via standard HTTP POST
        res = requests.post(DJANGO_URL, json={
            "type": "INGESTION",
            "source": f"Attacker_Sim [{socket.gethostname()}]",
            "details": formatted_log
        }, timeout=1)
        print(f"Sent → {event['category']} attacker step: {res.status_code}")
    except Exception as e:
        print("Error:", e)


def failed_login():
    return {
        "ip": random.choice(IPS),
        "user": random.choice(USERS),
        "action": "LOGIN",
        "status": "FAILURE",
        "category": "auth"
    }

def suspicious_command():
    return {
        "ip": random.choice(IPS),
        "user": "root",
        "action": "PRIVILEGE_ESCALATION",
        "status": "SUCCESS",
        "category": "exploit"
    }

def network_connection():
    return {
        "ip": random.choice(IPS),
        "user": "www-data",
        "action": "DOWNLOAD",
        "status": "DENIED",
        "category": "malware"
    }

def unauthorized_access():
    return {
        "ip": random.choice(IPS),
        "user": "vansh",
        "action": "EXPORT_DB",
        "status": "DENIED",
        "category": "exfiltration"
    }

def attack_sequence():
    return [
        failed_login(),
        failed_login(),
        suspicious_command(),
        network_connection(),
        unauthorized_access()
    ]

print("🚨 Aegis Attack Simulator Running (Press Ctrl+C to stop)...\\n")

while True:
    mode = random.choice(["normal", "attack"])

    if mode == "normal":
        event = failed_login() # Lots of background failed noise
        send(event)
        time.sleep(random.uniform(1.0, 2.5))
    else:
        print("\\n⚠️ Simulating ATTACK sequence...\\n")
        for event in attack_sequence():
            send(event)
            time.sleep(0.7)
        time.sleep(3)
