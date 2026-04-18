# 🛡️ Aegis Autonomous SIEM

Aegis Autonomous SIEM is a next-generation security operations platform featuring an AI-driven threat detection pipeline, real-time agent logging, and a self-healing SOAR (Security Orchestration, Automation, and Response) engine. It provides unparalleled "Human-in-the-Loop" analytics alongside a stunning, minimalist Google Pixel / macOS-inspired dark UI.

## 🌟 Key Features

### 1. Neural Analysis Pipeline (Phases 1-6)
* **Phase 1: Ingestion Layer** — Centralized log collection from native OS endpoints.
* **Phase 2: Normalization** — Standardizing heterogeneous schemas across various environments.
* **Phase 3: Graph Engine** — Building behavioral node-edge models mapping entities over time.
* **Phase 4: Detection Engine** — Advanced heuristic correlation detecting IP-based brute forces, lateral movement, data exfiltration, and critical process hijacking.
* **Phase 5: Neural AI Reasoning** — Employs Gemini Flash (or dynamic backend models) to synthesize context, establish confidence mappings, and attribute the MITRE ATT&CK framework IDs.
* **Phase 6: Autonomous SOAR** — Zero-latency playbook execution to actively **Block IPs**, **Isolate Hosts**, and **Kill Attacker Processes**.

### 2. Live Agent Telemetry
The core SIEM includes native Python scripts to run securely on endpoint machines (macOS currently supported out of the box), pushing real traffic logs into the SIEM's ingestion buffers.

* **Hybrid Mac Security Agent (`mac_agent.py`)**
Hooks directly into macOS native `log stream` and process registries (`ps aux`) to filter high-severity system events (SSH outbound, curl data theft, etc) and broadcast them securely.
* **Attack Simulator (`attack_sim.py`)** 
A localized penetration testing script that automatically fires sequence attacks (Brute Force → Root Shell → DB Exfiltration) to test SOAR playbooks iteratively.

### 3. Fully Persistent Database Architecture
Powered securely by **SQLite3**, maintaining absolute persistence over:
* System configurations and Firewall states.
* Complex History Tracking including distinct sub-views for Temporal graphs and Pipeline Breakdowns.
* Hard audit proofs on auto-remediated threats.

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/en) (v18+)
- Python 3+ (Pre-installed with standard libraries, no PIP required)

### Execution 

**1. Launch the SIEM Platform:**
```bash
# Install Node dependencies
npm install

# Start the full-stack SIEM infrastructure
npm run dev
```

> **Note:** The backend operates on `localhost:3000` executing SQLite alongside the bleeding-edge React + Vite frontend.

**2. Attach Live Telemetry Agents:**
Open a new background terminal to engage the live Mac endpoint telemetry. Ensure you have the Aegis directory open.
```bash
# Monitor the host kernel & network outbound connections live:
python3 mac_agent.py
```

**3. Run Security Drills (Attack Simulation):**
Watch Aegis trap inbound attacks LIVE across its dashboard. Run this in a third background process.
```bash
# Fires continuous simulated security threats:
python3 attack_sim.py
```

---

## 🖥️ Platform Navigation
1. **Dashboard:** Central security posture metrics and Neural Pipeline executor. Click `SCAN` to ingest buffers dynamically.
2. **Firewall:** Read-only & interactable global host isolation maps (Blocking/Unblocking IPs).
3. **History (Scan Results):** In-depth, node-level drill-downs to investigate past threats securely stored in the SQL Audit tables.
4. **Logs (Live Stream):** See all incoming system-events or Agent OS Logs flowing into the system buffers live before processing. Features one-click database log flushing.
5. **Settings:** Profile mapping and identity access views.

## 🛠 Tech Stack 
**Frontend**: React.js 19, TypeScript, TailwindCSS v4, Framer Motion, Vite  
**Backend**: Node.js, Express, SQLite3  
**Agents (End-Points)**: Python 3 Standard Library (urllib, subprocess, sockets) 

---
_Developed for next-generation active SOC automation._
