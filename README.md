# 🛡️ Aegis Autonomous SIEM

Aegis Autonomous SIEM is a next-generation security operations platform featuring an AI-driven threat detection pipeline, real-time agent logging, and a self-healing SOAR (Security Orchestration, Automation, and Response) engine. It provides unparalleled "Human-in-the-Loop" analytics alongside a stunning, minimalist Google Pixel / macOS-inspired dark UI.

## 🌟 Key Features

### 1. Neural Analysis Pipeline (Phases 1-7)
* **Phase 1: Ingestion Layer** — Centralized log collection from native OS endpoints.
* **Phase 2: Normalization** — Standardizing heterogeneous schemas across various environments.
* **Phase 3: Graph Engine** — Building behavioral node-edge models mapping entities over time.
* **Phase 4: Detection Engine** — Advanced heuristic correlation detecting IP-based brute forces, lateral movement, etc.
* **Phase 5: Intelligence Enrichment** — Secure backend proxying to **AbuseIPDB** and **VirusTotal** ensures real-time IP reputation and file/URL/IP hash validation without CORS limitations.
* **Phase 6: Multi-Stage AI Validation** — Translates the context using **Gemini** and passes findings into **Groq (Llama-3)** for high-precision confirmation before taking action.
* **Phase 7: Autonomous SOAR** — Zero-latency playbook execution to actively **Block IPs**, **Isolate Hosts**, and **Kill Attacker Processes**.

### 2. Live Agent Telemetry & SOC Intelligence
* **Overview AI Assistant** — A dedicated page where users can chat with **Aegis AI** (Gemini) about the system state, live detections, and audit logs.
* **Manual Intelligence Lookup** — Global header integrated IP Reputation tool powered by the backend AbuseIPDB proxy.
* **Hybrid Mac Security Agent (`mac_agent.py`)** — Hooks directly into macOS native `log stream` and process registries (`ps aux`) to filter high-severity system events.
* **Attack Simulator (`attack_sim.py`)** — A localized penetration testing script that automatically fires sequence attacks (Brute Force → Root Shell → DB Exfiltration) to test SOAR playbooks iteratively.

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
- Configure a `.env` file at the project root requiring:
  - `VITE_GEMINI_API_KEY` — Primary AI reasoning and Chat Assistant.
  - `VITE_ABUSEIPDB_API_KEY` — IP reputation services.
  - `VITE_VIRUSTOTAL_API_KEY` — Global file/URL intelligence.
  - `VITE_GROQ_API_KEY` — Final stage AI validation.

### Execution 

**1. Launch the SIEM Platform:**
```bash
# Install Node dependencies
npm install

# Start the full-stack SIEM infrastructure
npm run dev
```

> **Note:** The backend operates on `http://localhost:3000`. The server now includes a **Secure Proxy Layer** to prevent API keys from leaking to the browser and to bypass CORS restrictions for security APIs.

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
1. **Dashboard:** Central metrics, Terminal Pipeline, and interactive Relationship Graphs.
2. **Overview:** **Aegis AI Chat** — Chat with the platform about your live security data.
3. **Firewall:** Management of active host isolation and blocked IP lists.
4. **History:** Historical scan results and interactive timeline audit drill-downs.
5. **Logs:** Real-time stream of raw and normalized system events.

## 🛠 Tech Stack 
**Frontend**: React.js 19, TypeScript, TailwindCSS v4, Framer Motion, Vite  
**Backend**: Node.js, Express, SQLite3  
**Agents (End-Points)**: Python 3 Standard Library (urllib, subprocess, sockets) 

---
_Developed for next-generation active SOC automation._
