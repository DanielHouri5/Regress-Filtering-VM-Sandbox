# 🛡️ Regress-Filtering-Sandbox

A high-performance, Docker-based **Malware Analysis Sandbox** designed for dynamic file execution in an isolated environment. The system features real-time network sniffing, automated threat intelligence correlation, and active bidirectional traffic interception.

---

## 📋 System Overview

The Regress-Filtering-Sandbox provides a secure environment to execute and monitor suspicious Python scripts. By leveraging **Docker-out-of-Docker (DooD)** technology, it spawns isolated runtime containers, monitors their network stack, and cross-references all traffic with live **Threat Intelligence** feeds.

If a connection to a known malicious Command & Control (C2) server is detected, the system immediately drops the connection at the kernel level using `iptables`.

## 🔄 Data Flow & Architecture

1.  **Initialization:** The Controller pulls the latest malicious IP indicators (IOCs) from the **ThreatFox API**.
2.  **Environment Isolation:** A dedicated "Target Container" is created with a shared network namespace to the monitor.
3.  **Active Monitoring:** The Network Monitor utilizes **Scapy** for real-time packet inspection on the `eth0` interface.
4.  **Detection & Response:**
    - Outgoing packets are inspected for malicious destination IPs.
    - **Automated Mitigation:** Upon detection, the system injects `iptables` rules into the Target Container to block both `INPUT` and `OUTPUT` traffic for that IP.
5.  **Final Verdict:** After execution, the engine analyzes total packet count, block frequency, and threat severity to provide a final security **Verdict** (CLEAN, SUSPICIOUS, or MALICIOUS).

---

## 🛠️ System Requirements

- **Docker Desktop:** Installed and running.
- **Linux-based Shell:** Git Bash (Windows), WSL2, or native Linux.
- **Internet Access:** Required for real-time Threat Intelligence updates.

---

## 🚀 Getting Started

### 1. Build the Images

Run the following commands from the project root:

Build the Management Controller

```bash
# Build the Management Controller
docker build -t sandbox-controller .
# Build the Isolated Runtime Environment
docker build -f Dockerfile.runtime -t sandbox-runtime .
```

### 2. Execute a Sample Analysis

Use this generic command to run any Python sample. It automatically maps your local paths and initiates the monitoring sequence:

```bash
MSYS_NO_PATHCONV=1 docker run -it --privileged   -v //var/run/docker.sock:/var/run/docker.sock   -v "$(pwd)/shared:/sandbox/shared"   -e HOST_SHARED_PATH="$(pwd)/shared"   sandbox-controller --sample shared/samples/test_connection.py
```

📊 Analysis Outputs

Live Console: A color-coded table displaying real-time traffic status (ALLOWED, UNAUTHORIZED, or BLOCKED).

Traffic Logs: Detailed forensic logs are saved to shared/reports/traffic_log_DD-MM-YYYY.txt.

Security Verdict: A comprehensive final summary including risk assessment and recommendations.
