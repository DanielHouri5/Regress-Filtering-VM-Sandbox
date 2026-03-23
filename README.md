# Regress Filtering VM Sandbox

A lightweight malware analysis sandbox that runs suspicious Python files inside an isolated VM, monitors behavior, and generates security reports.

## Dependencies

- Python 3.7+
- VM with SSH access

### Python packages

scapy==2.5.0
requests==2.31.0
colorama==0.4.6
paramiko==2.12.0

## 🚀 How to Run

### 1. VM Preparation (One-Time Setup)

- Install and enable SSH:
```bash
sudo apt update
sudo apt install openssh-server -y
sudo systemctl enable --now ssh
```

- Set network:
  - Adapter → **Host-Only Adapter** (VirtualBox)

### 2. Sandbox Initialization (Inside VM)
```bash
sudo ip route add default via <'your HOST IP'>
sudo bash -c 'while true; do ss -tupn >> /tmp/network_log.txt; sleep 1; done' &
```

### 3. go to 'config.py' and set the values according to your VM details.

### 4. Install dependencies (On Host Machine):
```bash
pip install -r requirements.txt
```

### 5. Execution (On Host Machine)
```bash
python -m src.main --sample shared/samples/safe_test.py
```

## What happens?
Upload sample to VM
Execute for ~120 seconds
Monitor network activity
Generate report
Cleanup resources