# Network Packet Analyzer with Anomaly Detection

## 📌 Overview
This project is a real-time network packet analyzer built using **Python and Scapy**.
It automatically detects the local host IP at runtime, making the tool portable
and usable across different systems without hardcoded configuration.
  
It captures live network traffic and detects **network anomalies** such as:

- 🔍 **Port scanning attacks** (using a sliding time window)
- 🛑 **ARP spoofing attacks** (using IP-to-MAC consistency)

The project focuses on **behavior-based detection**, similar to how basic **Intrusion Detection Systems (IDS)** work.

---

## 🚀 Features
- Live packet capture on Linux (tested on Kali Linux)
- Port scan detection using:
  - Unique destination ports
  - **Sliding time window** (reduces false positives)
- ARP spoof detection by tracking IP → MAC changes
- Noise reduction by detecting **state changes**, not raw packets
- Handles common false positives (ephemeral ports, ARP probes)
- Direction-aware detection (identifies the external scanner, not the local host)
---

## 🧠 Detection Logic

## ⚙️ Configuration

- The analyzer **automatically detects the local machine’s IP address**
  using a socket-based method.
- No hardcoded IP addresses are used in the code.
- This makes the tool portable and reusable across different networks
  and systems without manual changes.

### 🔹 Port Scan Detection
- Detects **inbound TCP SYN packets** targeting the local host
- Tracks destination ports probed by a single external source IP
- Uses a **10-second sliding time window**
- Raises an alert if **5 or more unique ports** are probed within the window
- Filters out outbound traffic and ephemeral ports to reduce false positives

**Why time window?**  
Port scans happen quickly, while normal browsing is spread over time.

---

### 🔹 ARP Spoof Detection
- Monitors ARP packets on the local network
- Stores the first observed MAC address for each IP
- Raises an alert if the same IP claims a **different MAC address**
- Ignores ARP probes (`0.0.0.0`) to reduce false alerts

---

## 🛠️ Technologies Used
- **Python 3**
- **Scapy**
- Linux Networking (TCP/IP, ARP)

---

## 📦 Requirements
- Python 3.x
- Scapy
- Linux OS (packet sniffing requires root privileges)

Install dependencies:
```bash
pip install scapy

