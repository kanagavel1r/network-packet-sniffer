## Network Packet Sniffer & Intrusion Analyzer

A lightweight, Python-based command-line **Network Packet Sniffer and Intrusion Detection System (IDS)** built with **Scapy**. It captures live IPv4 network traffic (TCP and UDP), inspects packet headers and TCP control flags in real time, and detects potential **SYN Port Scan reconnaissance attacks** using a sliding time-window algorithm. 

## Key Features

* **Real-Time Packet Inspection:** Captures and parses source/destination IPv4 addresses, port numbers, and TCP control flags (SYN, ACK, SYN-ACK, PSH-ACK).
* **Sliding-Window Port Scan Detection:** Tracks unique destination ports probed per source IP within a configurable time window (default: **10+ unique ports within 5 seconds**).
* **Automated Incident Logging:** Displays instant console warnings and appends timestamped security alerts to security_alerts.log for audit trails.
* **Memory-Safe Live Capture:** Uses non-storing packet callbacks (store=False) to prevent RAM exhaustion during continuous network monitoring.

## How It Works

1. **Packet Capture:** Uses Scapy's sniff() engine (backed by Npcap on Windows or libpcap on Linux) to intercept raw network frames at Layer 2/3.
2. **Header Parsing:** Extracts IP, TCP, and UDP protocol layers to identify communication endpoints and TCP handshake states.
3. **Anomaly Detection:** Monitors incoming TCP SYN (Flags: S) connection requests. When a single source IP probes multiple distinct ports rapidly, the sliding-window tracker flags the activity as reconnaissance and logs the incident.

## Project Structure

<img width="728" height="177" alt="image" src="https://github.com/user-attachments/assets/0abd4f59-92c6-4759-920a-a5b39480ca87" />


## Installation & Usage

#### 1. Prerequisites

* **Python 3.11+**
* **Windows Users:** Install [Npcap](https://npcap.com/#download) with *"Install Npcap in WinPcap API-compatible Mode"* enabled.
* **Linux/macOS Users:** Ensure libpcap is installed (sudo apt install libpcap-dev).

#### 2. Setup

#### bash

#### Clone the repository
```
git clone https://github.com/kanagavel1r/network-packet-sniffer.git
cd network-packet-sniffer
```
#### Create and activate a virtual environment
```
python -m venv venv
```
#### Windows:
```
venv\Scripts\activate
```
#### Linux/macOS:

```
source venv/bin/activate
```

#### Install dependencies

```
pip install -r requirements.txt
```

#### 3. Run the Sniffer

Administrator or root privileges are required to access network interfaces: 

#### bash

#### Windows (Run PowerShell/CMD as Administrator):

```
python sniffer.py
```

#### Linux/macOS:

```
sudo ./venv/bin/python sniffer.py

```

## Sample Output

  <img width="690" height="453" alt="image" src="https://github.com/user-attachments/assets/af1b0b65-a296-42fe-b70d-1e880b3433d0" />

## Live Traffic Capture & Alert Trigger

#### text
```

Starting Network Packet Sniffer & Traffic Analyzer...
Press Ctrl+C to stop.

[TCP] 10.240.95.74:63053 -> 74.151.238.136:443 | Flags: S
[TCP] 74.151.238.136:443 -> 10.240.95.74:63053 | Flags: SA
[TCP] 10.240.95.74:63053 -> 74.151.238.136:443 | Flags: A
[UDP] 10.240.95.74:59618 -> 10.240.95.107:53

[2026-11-20 09:09:12] [ALERT] Potential Port Scan detected from 10.240.95.74! Probed 10 ports in 5s.

```

## Future Improvements

* [ ] Add detection rules for **ARP Spoofing** and **ICMP Ping Floods**.
* [ ] Export captured packet summaries to .pcap format for deeper analysis in **Wireshark**.
* [ ] Add CLI arguments (argparse) to customize port thresholds, time windows, and network interfaces.

## Disclaimer

This tool was developed strictly for educational purposes, network diagnostics, and authorized security testing. Do not run packet sniffers or port scanners on networks without explicit permission.
