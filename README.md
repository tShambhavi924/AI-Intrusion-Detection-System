

# 🚀 **AI-Powered Intrusion Detection & Network Attack Simulation System**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)]()
[![Flask](https://img.shields.io/badge/Flask-Backend-lightgrey.svg)]()
[![Socket.IO](https://img.shields.io/badge/Socket.IO-RealTime-black)]()
[![Scapy](https://img.shields.io/badge/Scapy-PacketCapture-yellow)]()
[![SQLite](https://img.shields.io/badge/Database-SQLite-green)]()
[![License](https://img.shields.io/badge/License-Educational-red)]()

A real-time cybersecurity monitoring platform simulating a modern **Security Operations Center (SOC)** environment.
Includes live packet capture, AI-driven anomaly detection, honeypot services, attack simulation, and a cyberpunk-themed SOC dashboard.

---

## 📌 **Features**

| Capability               | Description                                                       |
| ------------------------ | ----------------------------------------------------------------- |
| Real-time Packet Capture | Captures TCP/UDP/ICMP traffic using Scapy                         |
| AI Threat Detection      | Entropy scoring, heuristic rules & statistical anomaly analysis   |
| Attack Simulator         | Port scan, SQL injection, DDoS flood, Malware C2                  |
| Honeypot Services        | HTTP (8888), SSH (2222), FTP (2121) with detailed session logging |
| SOC Dashboard            | Live logs, entropy graph, threat cards, honeypot activity         |
| Auto Response            | Threat scoring and automatic IP blocking                          |
| Local Storage            | SQLite database persistence and PDF report export                 |

---

## 🏗 **Architecture Overview**

```
                         ┌───────────────────────────────┐
                         │          main.py               │
                         └───────────────┬───────────────┘
                                         │
       ┌───────────────────────┬─────────┼───────────┬────────────────────●
       │                       │         │           │
 Packet Sniffer         ML Detector    Threat Engine    Honeypots     Dashboard
scapy network capture   entropy + AI   scoring + DB     HTTP/SSH/FTP   Flask + Socket.IO
```

---



## ⚙️ **Installation**

### **1. Clone Repository**

```bash
git clone https://github.com/<username>/AI-Intrusion-Detection-System.git
cd AI-Intrusion-Detection-System
```

### **2. Create Virtual Environment**

```bash
python -m venv venv
source venv/bin/activate       # macOS/Linux
venv\Scripts\activate          # Windows
```

### **3. Install Dependencies**

```bash
pip install -r requirements.txt
```

---

## ▶ **Run the System**

### Start platform (run as admin/root)

```bash
python main.py
```

### Access SOC Dashboard

```
http://localhost:5000
```

### Honeypots For Testing

| Service | Port | Test Command                                        |
| ------- | ---- | --------------------------------------------------- |
| HTTP    | 8888 | curl [http://localhost:8888](http://localhost:8888) |
| SSH     | 2222 | ssh -p 2222 user@localhost                          |
| FTP     | 2121 | ftp localhost 2121                                  |

---

## 🧪 **Demo & Testing Flow**

### Generate Live Packets

```bash
ping 127.0.0.1 -t
```

### Trigger Cyber Attacks via Dashboard

* Port Scan
* SQL Injection
* DDoS Flood
* Malware C2

### Expected Demo Results

| Action            | Dashboard Output                        |
| ----------------- | --------------------------------------- |
| Simulate attack   | Threat item added with severity & score |
| Curl/SSH/FTP      | Honeypot hit logged                     |
| High threat score | IP appears in blocked list              |
| Traffic increases | Entropy graph reacts                    |

---

## 📂 **Project Structure**

```
AI_IDS_Project/
│── main.py
│── packet_sniffer.py
│── ml_detector.py
│── threat_engine.py
│── attack_simulator.py
│── honeypot.py
│── dashboard_server.py
│── requirements.txt
│── README.md
├── templates/   # Dashboard HTML
├── static/      # CSS/JS
├── data/        # Local DB + reports
└── venv/
```

---

## 🎓 **Academic / Research Value**

* Demonstrates real SOC workflow concepts
* Practical IDS & anomaly detection implementation
* Network forensics learning via honeypots
* Attacker behavior emulation
* AI-supported threat modeling

---

## 📌 **Future Enhancements**

* Integrate ElasticSearch + Kibana SIEM stack
* Add supervised ML classification
* Deploy distributed sensors
* User authentication for SOC access

