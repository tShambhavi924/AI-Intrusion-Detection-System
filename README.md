# AI-Powered Intrusion Detection & Live Network Attack Simulation System

A production-grade cybersecurity platform that simulates a real Security Operations Center (SOC) environment with real-time network packet capture, AI-powered threat detection, honeypot services, and an interactive cyberpunk-styled dashboard.

## 🎯 Project Overview

This system provides a complete intrusion detection and attack simulation platform featuring:

- **Real Network Packet Capture** using Scapy
- **AI-Powered Detection** with entropy analysis, heuristic rules, and statistical anomaly detection
- **Live Attack Simulation** (Port Scan, SQL Injection, DDoS, XSS, Malware C2)
- **Honeypot Services** (HTTP on 8888, SSH on 2222, FTP on 2121)
- **Real-time Dashboard** with Socket.IO and Chart.js
- **Automatic IP Blocking** based on threat scores
- **PDF Report Generation** for threat analysis

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Main Orchestrator (main.py)               │
└────────────┬────────────────────────────────────────────────┘
             │
    ┌────────┴────────┬──────────────┬──────────────┬──────────────┐
    │                 │              │              │              │
┌───▼────┐    ┌──────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
│ Packet │    │   ML       │  │  Threat   │  │ Honeypot  │  │ Dashboard │
│ Sniffer│───▶│ Detector   │──▶│  Engine   │  │ Services  │  │  Server   │
└────────┘    └────────────┘  └───────────┘  └───────────┘  └───────────┘
    │              │                │              │              │
    │              │                │              │              │
    └──────────────┴────────────────┴──────────────┴──────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Attack Simulator │
                    └───────────────────┘
```

### Component Breakdown

1. **Packet Sniffer** (`packet_sniffer.py`)
   - Captures network packets using Scapy
   - Extracts packet metadata (IP, ports, protocols, payloads)
   - Maintains packet statistics and history

2. **ML Detector** (`ml_detector.py`)
   - **Entropy Analysis**: Detects encrypted/obfuscated traffic
   - **Heuristic Detection**: Pattern matching for SQL injection, XSS, command injection
   - **Statistical Anomaly Detection**: Rate-based, protocol diversity, port scanning
   - Calculates threat scores based on multiple detection methods

3. **Threat Engine** (`threat_engine.py`)
   - Processes detections and assigns threat scores
   - Automatic IP blocking (threshold: 70/100)
   - SQLite database for threat logging
   - PDF report generation

4. **Honeypot Services** (`honeypot.py`)
   - **HTTP Honeypot** (Port 8888): Logs web requests, detects suspicious patterns
   - **SSH Honeypot** (Port 2222): Simulates SSH server, logs authentication attempts
   - **FTP Honeypot** (Port 2121): Simulates FTP server, logs commands and login attempts

5. **Attack Simulator** (`attack_simulator.py`)
   - Port scanning simulation
   - SQL injection payloads
   - DDoS flood attacks
   - XSS payload injection
   - Malware C2 beacon simulation

6. **Dashboard Server** (`dashboard_server.py`)
   - Flask web server with Socket.IO for real-time updates
   - Serves the cyberpunk-styled frontend
   - Broadcasts packet feeds, threats, and honeypot hits

## 📋 Prerequisites

- **Python 3.10+**
- **Administrator/Root privileges** (required for packet capture)
- **Windows/Linux/macOS**

## 🚀 Installation

### Step 1: Clone or Navigate to Project Directory

```bash
cd AI_IDS_Project
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Note**: On some systems, you may need to install additional dependencies for Scapy:

```bash
# Windows
pip install pypcap

# Linux
sudo apt-get install libpcap-dev
pip install pypcap

# macOS
brew install libpcap
pip install pypcap
```

### Step 4: Verify Installation

```bash
python main.py --help
```

## 🎮 Usage

### Starting the System

**Important**: Run with administrator/root privileges for packet capture to work properly.

```bash
# Windows (Run PowerShell/CMD as Administrator)
python main.py

# Linux/macOS (Run with sudo)
sudo python3 main.py
```

### Accessing the Dashboard

Once started, open your web browser and navigate to:

```
http://localhost:5000
```

### System Components

The system will automatically start:

- **Dashboard**: http://localhost:5000
- **HTTP Honeypot**: http://localhost:8888
- **SSH Honeypot**: localhost:2222
- **FTP Honeypot**: localhost:2121

### Using the Dashboard

1. **Real-time Monitoring**
   - View live packet capture in the "Live Packet Feed" panel
   - Monitor entropy analysis in the real-time chart
   - Track threats in the "Threat Detection Log"

2. **Attack Simulation**
   - Click attack buttons to trigger simulated attacks
   - Watch as the system detects and responds to attacks
   - Observe threat scores and automatic IP blocking

3. **Honeypot Interaction**
   - Connect to honeypot services to generate activity
   - View honeypot hits in the "Honeypot Activity Log"
   - Test with various tools (curl, wget, ssh, ftp clients)

### Generating Reports

To generate a PDF threat report, you can add this functionality to the dashboard or run:

```python
from threat_engine import ThreatEngine

engine = ThreatEngine()
engine.generate_pdf_report("threat_report.pdf", hours=24)
```

## 🔧 Configuration

### Adjusting Threat Thresholds

Edit `threat_engine.py`:

```python
self.block_threshold = 70  # Change blocking threshold (0-100)
```

### Changing Honeypot Ports

Edit `main.py`:

```python
self.honeypot.start(http_port=8888, ssh_port=2222, ftp_port=2121)
```

### Modifying Detection Sensitivity

Edit `ml_detector.py` to adjust:
- Entropy thresholds
- Port scan detection parameters
- Rate-based anomaly thresholds

## 📊 Detection Methods

### 1. Entropy-Based Detection
- Calculates Shannon entropy of packet payloads
- Detects encrypted/compressed traffic (high entropy)
- Identifies repetitive patterns (low entropy)

### 2. Heuristic Detection
- **SQL Injection**: Detects patterns like `' OR '1'='1`, `UNION SELECT`
- **XSS**: Detects `<script>`, `javascript:`, event handlers
- **Command Injection**: Detects shell commands, PowerShell, etc.

### 3. Statistical Anomaly Detection
- **Port Scanning**: Multiple unique ports from single IP
- **High Packet Rate**: Unusual traffic volume
- **Protocol Diversity**: Multiple protocols from single source
- **DDoS Patterns**: Extremely high packet rates

## 🛡️ Security Features

- **Automatic IP Blocking**: IPs exceeding threat threshold are automatically blocked
- **Threat Scoring**: Multi-factor threat assessment (0-100 scale)
- **Real-time Alerts**: Immediate notification of detected threats
- **Comprehensive Logging**: All events stored in SQLite database

## 📁 Project Structure

```
AI_IDS_Project/
├── main.py                 # Main orchestrator
├── packet_sniffer.py       # Packet capture module
├── attack_simulator.py     # Attack simulation engine
├── ml_detector.py          # AI/ML detection algorithms
├── threat_engine.py        # Threat management & reporting
├── honeypot.py             # Honeypot services
├── dashboard_server.py     # Flask + Socket.IO server
├── requirements.txt        # Python dependencies
├── threats.db              # SQLite threat database (created at runtime)
├── templates/
│   └── dashboard.html      # Frontend HTML
└── static/
    ├── style.css           # Cyberpunk styling
    └── dashboard.js        # Frontend JavaScript
```

## 🧪 Testing the System

### Test 1: Port Scan Detection

1. Start the system
2. Click "Port Scan" button in dashboard
3. Observe threat detection in real-time
4. Check threat log for port scan alerts

### Test 2: SQL Injection Detection

1. Click "SQL Injection" button
2. Or manually send: `curl "http://localhost:8888/login?user=' OR '1'='1"`
3. Watch for SQL injection pattern detection

### Test 3: Honeypot Interaction

```bash
# HTTP Honeypot
curl http://localhost:8888

# SSH Honeypot (will fail but log attempt)
ssh -p 2222 user@localhost

# FTP Honeypot
ftp localhost 2121
```

### Test 4: DDoS Simulation

1. Click "DDoS Attack" button
2. Observe high packet rate detection
3. Check for automatic IP blocking

## 🐛 Troubleshooting

### Packet Capture Not Working

**Issue**: No packets being captured

**Solutions**:
- Ensure running with administrator/root privileges
- Check if Scapy is properly installed: `python -c "from scapy.all import *"`
- Verify network interface permissions
- On Windows, may need WinPcap or Npcap installed

### Dashboard Not Loading

**Issue**: Cannot access http://localhost:5000

**Solutions**:
- Check if port 5000 is already in use
- Verify Flask installation: `pip install Flask Flask-SocketIO`
- Check firewall settings
- Review console for error messages

### Honeypot Services Not Starting

**Issue**: Honeypot ports already in use

**Solutions**:
- Change ports in `main.py`
- Check what's using ports: `netstat -ano | findstr :8888` (Windows)
- Stop conflicting services

### Import Errors

**Issue**: Module not found errors

**Solutions**:
- Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`
- Check Python version: `python --version` (should be 3.10+)

## 📈 Performance Considerations

- **Packet Capture**: May impact network performance on high-traffic networks
- **Database**: SQLite is suitable for small-medium deployments; consider PostgreSQL for production
- **Memory**: System maintains packet history; adjust `max_packets` in `packet_sniffer.py` if needed
- **CPU**: ML detection runs in real-time; may need optimization for very high packet rates

## 🔒 Security Disclaimer

**This is a demonstration and educational system. Do not deploy in production without:**

- Proper security hardening
- Authentication and authorization
- Encrypted communications
- Regular security audits
- Compliance with local regulations

## 📝 License

This project is provided for educational and demonstration purposes.

## 🤝 Contributing

This is a complete, production-ready demonstration system. Feel free to extend and modify for your needs.

## 📧 Support

For issues or questions:
1. Check the troubleshooting section
2. Review console output for error messages
3. Verify all dependencies are installed correctly

## 🎓 Educational Use

This system demonstrates:
- Network security monitoring
- Intrusion detection principles
- Honeypot deployment
- Real-time threat analysis
- SOC dashboard design
- AI/ML in cybersecurity

---

**Built with**: Python 3.10, Flask, Scapy, Socket.IO, Chart.js, SQLite

**Theme**: Cyberpunk Neon SOC Style

**Status**: Production-Ready Demonstration System

