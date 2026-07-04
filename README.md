# NetGuard — AI Network Traffic Analyzer & Active Defense Platform

A unified network security platform that combines packet sniffing, traffic visualization, intrusion detection, and AI-powered traffic classification into a single active defense system with automated remediation.

## What it does

| Layer | What happens |
|---|---|
| Capture | Scapy captures raw packets from your network interface |
| Detect | Rule-based IDS checks for port scans, SYN floods, DDoS, brute force |
| Classify | Random Forest ML model classifies traffic: Normal / DoS / Probe / R2L / U2R |
| Remediate | Maps threat type to plain-English fix steps |
| Block | Fires iptables rule automatically for HIGH severity threats |
| Report | Generates downloadable PDF incident report |

## Project structure

```
netguard/
├── main.py                  ← FastAPI orchestrator (THE new brain)
├── requirements.txt
├── README.md
├── core/
│   ├── __init__.py
│   ├── remediation.py       ← threat → fix steps engine
│   ├── blocker.py           ← iptables block/unblock
│   └── reporter.py          ← PDF incident report generator
├── dashboard/
│   └── index.html           ← browser UI
├── data/                    ← SQLite database (auto-created)
├── reports/                 ← PDF reports (auto-created)
└── modules/
    ├── sniffer/             ← git submodule: network-sniffer
    ├── visualizer/          ← git submodule: network-traffic-visualizer
    ├── detector/            ← git submodule: intrusion-detection-prototype
    ├── classifier/          ← git submodule: ai-network-traffic-classifier
    └── model/               ← git submodule: network-traffic-classifier-model
```

## Setup

### 1. Clone NetGuard
```bash
git clone https://github.com/GulrezQayyum/netguard
cd netguard
```

### 2. Link your 4 existing repos as submodules
```bash
git submodule add https://github.com/GulrezQayyum/network-sniffer              modules/sniffer
git submodule add https://github.com/GulrezQayyum/network-traffic-visualizer    modules/visualizer
git submodule add https://github.com/GulrezQayyum/intrusion-detection-prototype modules/detector
git submodule add https://github.com/GulrezQayyum/ai-network-traffic-classifier modules/classifier
git submodule add https://github.com/GulrezQayyum/network-traffic-classifier-model modules/model

touch modules/__init__.py
mkdir -p data reports
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run

**Terminal 1** — AI Classifier (port 8000):
```bash
cd modules/classifier
uvicorn backend.main:app --port 8000 --reload
```

**Terminal 2** — NetGuard (port 8080):
```bash
cd /path/to/netguard
sudo uvicorn main:app --port 8080 --reload
# sudo needed for iptables auto-blocking
```

**Open dashboard:**
```
http://localhost:8080
```

## API Routes

| Method | Route | Description |
|---|---|---|
| GET | `/` | Dashboard UI |
| GET | `/health` | Health check + local IPs |
| POST | `/analyze` | Core pipeline: packet → IDS → AI → remediation → (block) |
| GET | `/alerts` | Recent alerts from SQLite |
| GET | `/alerts/ip/{ip}` | All alerts for a specific IP |
| POST | `/block` | Manually block an IP |
| DELETE | `/block/{ip}` | Unblock an IP |
| GET | `/blocked` | List all blocked IPs |
| GET | `/report/{ip}` | Download PDF incident report |
| GET | `/stats` | Summary stats for dashboard |
| GET | `/visualizer/stats` | Live bandwidth and protocol stats |
| GET | `/docs` | Swagger API documentation |

## Example: analyze a packet

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "packet": {
      "src_ip": "10.0.0.99",
      "dst_ip": "192.168.1.1",
      "protocol": "TCP",
      "flags": "S",
      "src_port": 12345,
      "dst_port": 22,
      "length": 60
    },
    "features": {}
  }'
```

## Threat types and responses

| Threat | Severity | Auto action |
|---|---|---|
| `port_scan` | MEDIUM | Log only |
| `ddos` | HIGH | Auto-block + log |
| `brute_force` | HIGH | Auto-block + log |
| `malicious_traffic` | HIGH | Auto-block + log |
| `unusual_traffic` | LOW | Log only |

## Built with

- **FastAPI** — async REST API
- **Scapy** — packet capture
- **scikit-learn** — Random Forest classifier (96.8% accuracy on NSL-KDD)
- **SQLite** — alert persistence
- **fpdf2** — PDF report generation
- **iptables** — IP blocking on Linux
- **Chart.js** — dashboard visualizations