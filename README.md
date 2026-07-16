NetGuard — AI Network Traffic Analyzer & Active Defense Platform
NetGuard is a unified network security platform that combines packet sniffing, traffic visualization, intrusion detection, and AI‑powered traffic classification into a single active defense system with automated remediation.

Features
Layer	What happens
Capture	Scapy captures raw packets from your network interface
Detect	Rule‑based IDS checks for port scans, SYN floods, DDoS, brute force attacks
Classify	Random Forest ML model (96.8% accuracy on NSL‑KDD) classifies traffic: Normal / DoS / Probe / R2L / U2R
Remediate	Maps threat type to plain‑English fix steps
Block	Automatically fires iptables rules for HIGH severity threats
Report	Generates downloadable PDF incident reports
Architecture
NetGuard orchestrates five submodules (repositories you already own) via a FastAPI backend:

modules/sniffer – packet capture and analysis (from network-sniffer)

modules/visualizer – live traffic visualisation (from network-traffic-visualizer)

modules/detector – rule‑based intrusion detection (from intrusion-detection-prototype)

modules/classifier – AI classification server (from ai-network-traffic-classifier)

modules/model – trained model artifacts (from network-traffic-classifier-model)

The orchestrator (main.py) runs on port 8080 and the AI classifier runs as a separate service on port 8000.

Project Structure
text
netguard/
├── main.py                  # FastAPI orchestrator
├── requirements.txt
├── README.md
├── core/
│   ├── __init__.py
│   ├── remediation.py       # threat → fix steps engine
│   ├── blocker.py           # iptables block/unblock
│   └── reporter.py          # PDF incident report generator
├── dashboard/
│   └── index.html           # browser UI
├── data/                    # SQLite database (auto-created)
├── reports/                 # PDF reports (auto-created)
└── modules/
    ├── sniffer/             # submodule: network-sniffer
    ├── visualizer/          # submodule: network-traffic-visualizer
    ├── detector/            # submodule: intrusion-detection-prototype
    ├── classifier/          # submodule: ai-network-traffic-classifier
    └── model/               # submodule: network-traffic-classifier-model
Setup
1. Clone the repository and initialise submodules
bash
git clone https://github.com/GulrezQayyum/netguard
cd netguard
git submodule update --init --recursive
If you have not yet added the submodules, use the commands from the original README.

2. Create required directories
bash
mkdir -p data reports
3. Create and activate a Python virtual environment
bash
python3 -m venv .venv
source .venv/bin/activate
4. Install Python dependencies
bash
pip install -r requirements.txt
Key packages: fastapi, uvicorn, httpx, scapy, scikit-learn, joblib, pandas, reportlab, fpdf2.

Running the system
The system runs as two separate services – you need two terminal windows.

Terminal 1 — AI Classifier (port 8000)
bash
cd modules/classifier
source ../.venv/bin/activate          # if using the same venv
uvicorn backend.main:app --port 8000 --reload
Wait for ✅ Model loaded successfully!

Terminal 2 — NetGuard Orchestrator (port 8080)
bash
cd /path/to/netguard
sudo /path/to/netguard/.venv/bin/uvicorn main:app --port 8080 --reload
sudo is required for automatic IP blocking via iptables.

Open the dashboard
text
http://localhost:8080
API Endpoints
Method	Route	Description
GET	/	Dashboard UI
GET	/health	Health check + local IPs
POST	/analyze	Core pipeline: packet → IDS → AI → remediation → (block)
GET	/alerts	Recent alerts from SQLite
GET	/alerts/ip/{ip}	All alerts for a specific IP
POST	/block	Manually block an IP
DELETE	/block/{ip}	Unblock an IP
GET	/blocked	List all blocked IPs
GET	/report/{ip}	Download PDF incident report
GET	/stats	Summary stats for dashboard
GET	/visualizer/stats	Live bandwidth & protocol stats
GET	/docs	Swagger API documentation
Example Usage
Analyze a sample packet
bash
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
    }
  }'
The response will contain ids_alerts, ai_result, threat_type, remediation and (if severity is HIGH) block_result.

Generate a PDF report for an IP
bash
curl -v http://localhost:8080/report/10.0.0.99 --output report.pdf
Threat Responses
Threat Type	Severity	Auto Action
port_scan	MEDIUM	Log only
ddos	HIGH	Auto‑block + log
brute_force	HIGH	Auto‑block + log
malicious_traffic	HIGH	Auto‑block + log
unusual_traffic	LOW	Log only
Troubleshooting & Known Issues
During development and testing, we encountered and resolved several issues. Here is a summary for future reference.

1. Submodules not initialised
Error: Folders inside modules/ are empty.

Fix: Run git submodule update --init --recursive.

2. Missing Python packages (httpx, reportlab, etc.)
Error: ModuleNotFoundError: No module named 'httpx' (or reportlab).

Fix: Install them in your virtual environment:

bash
pip install httpx reportlab
Also ensure you run the main server with the full path to the venv’s uvicorn to avoid system‑wide Python:

bash
sudo /path/to/venv/bin/uvicorn main:app --port 8080 --reload
3. API key error from classifier
Error: {"detail":"Invalid or missing API key"} when calling /predict.

Fix: Either set API_KEY in modules/classifier/config.py (or .env) to match the header sent by the orchestrator, or disable the authentication check by commenting out the verify_api_key dependency and the Depends in the /predict route.
We chose to bypass it for local testing.

4. Classifier returns 404 because the orchestrator called itself
Error: In the orchestrator logs:

text
INFO:httpx:HTTP Request: POST http://localhost:8080/predict "HTTP/1.1 404 Not Found"
This means main.py was sending the request to port 8080 (itself) instead of port 8000 (the classifier).

Fix: In main.py, inside the call_classifier function, change:

python
resp = await client.post(
    "http://localhost:8080/predict", ...
)
to:

python
resp = await client.post(
    "http://localhost:8000/predict", ...
)
5. Scikit‑learn version warnings on classifier startup
Warning: InconsistentVersionWarning: Trying to unpickle estimator from version 1.8.0 when using version 1.9.0

Effect: The model still loads and works; these warnings can be safely ignored.

6. PDF report fails with 404 Not Found
Cause: The report endpoint requires an existing alert for the requested IP. If no analysis has been performed for that IP, or the analysis did not persist an alert (e.g., if the AI call failed), the report cannot be generated.

Fix: First run /analyze with that IP to ensure an alert is created. Verify that ai_result is not null in the response.

7. ai_result stays null even after classifier call succeeds
Possible reasons:

The classifier response is not in the expected format (e.g., missing prediction key).

An exception occurs while parsing the response (e.g., JSON decode error, network timeout, etc.).

Debug: Add print(resp.text) inside the call_classifier function to inspect the raw response. We fixed this by ensuring the payload sent to the classifier matches the 40‑feature schema required by the model.

Lessons Learned
Always check the port when integrating microservices.

Use virtual environments and run with sudo using the full binary path to avoid system‑wide package conflicts.

Submodules require explicit initialisation; include this step in your setup guide.

API authentication can be bypassed for internal testing, but remember to secure it for production.

Test each component separately before integrating – it saves hours of debugging.

Built With
FastAPI – async REST API

Scapy – packet capture

scikit‑learn – Random Forest classifier (96.8% accuracy on NSL‑KDD)

SQLite – alert persistence

fpdf2 – PDF report generation

iptables – IP blocking on Linux

Chart.js – dashboard visualisations

License
This project is submitted as part of a university/portfolio assignment. All submodules are the property of their respective authors.

