## NetGuard — AI Network Traffic Analyzer & Active Defense Platform

NetGuard is a unified network security platform that combines packet sniffing, traffic visualization, intrusion detection, and AI‑powered traffic classification into a single active defense system with automated remediation. 

> ⚠️ STATUS: WORK IN PROGRESS  
> The core architecture is in place, but some critical components are not fully functional (see Known Issues). This project is a collaborative effort – your expertise is needed to get it across the finish line! 

---

## Demo


[Watch full demo (MP4) →](assets/netGuard.mp4)

---

### Vision & Pipeline

NetGuard is designed as a layered pipeline from raw packet capture to active defense:

| Layer      | Goal                                                              | Current Status                         |
|-----------|-------------------------------------------------------------------|----------------------------------------|
| Capture   | Scapy captures raw packets from your network interface            | ✅ Works (sniffer submodule integrated) |
| Detect    | Rule‑based IDS checks for port scans, SYN floods, DDoS, brute force | ✅ Works (detector submodule integrated) |
| Classify  | Random Forest ML model (96.8% accuracy) classifies traffic as Normal / DoS / Probe / R2L / U2R | ⚠️ Partially integrated – AI server runs but orchestrator fails to parse responses |
| Remediate | Maps threat type to plain‑English fix steps                       | ✅ Works (`core/remediation.py`)        |
| Block     | Automatically fires iptables rules for HIGH‑severity threats      | ✅ Works (`core/blocker.py`)            |
| Report    | Generates downloadable PDF incident reports                       | ❌ Fails with 404 – alert data not persisting correctly |

---

### Project Structure

```text
netguard/
├── main.py                  # FastAPI orchestrator (BUGGY)
├── requirements.txt
├── README.md
├── core/
│   ├── remediation.py       # ✅ Works
│   ├── blocker.py           # ✅ Works
│   └── reporter.py          # ❌ Needs debugging (PDF generation)
├── dashboard/
│   └── index.html           # ✅ Serves UI
├── data/                    # SQLite database (auto-created) – not populating?
├── reports/                 # PDF reports (auto-created) – empty?
└── modules/
    ├── sniffer/             # ✅ Integrated
    ├── visualizer/          # ✅ Integrated
    ├── detector/            # ✅ Integrated
    └── classifier/          # ⚠️ AI server runs, but payload/response mismatch
        └── model/
            └── saved_models/ # ✅ Model loads with warnings (scikit-learn version mismatch)
```

---

### What Works

- All four submodules are cloned and initialised correctly.  
- Classifier service starts, loads the model, and serves `/predict` on port 8000.  
- Orchestrator (`main.py`) runs and serves the dashboard UI on port 8080.  
- IDS rules trigger correctly (e.g., SYN flag detection).  
- `block_ip()` and `unblock_ip()` work with `iptables`.  
- Remediation mapping returns a fix for each threat type.  
- `/analyze` endpoint responds and returns a JSON structure.

---

### What’s Broken (Help Needed)

1. **`ai_result` is always `null`**

   Even though the orchestrator successfully calls the classifier (logs show `200 OK`), the `ai_result` field in the `/analyze` response stays `null`. The orchestrator cannot parse the classifier’s JSON response.  
   - Suspect: The payload sent to the classifier does not match the 40‑feature schema expected by the model, or the classifier returns an error that is swallowed.  
   - Need: Debug the `call_classifier()` function in `main.py` and compare the payload against the model’s expected features (defined in `modules/classifier/backend/main.py` and `model/metadata.json`).

2. **PDF report returns `404 Not Found`**

   The `/report/{ip}` endpoint fails because it cannot find an alert for the given IP in the SQLite database. This suggests alerts are not being persisted, possibly because the AI step fails (so no alert is logged).  
   - Need: Fix the alert logging logic – either ensure alerts are saved even when AI fails, or fix the AI integration first.

3. **Classifier authentication still blocks requests**

   The classifier’s `/predict` endpoint originally required an `X-API-Key` header. This was bypassed by commenting out the `verify_api_key` dependency, but remnants may still cause occasional `403` errors.  
   - Need: Cleanly disable the API key check for local testing, or configure a matching key in both services.

4. **Scikit‑learn version warnings**

   You may see warnings like:  
   `InconsistentVersionWarning: Trying to unpickle estimator from version 1.8.0 when using version 1.9.0`  
   - Effect: The model still loads, but this could cause subtle issues.  
   - Need: Retrain or re‑save the model with the newer scikit‑learn version, or pin the version in `requirements.txt`.

5. **Main server must be run with `sudo`**

   The orchestrator needs `sudo` for `iptables`, which often forces the system Python instead of the venv Python. The current workaround uses the full venv binary path, which is confusing for new contributors.  
   - Need: Document the exact command clearly, or find a way to avoid `sudo` (e.g., call `iptables` via `sudo` only in the blocker, or adopt a non‑root alternative).

---

### How You Can Help (Collaboration)

I am actively looking for developers to collaborate on fixing the remaining bugs. If you have experience with:  

- FastAPI and async Python  
- scikit‑learn model serving  
- SQLite and data persistence  
- Debugging network services  

…please reach out or submit a pull request with a fix.

**High‑priority tasks:**

- Debug the classifier integration – fix `ai_result` `null` issue.  
- Make alerts persist so the PDF report can retrieve data.  
- Simplify the startup process (e.g., single script to launch orchestrator + classifier).  
- Write unit tests for the core functions.

---

### Setup Instructions (For Contributors)

1. **Clone and initialise submodules**

   ```bash
   git clone https://github.com/GulrezQayyum/netguard
   cd netguard
   git submodule update --init --recursive
   ```

2. **Create directories**

   ```bash
   mkdir -p data reports
   ```

3. **Set up virtual environment**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Run the services (two terminals)**

   **Terminal 1 – Classifier**

   ```bash
   cd modules/classifier
   source ../.venv/bin/activate
   uvicorn backend.main:app --port 8000 --reload
   ```

   **Terminal 2 – Orchestrator**

   ```bash
   cd /path/to/netguard
   sudo /path/to/netguard/.venv/bin/uvicorn main:app --port 8080 --reload
   ```

5. **Test the `/analyze` endpoint**

   ```bash
   curl -X POST http://localhost:8080/analyze \
     -H "Content-Type: application/json" \
     -d '{"packet":{"src_ip":"10.0.0.99","dst_ip":"192.168.1.1","protocol":"TCP","flags":"S","src_port":12345,"dst_port":22,"length":60}}'
   ```

   - Expected: A response with `ai_result` **not** `null`.  
   - Actual: `ai_result` is `null` – this is the bug we need to fix.

---

### Current Debugging Notes

- The classifier responds with valid JSON (e.g., via `print(resp.text)` added in `main.py`).  
- The orchestrator receives the response but fails to assign it to `ai_result`, likely because `call_classifier()` returns `None` due to an exception that is caught and logged as `"Classifier offline or error"`.  
- The exception message `"All connection attempts failed"` is misleading: httpx logs show `200 OK`, so the failure is likely in reading / decoding the response body (timeout or JSON decode error).  
- Immediate next step: Insert detailed logging inside `call_classifier()` to capture response status, headers, and body, then refine based on actual output.

---

### Running & Accessing the Dashboard

Once both services are running:

- Classifier API: `http://localhost:8000/predict`
- Orchestrator & dashboard: `http://localhost:8080/`

Open your browser and navigate to:

- Main dashboard UI: [http://localhost:8080/](http://localhost:8080/)
- (Optional) API docs, if enabled: `http://localhost:8080/docs`

---

### Built With

- FastAPI – async REST API  
- Scapy – packet capture  
- scikit‑learn – Random Forest classifier (96.8% accuracy on NSL‑KDD)  
- SQLite – alert persistence  
- fpdf2 – PDF report generation  
- iptables – IP blocking on Linux  
- Chart.js – dashboard visualisations

---


**Ways you can help:**

- Fix open issues (AI classifier integration, alert persistence, PDF reporting).  
- Improve documentation and setup scripts for easier onboarding.  
- Add unit tests and CI for core modules.  
- Propose and implement new features (e.g., new detection rules, better dashboard, alternative blocking backends).

---

### Collaboration & Call for Contributors

If you’re interested in contributing, please:

- Open an issue on GitHub describing the bug you want to tackle.  
- Fork the repo, make a fix, and submit a pull request.
- Share feedback, ideas, or questions via issues or discussions.
  
---

### License

This is a collaborative open‑source project for educational and portfolio purposes. 

Let’s make NetGuard fully functional together! 🚀
