"""
NetGuard — AI Network Traffic Analyzer & Active Defense Platform
main.py — FastAPI orchestrator

Wires together:
  modules/sniffer    → analyze_packet(), get_local_ips()
  modules/visualizer → PacketCapture, DataProcessor
  modules/detector   → DetectionRules, AlertDatabase
  modules/classifier → POST http://localhost:8000/predict  (runs separately)
  core/remediation   → get_remediation()
  core/blocker       → block_ip(), unblock_ip(), get_blocked_ips()
  core/reporter      → generate_report()

Run:
  Terminal 1 — cd modules/classifier && uvicorn backend.main:app --port 8000
  Terminal 2 — sudo uvicorn main:app --port 8080 --reload
"""

import sys
import logging
from pathlib import Path
from datetime import datetime

import httpx
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# ── Add modules/ to Python path so imports resolve ────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "modules"))

# ── Import from your existing repos ───────────────────────────────────────
# Sniffer — functions (not a class)
from modules.sniffer import analyze_packet as sniffer_analyze, get_local_ips

# Visualizer — classes
from modules.viusalizer import PacketCapture
from modules.viusalizer import DataProcessor

# Intrusion Detector — classes
from modules.detector import DetectionRules
from modules.detector import AlertDatabase

# ── Import new NetGuard core ───────────────────────────────────────────────
from core.remediation import get_remediation
from core.blocker import block_ip, unblock_ip, get_blocked_ips
from core.reporter import generate_report

# ── Logging ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("netguard")

# ── FastAPI app ────────────────────────────────────────────────────────────
app = FastAPI(
    title="NetGuard",
    description="AI Network Traffic Analyzer & Active Defense Platform",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve dashboard as static files
app.mount("/static", StaticFiles(directory=str(ROOT / "dashboard")), name="static")

# ── Global state ───────────────────────────────────────────────────────────
detector = DetectionRules()
alert_db = AlertDatabase(db_path="data/alerts.db")

# ── Map AI classifier labels → remediation threat types ───────────────────
# Your classifier outputs: dos, normal, probe, r2l, u2r
LABEL_TO_THREAT = {
    "dos":    "ddos",
    "probe":  "port_scan",
    "r2l":    "brute_force",
    "u2r":    "malicious_traffic",
    "normal": None,
}

# ── Pydantic request/response models ──────────────────────────────────────

class PacketInput(BaseModel):
    """
    Packet data sent to /analyze.
    Matches the dict that analyze_packet() returns from your sniffer.
    """
    src_ip:    str   = Field(...,  example="192.168.1.105")
    dst_ip:    str   = Field(...,  example="8.8.8.8")
    protocol:  str   = Field(...,  example="TCP")
    src_port:  int   = Field(0,    example=54321)
    dst_port:  int   = Field(0,    example=80)
    length:    int   = Field(0,    example=1480)
    flags:     str   = Field("",   example="S")      # TCP flags e.g. "S", "SA", "R"
    timestamp: str   = Field("",   example="2025-07-04T22:00:00")

class ClassifierFeatures(BaseModel):
    """
    The 12 features your AI classifier (config.py FEATURES list) expects.
    All default to 0 — fill what you know from the packet.
    """
    duration:           float = 0.0
    src_bytes:          float = 0.0
    dst_bytes:          float = 0.0
    count:              float = 0.0
    srv_count:          float = 0.0
    serror_rate:        float = 0.0
    srv_serror_rate:    float = 0.0
    rerror_rate:        float = 0.0
    srv_rerror_rate:    float = 0.0
    same_srv_rate:      float = 0.0
    dst_host_count:     float = 0.0
    dst_host_srv_count: float = 0.0

class BlockRequest(BaseModel):
    ip:     str = Field(..., example="192.168.1.105")
    reason: str = Field("manual", example="port_scan")

class AnalyzeRequest(BaseModel):
    """Full analyze request — packet + optional pre-extracted features."""
    packet:   PacketInput
    features: ClassifierFeatures = ClassifierFeatures()  # optional; defaults to zeros


# ── Helper: call AI classifier ─────────────────────────────────────────────

async def call_classifier(features: ClassifierFeatures) -> dict | None:
    """
    POST to your AI classifier running on port 8000.
    Endpoint: POST /predict
    Body matches your PredictionRequest schema in backend/main.py.
    Returns prediction dict or None if classifier is offline.
    """
    payload = {
        "duration":           features.duration,
        "protocol_type":      "tcp",       # default; sniffer doesn't extract this field
        "service":            "http",      # default
        "flag":               "SF",        # default (normal established)
        "src_bytes":          features.src_bytes,
        "dst_bytes":          features.dst_bytes,
        "land":               0,
        "wrong_fragment":     0,
        "urgent":             0,
        "hot":                0,
        "num_failed_logins":  0,
        "logged_in":          0,
        "count":              features.count,
        "srv_count":          features.srv_count,
        "serror_rate":        features.serror_rate,
        "srv_serror_rate":    features.srv_serror_rate,
        "rerror_rate":        features.rerror_rate,
        "srv_rerror_rate":    features.srv_rerror_rate,
        "same_srv_rate":      features.same_srv_rate,
        "dst_host_count":     features.dst_host_count,
        "dst_host_srv_count": features.dst_host_srv_count,
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post("http://localhost:8000/predict", json=payload)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning(f"Classifier offline or error: {e}")
        return None


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root():
    """Serve the dashboard."""
    return FileResponse(str(ROOT / "dashboard" / "index.html"))


@app.get("/health")
def health():
    """Quick health check."""
    return {
        "status": "ok",
        "time":   datetime.now().isoformat(),
        "local_ips": get_local_ips(),
    }


@app.post("/analyze")
async def analyze(req: AnalyzeRequest, bg: BackgroundTasks):
    """
    Core pipeline — the brain of NetGuard:

      1. Fill timestamp if missing
      2. Run packet through IDS DetectionRules.analyze_packet()
      3. Call AI classifier → get label (dos/probe/r2l/u2r/normal)
      4. Map label → threat type → get remediation guide
      5. Auto-block source IP if severity == HIGH
      6. Log alert to SQLite in background
      7. Return everything to dashboard in one response
    """
    packet = req.packet

    # Step 1 — timestamp
    if not packet.timestamp:
        packet.timestamp = datetime.now().isoformat()

    # Build packet_info dict matching DetectionRules.analyze_packet() expectations
    packet_info = {
        "src_ip":    packet.src_ip,
        "dst_ip":    packet.dst_ip,
        "protocol":  packet.protocol,
        "src_port":  packet.src_port,
        "dst_port":  packet.dst_port,
        "length":    packet.length,
        "flags":     packet.flags,
        "timestamp": packet.timestamp,
    }

    # Step 2 — IDS rule engine
    ids_alerts = detector.analyze_packet(packet_info)

    # Step 3 — AI classifier
    ai_result   = await call_classifier(req.features)
    ai_label    = ai_result.get("prediction", "normal").lower() if ai_result else None

    # Step 4 — resolve threat type
    # Priority: AI label > IDS alert type > None
    threat_type = None
    if ai_label and ai_label != "normal":
        threat_type = LABEL_TO_THREAT.get(ai_label)
    elif ids_alerts:
        # IDS uses rule names like "syn_flood", "port_scan" — map to our types
        rule_type = ids_alerts[0].get("rule_type", "")
        ids_map = {
            "syn_flood":  "ddos",
            "port_scan":  "port_scan",
            "ping_flood": "ddos",
            "udp_flood":  "ddos",
        }
        threat_type = ids_map.get(rule_type, "unusual_traffic")

    remediation = get_remediation(threat_type) if threat_type else None

    # Step 5 — auto-block if HIGH
    block_result = None
    if remediation and remediation.get("severity") == "high":
        block_result = block_ip(packet.src_ip, threat_type)
        logger.warning(
            f"AUTO-BLOCK | IP: {packet.src_ip} | Reason: {threat_type} | "
            f"Result: {block_result['message']}"
        )

    # Step 6 — log to SQLite (non-blocking)
    if ids_alerts or threat_type:
        alert_record = {
            "timestamp":  packet.timestamp,
            "alert_type": threat_type or ids_alerts[0].get("rule_type", "unknown"),
            "severity":   remediation["severity"].upper() if remediation else "LOW",
            "src_ip":     packet.src_ip,
            "dst_ip":     packet.dst_ip,
            "src_port":   packet.src_port,
            "dst_port":   packet.dst_port,
            "message":    remediation["title"] if remediation else "IDS alert",
            "details":    str(ids_alerts),
        }
        bg.add_task(alert_db.log_alert, alert_record)

    # Step 7 — respond
    return {
        "packet":      packet_info,
        "ids_alerts":  ids_alerts,
        "ai_result":   ai_result,
        "threat_type": threat_type,
        "remediation": remediation,
        "block_result": block_result,
        "timestamp":   packet.timestamp,
    }


@app.get("/alerts")
def get_alerts(limit: int = 50):
    """Return recent alerts from SQLite."""
    return alert_db.get_recent_alerts(limit=limit)


@app.get("/alerts/ip/{src_ip}")
def get_alerts_by_ip(src_ip: str):
    """Return all alerts for a specific source IP."""
    try:
        import sqlite3
        with sqlite3.connect("data/alerts.db") as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM alerts WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 100",
                (src_ip,)
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/block")
def manual_block(req: BlockRequest):
    """Manually block an IP from the dashboard."""
    return block_ip(req.ip, req.reason)


@app.delete("/block/{ip}")
def manual_unblock(ip: str):
    """Unblock an IP."""
    return unblock_ip(ip)


@app.get("/blocked")
def list_blocked():
    """List all currently blocked IPs."""
    return get_blocked_ips()


@app.get("/report/{src_ip}")
def export_report(src_ip: str):
    """
    Generate and download a PDF incident report for a given source IP.
    Pulls the most recent alert for that IP from SQLite.
    """
    import sqlite3
    try:
        with sqlite3.connect("data/alerts.db") as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM alerts WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 1",
                (src_ip,)
            )
            row = cur.fetchone()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not row:
        raise HTTPException(status_code=404, detail=f"No alerts found for IP: {src_ip}")

    alert    = dict(row)
    threat   = alert.get("alert_type", "unusual_traffic")
    remediation  = get_remediation(threat)
    block_result = next((b for b in get_blocked_ips() if b["ip"] == src_ip), None)

    filepath = generate_report(alert, remediation, block_result)
    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename=Path(filepath).name
    )


@app.get("/stats")
def get_stats():
    """
    Summary stats for the dashboard header cards.
    Returns total alerts, blocked IPs, and severity breakdown.
    """
    import sqlite3
    blocked = get_blocked_ips()

    try:
        with sqlite3.connect("data/alerts.db") as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Total
            cur.execute("SELECT COUNT(*) as n FROM alerts")
            total = cur.fetchone()["n"]

            # By severity
            cur.execute("""
                SELECT severity, COUNT(*) as n
                FROM alerts
                GROUP BY severity
            """)
            severity_counts = {r["severity"]: r["n"] for r in cur.fetchall()}

            # Top attacking IPs
            cur.execute("""
                SELECT src_ip, COUNT(*) as n
                FROM alerts
                GROUP BY src_ip
                ORDER BY n DESC
                LIMIT 5
            """)
            top_ips = [{"ip": r["src_ip"], "count": r["n"]} for r in cur.fetchall()]

            # Recent activity (last 10)
            cur.execute("""
                SELECT timestamp, alert_type, severity, src_ip
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            recent = [dict(r) for r in cur.fetchall()]

    except Exception:
        total = 0
        severity_counts = {}
        top_ips = []
        recent = []

    return {
        "total_alerts":  total,
        "blocked_count": len(blocked),
        "severity":      severity_counts,
        "top_ips":       top_ips,
        "recent":        recent,
    }


@app.get("/visualizer/stats")
def visualizer_stats():
    """
    Pull bandwidth and protocol stats from DataProcessor.
    Uses a short live capture (5 packets, 3s timeout) or returns zeros if no root.
    """
    try:
        cap = PacketCapture(packet_count=5)
        cap.start_capture(timeout=3)
        packets = cap.get_packets()

        if not packets:
            return {"bandwidth": {"total_bytes": 0, "packet_count": 0}, "protocols": {}}

        dp = DataProcessor(packets)
        return {
            "bandwidth":  dp.get_bandwidth_stats(),
            "protocols":  dp.get_protocol_distribution(),
        }
    except Exception as e:
        logger.warning(f"Visualizer stats skipped: {e}")
        return {"bandwidth": {"total_bytes": 0, "packet_count": 0}, "protocols": {}}