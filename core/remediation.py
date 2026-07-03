# core/remediation.py

REMEDIATION_GUIDE = {
    "port_scan": {
        "severity": "medium",
        "title": "Port scan detected",
        "what_happened": "An external IP systematically probed multiple ports on your network, looking for open services to exploit.",
        "steps": [
            "Identify the source IP from the alert details below.",
            "Check if this IP belongs to a known service (run: whois <IP>).",
            "If unrecognized, block it immediately using the 'Block IP' button.",
            "Review which ports were probed — close any that should not be public.",
            "Check your firewall rules: sudo iptables -L -n"
        ],
        "auto_action": "log"
    },
    "ddos": {
        "severity": "high",
        "title": "DDoS attack in progress",
        "what_happened": "Your network is receiving an abnormally high volume of requests from one or multiple IPs, designed to overwhelm your system.",
        "steps": [
            "The attacking IP has been automatically blocked (see below).",
            "Monitor if traffic normalizes within 2-3 minutes.",
            "If attack continues from new IPs, enable rate limiting: sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute -j ACCEPT",
            "Contact your ISP if the attack persists — they can filter upstream.",
            "Document the incident using the 'Export Report' button."
        ],
        "auto_action": "block"
    },
    "brute_force": {
        "severity": "high",
        "title": "Brute force login attempt",
        "what_happened": "Repeated failed login attempts detected from a single IP — someone is trying to guess a password.",
        "steps": [
            "The source IP has been automatically blocked.",
            "Immediately change the password of the targeted account.",
            "Enable two-factor authentication if not already active.",
            "Check login logs: sudo journalctl -u ssh | tail -50",
            "Consider installing fail2ban for permanent protection."
        ],
        "auto_action": "block"
    },
    "malicious_traffic": {
        "severity": "high",
        "title": "Malicious traffic flagged by AI",
        "what_happened": "The AI classifier detected traffic patterns matching known malware signatures or command-and-control communication.",
        "steps": [
            "Isolate the source device from the network immediately.",
            "Run a malware scan on the source device.",
            "Block the destination IP using the button below.",
            "Check for any recently installed software on the flagged device.",
            "Export this incident report and preserve it as evidence."
        ],
        "auto_action": "block"
    },
    "unusual_traffic": {
        "severity": "low",
        "title": "Unusual traffic pattern",
        "what_happened": "Traffic volume or protocol usage is outside normal patterns, but no specific attack signature was matched.",
        "steps": [
            "Monitor the source IP for the next 10-15 minutes.",
            "Check if it corresponds to a scheduled backup or update.",
            "No immediate action required — this is logged for review."
        ],
        "auto_action": "log"
    }
}

def get_remediation(threat_type: str) -> dict:
    """Return the remediation guide for a given threat type."""
    return REMEDIATION_GUIDE.get(
        threat_type.lower(),
        {
            "severity": "low",
            "title": "Unknown threat type",
            "what_happened": "An unrecognized threat type was flagged.",
            "steps": ["Review the raw alert data and consult your network logs."],
            "auto_action": "log"
        }
    )