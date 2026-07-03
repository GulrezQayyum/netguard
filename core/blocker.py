# core/blocker.py
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

BLOCKED_IPS: list[dict] = []  # in-memory log of blocked IPs

def block_ip(ip: str, reason: str) -> dict:
    """Block an IP using iptables and return a result dict."""
    result = {
        "ip": ip,
        "reason": reason,
        "timestamp": datetime.now().isoformat(),
        "success": False,
        "message": ""
    }
    try:
        # Drop all incoming packets from this IP
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        result["success"] = True
        result["message"] = f"IP {ip} blocked successfully."
        BLOCKED_IPS.append(result)
        logger.info(f"Blocked IP: {ip} | Reason: {reason}")
    except subprocess.CalledProcessError as e:
        result["message"] = f"Failed to block {ip}: {e.stderr.decode()}"
        logger.error(result["message"])
    return result

def unblock_ip(ip: str) -> dict:
    """Remove an iptables block for a given IP."""
    result = {"ip": ip, "success": False, "message": ""}
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        result["success"] = True
        result["message"] = f"IP {ip} unblocked."
    except subprocess.CalledProcessError as e:
        result["message"] = f"Failed to unblock {ip}: {e.stderr.decode()}"
    return result

def get_blocked_ips() -> list[dict]:
    return BLOCKED_IPS