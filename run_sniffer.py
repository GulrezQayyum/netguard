# run_sniffer.py — place this in your netguard root folder
import sys
import requests
from pathlib import Path
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

API = "http://localhost:8080"   # ← correct, that's NetGuard

def on_packet(packet):
    if IP not in packet:
        return  # skip non-IP packets

    # Build the same dict your sniffer builds
    info = {
        "src_ip":   packet[IP].src,
        "dst_ip":   packet[IP].dst,
        "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER",
        "src_port": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
        "dst_port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
        "length":   len(packet),
        "flags":    str(packet[TCP].flags) if TCP in packet else "",
        "timestamp": datetime.now().isoformat(),
    }

    try:
        resp = requests.post(f"{API}/analyze", json={"packet": info, "features": {}}, timeout=2)
        result = resp.json()
        threat = result.get("threat_type")
        if threat:
            print(f"[THREAT] {threat.upper()} from {info['src_ip']}")
        else:
            print(f"[OK]     {info['protocol']} {info['src_ip']} → {info['dst_ip']}")
    except Exception as e:
        print(f"[ERR]    {e}")

print("NetGuard sniffer bridge running — press Ctrl+C to stop")
sniff(prn=on_packet, store=False)