#!/usr/bin/env python3
"""
A Beginner-Friendly Network Sniffer
This tool helps you understand how data flows through your network.

WHAT IT DOES:
- Captures network packets (data traveling through your network)
- Displays information about each packet (source, destination, protocol)
- Helps you learn network fundamentals like IP addresses and protocols

REQUIREMENTS:
- Linux/Mac with root/admin privileges (to capture packets)
- scapy library (Python packet manipulation library)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys
import socket
from datetime import datetime


def get_hostname_from_ip(ip_address):
    """
    Reverse DNS lookup - find the hostname/website from an IP address.
    This shows which website or service owns that IP.
    
    Args:
        ip_address: IP address to look up
    
    Returns:
        Hostname/domain name or the IP if lookup fails
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except:
        # If reverse DNS fails, just return the IP
        return ip_address


def get_local_ips():
    """
    Get all local IP addresses of this machine.
    These are your computer's IPs on the network.
    """
    local_ips = []
    try:
        # Get hostname and resolve to IPs
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        local_ips.append(local_ip)
    except:
        pass
    
    # Also try to get IPs from all interfaces
    try:
        import subprocess
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        if result.stdout:
            local_ips.extend(result.stdout.strip().split())
    except:
        pass
    
    # Remove duplicates and return
    return list(set(local_ips))


def analyze_packet(packet, local_ips):
    """
    Analyze a single packet and display useful information.
    
    Args:
        packet: A Scapy packet object
        local_ips: List of your computer's IP addresses
    """
    # Check if packet has an IP layer (most packets do)
    if IP in packet:
        ip_src = packet[IP].src          # Source IP address
        ip_dst = packet[IP].dst          # Destination IP address
        protocol = packet[IP].proto      # Protocol number (6=TCP, 17=UDP, 1=ICMP)
        ttl = packet[IP].ttl             # Time To Live (hops remaining)
        
        # Check if this packet involves YOUR computer
        is_from_you = ip_src in local_ips
        is_to_you = ip_dst in local_ips
        
        # Decode protocol number to human-readable format
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = protocol_map.get(protocol, "OTHER")
        
        # Create marker to show if packet is from/to your computer
        marker = ""
        if is_from_you:
            marker = " ← YOUR COMPUTER (SENDING)"
        elif is_to_you:
            marker = " ← YOUR COMPUTER (RECEIVING)"
        
        # Print basic packet info
        print(f"\n{'='*70}")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Packet Captured{marker}")
        print(f"{'='*70}")
        print(f"Source IP: {ip_src:<20} → Destination IP: {ip_dst}")
        
        # Try to get the website/service name for the destination IP
        dest_hostname = get_hostname_from_ip(ip_dst)
        if dest_hostname != ip_dst:
            print(f"Destination Service: {dest_hostname}")
        
        print(f"Protocol: {protocol_name:<15} TTL: {ttl}")
        
        # Get more details based on the protocol
        if TCP in packet:
            sport = packet[TCP].sport      # Source port
            dport = packet[TCP].dport      # Destination port
            flags = packet[TCP].flags      # TCP flags (SYN, ACK, FIN, etc.)
            print(f"TCP Ports: {sport} → {dport}")
            print(f"Flags: {flags}")
            
        elif UDP in packet:
            sport = packet[UDP].sport      # Source port
            dport = packet[UDP].dport      # Destination port
            print(f"UDP Ports: {sport} → {dport}")
            
        elif ICMP in packet:
            print(f"ICMP Type: {packet[ICMP].type}")
        
        # Show packet size
        packet_size = len(packet)
        print(f"Packet Size: {packet_size} bytes")


def start_sniffer(packet_count=10, interface=None):
    """
    Start capturing packets from the network.
    
    Args:
        packet_count: Number of packets to capture (default: 10)
        interface: Network interface to sniff on (default: auto-detect)
    
    WHAT'S HAPPENING:
    - sniff() listens for all packets on your network interface
    - prn=analyze_packet calls our analyze_packet() for each packet
    - count=packet_count stops after capturing this many packets
    """
    try:
        # Get your computer's local IP addresses
        local_ips = get_local_ips()
        
        print("\n" + "="*70)
        print("NETWORK SNIFFER - Educational Packet Analyzer")
        print("="*70)
        print(f"\n🖥️  YOUR COMPUTER'S IP ADDRESS(ES):")
        for ip in local_ips:
            print(f"   → {ip}")
        print(f"\nStarting packet capture (will capture {packet_count} packets)...")
        print("Note: This includes ALL packets - your traffic, system traffic, etc.\n")
        
        # Create a wrapper function that passes local_ips to analyze_packet
        def packet_callback(packet):
            analyze_packet(packet, local_ips)
        
        # Start sniffing
        sniff(
            prn=packet_callback,          # Function to call for each packet
            count=packet_count,           # Number of packets to capture
            iface=interface,              # Network interface (None=default)
            store=False                   # Don't store packets in memory
        )
        
        print("\n" + "="*70)
        print("Capture Complete!")
        print("="*70)
        
    except PermissionError:
        print("\n❌ ERROR: Root/Administrator privileges required!")
        print("On Linux: Run with 'sudo python3 sniffer.py'")
        print("On Mac:   Run with 'sudo python3 sniffer.py'")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nCapture stopped by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Customize packet count if provided as argument
    packet_count = 10
    if len(sys.argv) > 1:
        try:
            packet_count = int(sys.argv[1])
        except ValueError:
            print(f"Usage: python3 sniffer.py [packet_count]")
            print(f"Example: python3 sniffer.py 20")
            sys.exit(1)
    
    start_sniffer(packet_count=packet_count)