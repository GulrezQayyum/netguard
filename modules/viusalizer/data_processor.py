"""
Module for processing and analyzing network packets
"""

import pandas as pd
from collections import defaultdict, Counter
from scapy.all import IP, TCP, UDP, ICMP


class DataProcessor:
    """Process and analyze captured network traffic"""

    def __init__(self, packets):
        """
        Initialize data processor

        Args:
            packets: List of Scapy packet objects
        """
        self.packets = packets
        self.stats = {}

    def extract_packet_info(self):
        """
        Extract relevant information from packets

        Returns:
            DataFrame with packet information
        """
        packet_data = []

        for packet in self.packets:
            if IP in packet:
                info = {
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": packet[IP].proto,
                    "length": len(packet),
                }

                if TCP in packet:
                    info["transport"] = "TCP"
                    info["src_port"] = packet[TCP].sport
                    info["dst_port"] = packet[TCP].dport
                elif UDP in packet:
                    info["transport"] = "UDP"
                    info["src_port"] = packet[UDP].sport
                    info["dst_port"] = packet[UDP].dport
                elif ICMP in packet:
                    info["transport"] = "ICMP"
                else:
                    info["transport"] = "Other"

                packet_data.append(info)

        return pd.DataFrame(packet_data)

    def get_bandwidth_stats(self):
        """
        Calculate bandwidth statistics

        Returns:
            Dictionary with bandwidth stats
        """
        if not self.packets:
            return {"total_bytes": 0, "packet_count": 0}

        total_bytes = sum(len(p) for p in self.packets)
        return {"total_bytes": total_bytes, "packet_count": len(self.packets)}

    def get_protocol_distribution(self):
        """
        Get distribution of protocols

        Returns:
            Counter object with protocol counts
        """
        protocols = Counter()

        for packet in self.packets:
            if TCP in packet:
                protocols["TCP"] += 1
            elif UDP in packet:
                protocols["UDP"] += 1
            elif ICMP in packet:
                protocols["ICMP"] += 1
            else:
                protocols["Other"] += 1

        return protocols

    def get_top_ips(self, n=10):
        """
        Get top N source IPs by packet count

        Args:
            n: Number of top IPs to return

        Returns:
            Counter object with top IPs
        """
        ips = Counter()

        for packet in self.packets:
            if IP in packet:
                ips[packet[IP].src] += 1

        return ips.most_common(n)

    def get_connection_pairs(self):
        """
        Get all IP connection pairs

        Returns:
            List of tuples (src_ip, dst_ip, count)
        """
        connections = defaultdict(int)

        for packet in self.packets:
            if IP in packet:
                key = (packet[IP].src, packet[IP].dst)
                connections[key] += 1

        return sorted(
            [(src, dst, count) for (src, dst), count in connections.items()],
            key=lambda x: x[2],
            reverse=True,
        )