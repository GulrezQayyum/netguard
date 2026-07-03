"""
Module for capturing and filtering network packets using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PacketCapture:
    """Captures network packets from the specified interface"""

    def __init__(self, interface=None, packet_count=0):
        """
        Initialize packet capture

        Args:
            interface: Network interface to capture from (None for default)
            packet_count: Number of packets to capture (0 for infinite)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packets = []

    def packet_callback(self, packet):
        """
        Callback function for each captured packet

        Args:
            packet: Scapy packet object
        """
        self.packets.append(packet)
        logger.info(f"Captured packet: {len(self.packets)}")

    def start_capture(self, filter_str="", timeout=None):
        """
        Start capturing packets

        Args:
            filter_str: BPF filter string (e.g., "tcp port 80")
            timeout: Capture timeout in seconds
        """
        try:
            logger.info(f"Starting capture on interface: {self.interface or 'default'}")
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_count,
                filter=filter_str,
                timeout=timeout,
                store=False,
            )
            logger.info("Packet capture completed")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")

    def get_packets(self):
        """Return captured packets"""
        return self.packets

    def clear_packets(self):
        """Clear the packet buffer"""
        self.packets = []