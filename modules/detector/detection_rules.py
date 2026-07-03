"""
Detection Rules Engine for IDS
Implements rule-based intrusion detection using packet features
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import logging

logger = logging.getLogger(__name__)


class DetectionRules:
    """
    Rule-based intrusion detection engine
    Detects common attacks: port scans, SYN floods, ping floods, UDP floods
    """

    def __init__(self):
        """Initialize detection rules and tracking structures"""
        
        # Rule thresholds (configurable)
        self.rules_config = {
            'syn_flood': {
                'threshold': 50,          # SYN packets from one IP in time window
                'time_window': 10,        # seconds
                'severity': 'HIGH'
            },
            'port_scan': {
                'threshold': 5,           # Different ports scanned from one IP
                'time_window': 10,        # seconds
                'severity': 'HIGH'
            },
            'ping_flood': {
                'threshold': 20,          # ICMP packets in time window
                'time_window': 10,
                'severity': 'MEDIUM'
            },
            'udp_flood': {
                'threshold': 100,         # UDP packets from one IP
                'time_window': 5,
                'severity': 'MEDIUM'
            },
            'unusual_packet_rate': {
                'threshold': 1000,        # packets/sec threshold
                'severity': 'LOW'
            },
            'suspicious_ports': {
                'ports': [23, 135, 139, 445, 1433, 3389],  # Telnet, NetBIOS, RDP, MSSQL, etc.
                'severity': 'MEDIUM'
            }
        }
        
        # Tracking structures for stateful detection
        self.ip_packet_history = defaultdict(lambda: deque(maxlen=200))    # Store packets per IP
        self.tcp_connections = defaultdict(lambda: deque(maxlen=500))      # Track TCP connections
        self.icmp_packets = defaultdict(lambda: deque(maxlen=300))         # Track ICMP packets
        self.udp_packets = defaultdict(lambda: deque(maxlen=300))          # Track UDP packets
        self.port_scans = defaultdict(set)                                 # Track destination ports per IP
        
        self.lock = threading.Lock()
        
        # Alert history for deduplication
        self.recent_alerts = deque(maxlen=100)

    def analyze_packet(self, packet_info):
        """
        Analyze a single packet against all rules
        
        Args:
            packet_info (dict): Packet information from sniffer
            
        Returns:
            list: List of alerts (empty if no threats detected)
        """
        alerts = []
        
        with self.lock:
            timestamp = self._parse_timestamp(packet_info['timestamp'])
            src_ip = packet_info['src_ip']
            dst_ip = packet_info['dst_ip']
            protocol = packet_info['protocol']
            
            if src_ip == 'N/A' or dst_ip == 'N/A':
                return alerts
            
            # Store packet in history
            self.ip_packet_history[src_ip].append(timestamp)
            
            # Rule 1: SYN Flood Detection
            if protocol == 'TCP' and packet_info.get('flags') == 'S':
                alert = self._detect_syn_flood(src_ip, timestamp)
                if alert:
                    alerts.append(alert)
            
            # Rule 2: Port Scanning Detection
            if protocol == 'TCP' and packet_info.get('dst_port'):
                alert = self._detect_port_scan(src_ip, packet_info['dst_port'], timestamp)
                if alert:
                    alerts.append(alert)
            
            # Rule 3: Ping Flood Detection
            if protocol == 'ICMP':
                alert = self._detect_ping_flood(src_ip, timestamp)
                if alert:
                    alerts.append(alert)
            
            # Rule 4: UDP Flood Detection
            if protocol == 'UDP':
                self.udp_packets[src_ip].append(timestamp)
                alert = self._detect_udp_flood(src_ip, timestamp)
                if alert:
                    alerts.append(alert)
            
            # Rule 5: Suspicious Port Access
            alert = self._detect_suspicious_port(src_ip, dst_ip, protocol, packet_info.get('dst_port'))
            if alert:
                alerts.append(alert)
        
        return alerts

    def _detect_syn_flood(self, src_ip, timestamp):
        """
        Detect SYN flood: many SYN packets from single IP in short time
        """
        config = self.rules_config['syn_flood']
        
        # Count SYN packets from this IP in time window
        time_threshold = timestamp - timedelta(seconds=config['time_window'])
        
        # This would need more detailed tracking, using packet count as proxy
        packet_count = len([t for t in self.ip_packet_history[src_ip] 
                           if t > time_threshold])
        
        if packet_count > config['threshold']:
            return {
                'type': 'SYN_FLOOD',
                'src_ip': src_ip,
                'severity': config['severity'],
                'message': f"Possible SYN flood from {src_ip} ({packet_count} packets in {config['time_window']}s)",
                'timestamp': timestamp.isoformat(),
                'threshold': config['threshold'],
                'detected_value': packet_count
            }
        return None

    def _detect_port_scan(self, src_ip, dst_port, timestamp):
        """
        Detect port scanning: many different destination ports from single IP
        """
        config = self.rules_config['port_scan']
        
        # Add port to this IP's port set (auto-resets after time window)
        time_threshold = timestamp - timedelta(seconds=config['time_window'])
        
        # Track which ports we've seen recently
        if src_ip not in self.port_scans:
            self.port_scans[src_ip] = set()
        
        self.port_scans[src_ip].add(dst_port)
        
        # If too many different ports, it's a scan
        if len(self.port_scans[src_ip]) > config['threshold']:
            ports_list = sorted(list(self.port_scans[src_ip]))[:10]  # Show first 10
            return {
                'type': 'PORT_SCAN',
                'src_ip': src_ip,
                'severity': config['severity'],
                'message': f"Possible port scan from {src_ip} ({len(self.port_scans[src_ip])} different ports)",
                'timestamp': timestamp.isoformat(),
                'ports_scanned': ports_list,
                'threshold': config['threshold'],
                'detected_value': len(self.port_scans[src_ip])
            }
        return None

    def _detect_ping_flood(self, src_ip, timestamp):
        """
        Detect ping flood: many ICMP packets from single IP in short time
        """
        config = self.rules_config['ping_flood']
        
        self.icmp_packets[src_ip].append(timestamp)
        
        # Count ICMP packets in time window
        time_threshold = timestamp - timedelta(seconds=config['time_window'])
        icmp_count = len([t for t in self.icmp_packets[src_ip] if t > time_threshold])
        
        if icmp_count > config['threshold']:
            return {
                'type': 'PING_FLOOD',
                'src_ip': src_ip,
                'severity': config['severity'],
                'message': f"Possible ping flood from {src_ip} ({icmp_count} ICMP packets in {config['time_window']}s)",
                'timestamp': timestamp.isoformat(),
                'threshold': config['threshold'],
                'detected_value': icmp_count
            }
        return None

    def _detect_udp_flood(self, src_ip, timestamp):
        """
        Detect UDP flood: many UDP packets from single IP
        """
        config = self.rules_config['udp_flood']
        
        # Count UDP packets in time window
        time_threshold = timestamp - timedelta(seconds=config['time_window'])
        udp_count = len([t for t in self.udp_packets[src_ip] if t > time_threshold])
        
        if udp_count > config['threshold']:
            return {
                'type': 'UDP_FLOOD',
                'src_ip': src_ip,
                'severity': config['severity'],
                'message': f"Possible UDP flood from {src_ip} ({udp_count} UDP packets in {config['time_window']}s)",
                'timestamp': timestamp.isoformat(),
                'threshold': config['threshold'],
                'detected_value': udp_count
            }
        return None

    def _detect_suspicious_port(self, src_ip, dst_ip, protocol, dst_port):
        """
        Detect connection attempts to suspicious/dangerous ports
        """
        if not dst_port or protocol not in ['TCP', 'UDP']:
            return None
        
        config = self.rules_config['suspicious_ports']
        
        if dst_port in config['ports']:
            port_names = {
                23: 'Telnet',
                135: 'RPC',
                139: 'NetBIOS',
                445: 'SMB',
                1433: 'MSSQL',
                3389: 'RDP'
            }
            port_name = port_names.get(dst_port, f"Port {dst_port}")
            
            return {
                'type': 'SUSPICIOUS_PORT_ACCESS',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'severity': config['severity'],
                'message': f"Connection to suspicious port {dst_port} ({port_name}) from {src_ip}",
                'timestamp': datetime.now().isoformat(),
                'port': dst_port,
                'port_name': port_name
            }
        return None

    def analyze_packet_stream(self, packets):
        """
        Analyze multiple packets at once
        
        Args:
            packets (list): List of packet dictionaries
            
        Returns:
            list: Combined list of all alerts
        """
        all_alerts = []
        for packet in packets:
            alerts = self.analyze_packet(packet)
            all_alerts.extend(alerts)
        return all_alerts

    def get_suspicious_ips(self, top_n=10):
        """
        Get most suspicious IPs based on alert count
        
        Args:
            top_n (int): Number of top IPs to return
            
        Returns:
            list: List of (ip, alert_count) tuples
        """
        with self.lock:
            ip_alerts = defaultdict(int)
            for alert in self.recent_alerts:
                ip_alerts[alert['src_ip']] += 1
            
            return sorted(ip_alerts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    def get_alert_statistics(self):
        """
        Get statistics about detected alerts
        
        Returns:
            dict: Alert statistics
        """
        with self.lock:
            alert_types = defaultdict(int)
            severity_count = defaultdict(int)
            
            for alert in self.recent_alerts:
                alert_types[alert['type']] += 1
                severity_count[alert['severity']] += 1
            
            return {
                'total_alerts': len(self.recent_alerts),
                'alert_types': dict(alert_types),
                'severity_distribution': dict(severity_count),
                'suspicious_ips': self.get_suspicious_ips(5)
            }

    def _parse_timestamp(self, timestamp_str):
        """
        Parse timestamp string to datetime object
        """
        try:
            return datetime.fromisoformat(timestamp_str)
        except:
            return datetime.now()

    def reset_port_scans(self):
        """
        Reset port scan tracking (call periodically)
        """
        with self.lock:
            self.port_scans.clear()
            logger.info("Port scan tracking reset")

    def update_rule_threshold(self, rule_name, new_threshold):
        """
        Dynamically update rule thresholds
        
        Args:
            rule_name (str): Name of the rule
            new_threshold (int): New threshold value
        """
        if rule_name in self.rules_config:
            if 'threshold' in self.rules_config[rule_name]:
                self.rules_config[rule_name]['threshold'] = new_threshold
                logger.info(f"Updated {rule_name} threshold to {new_threshold}")

    def get_rules_config(self):
        """
        Get current rules configuration
        
        Returns:
            dict: Current detection rules configuration
        """
        return self.rules_config

    def add_alert_to_history(self, alert):
        """
        Track alert in recent history for deduplication
        
        Args:
            alert (dict): Alert to track
        """
        with self.lock:
            self.recent_alerts.append(alert)