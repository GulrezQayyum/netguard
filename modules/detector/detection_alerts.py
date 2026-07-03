"""
Alert Logging and Database Management
Persists alerts to SQLite for historical analysis and reporting
"""

import sqlite3
import threading
import logging
from datetime import datetime, timedelta
from pathlib import Path
import json
from collections import deque

logger = logging.getLogger(__name__)


class AlertDatabase:
    """
    SQLite database for persistent alert storage
    Thread-safe alert logging and retrieval
    """

    def __init__(self, db_path='data/alerts.db'):
        """
        Initialize alert database
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        
        # Create data directory if it doesn't exist
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Create database tables if they don't exist"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        message TEXT,
                        details TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indices for faster queries
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_alert_type ON alerts(alert_type)
                ''')
                
                # Statistics table (for fast aggregations)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alert_statistics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL UNIQUE,
                        total_alerts INTEGER,
                        high_alerts INTEGER,
                        medium_alerts INTEGER,
                        low_alerts INTEGER,
                        unique_ips INTEGER,
                        top_attacks TEXT
                    )
                ''')
                
                # Blocked IPs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL UNIQUE,
                        reason TEXT,
                        blocked_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        unblocked_at TEXT
                    )
                ''')
                
                conn.commit()
                logger.info(f"Database initialized: {self.db_path}")
                
        except Exception as e:
            logger.error(f"Error initializing database: {e}")

    def log_alert(self, alert):
        """
        Log an alert to the database
        
        Args:
            alert (dict): Alert information from detection engine
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT INTO alerts (
                            timestamp, alert_type, severity, src_ip, dst_ip,
                            src_port, dst_port, message, details
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        alert.get('timestamp', datetime.now().isoformat()),
                        alert.get('type', 'UNKNOWN'),
                        alert.get('severity', 'LOW'),
                        alert.get('src_ip', 'N/A'),
                        alert.get('dst_ip', 'N/A'),
                        alert.get('src_port'),
                        alert.get('dst_port'),
                        alert.get('message', ''),
                        json.dumps(alert)  # Store full alert as JSON
                    ))
                    
                    conn.commit()
        except Exception as e:
            logger.error(f"Error logging alert: {e}")

    def log_multiple_alerts(self, alerts):
        """
        Log multiple alerts at once (more efficient)
        
        Args:
            alerts (list): List of alert dictionaries
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    for alert in alerts:
                        cursor.execute('''
                            INSERT INTO alerts (
                                timestamp, alert_type, severity, src_ip, dst_ip,
                                src_port, dst_port, message, details
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            alert.get('timestamp', datetime.now().isoformat()),
                            alert.get('type', 'UNKNOWN'),
                            alert.get('severity', 'LOW'),
                            alert.get('src_ip', 'N/A'),
                            alert.get('dst_ip', 'N/A'),
                            alert.get('src_port'),
                            alert.get('dst_port'),
                            alert.get('message', ''),
                            json.dumps(alert)
                        ))
                    
                    conn.commit()
        except Exception as e:
            logger.error(f"Error logging multiple alerts: {e}")

    def get_alerts(self, limit=100, offset=0):
        """
        Get alerts from database
        
        Args:
            limit (int): Number of alerts to retrieve
            offset (int): Offset for pagination
            
        Returns:
            list: List of alert dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM alerts 
                    ORDER BY timestamp DESC 
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []

    def get_recent_alerts(self, limit=12):
        """
        Get recent alerts (convenience method)
        
        Args:
            limit (int): Number of recent alerts to retrieve
            
        Returns:
            list: Most recent alerts
        """
        return self.get_alerts(limit=limit, offset=0)

    def get_alerts_by_severity(self, severity, limit=100):
        """
        Get alerts filtered by severity
        
        Args:
            severity (str): 'HIGH', 'MEDIUM', or 'LOW'
            limit (int): Number of alerts
            
        Returns:
            list: Filtered alerts
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM alerts 
                    WHERE severity = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (severity, limit))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error retrieving alerts by severity: {e}")
            return []

    def get_alerts_by_ip(self, ip_address, limit=100):
        """
        Get all alerts from a specific IP
        
        Args:
            ip_address (str): Source IP address
            limit (int): Number of alerts
            
        Returns:
            list: Alerts from this IP
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM alerts 
                    WHERE src_ip = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (ip_address, limit))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error retrieving alerts by IP: {e}")
            return []

    def get_alerts_by_type(self, alert_type, limit=100):
        """
        Get alerts of specific type
        
        Args:
            alert_type (str): Alert type (e.g., 'SYN_FLOOD', 'PORT_SCAN')
            limit (int): Number of alerts
            
        Returns:
            list: Filtered alerts
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM alerts 
                    WHERE alert_type = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (alert_type, limit))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error retrieving alerts by type: {e}")
            return []

    def get_alerts_in_timerange(self, start_time, end_time):
        """
        Get alerts within a time range
        
        Args:
            start_time (str): ISO format start time
            end_time (str): ISO format end time
            
        Returns:
            list: Alerts in time range
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM alerts 
                    WHERE timestamp BETWEEN ? AND ? 
                    ORDER BY timestamp DESC
                ''', (start_time, end_time))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error retrieving alerts by time range: {e}")
            return []

    def get_total_alert_count(self):
        """
        Get total number of alerts in database
        
        Returns:
            int: Total alert count
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM alerts')
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error getting alert count: {e}")
            return 0

    def get_statistics(self):
        """
        Get comprehensive alert statistics
        
        Returns:
            dict: Statistics summary
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total alerts
                cursor.execute('SELECT COUNT(*) FROM alerts')
                total = cursor.fetchone()[0]
                
                # By severity
                cursor.execute('''
                    SELECT severity, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY severity
                ''')
                severity_stats = {row[0]: row[1] for row in cursor.fetchall()}
                
                # By type
                cursor.execute('''
                    SELECT alert_type, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY alert_type
                ''')
                type_stats = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Unique IPs
                cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM alerts')
                unique_ips = cursor.fetchone()[0]
                
                # Top 10 IPs
                cursor.execute('''
                    SELECT src_ip, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY src_ip 
                    ORDER BY count DESC 
                    LIMIT 10
                ''')
                top_ips = [(row[0], row[1]) for row in cursor.fetchall()]
                
                return {
                    'total_alerts': total,
                    'by_severity': severity_stats,
                    'by_type': type_stats,
                    'unique_ips': unique_ips,
                    'top_ips': top_ips
                }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    def block_ip(self, ip_address, reason='Manual block'):
        """
        Add IP to blocked list
        
        Args:
            ip_address (str): IP to block
            reason (str): Reason for blocking
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT OR IGNORE INTO blocked_ips (ip_address, reason)
                        VALUES (?, ?)
                    ''', (ip_address, reason))
                    
                    conn.commit()
                    logger.info(f"Blocked IP: {ip_address} - Reason: {reason}")
        except Exception as e:
            logger.error(f"Error blocking IP: {e}")

    def unblock_ip(self, ip_address):
        """
        Remove IP from blocked list
        
        Args:
            ip_address (str): IP to unblock
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        UPDATE blocked_ips 
                        SET unblocked_at = CURRENT_TIMESTAMP 
                        WHERE ip_address = ? AND unblocked_at IS NULL
                    ''', (ip_address,))
                    
                    conn.commit()
                    logger.info(f"Unblocked IP: {ip_address}")
        except Exception as e:
            logger.error(f"Error unblocking IP: {e}")

    def get_blocked_ips(self):
        """
        Get list of currently blocked IPs
        
        Returns:
            list: Blocked IP addresses
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT ip_address, reason, blocked_at 
                    FROM blocked_ips 
                    WHERE unblocked_at IS NULL
                ''')
                
                return [{'ip': row[0], 'reason': row[1], 'blocked_at': row[2]} 
                        for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting blocked IPs: {e}")
            return []

    def export_alerts_csv(self, filename, filters=None):
        """
        Export alerts to CSV file
        
        Args:
            filename (str): Output CSV filename
            filters (dict): Optional filters (severity, alert_type, src_ip, date_from, date_to)
        """
        try:
            import csv
            
            alerts = self.get_alerts(limit=10000)
            
            if filters:
                if 'severity' in filters:
                    alerts = [a for a in alerts if a.get('severity') == filters['severity']]
                if 'alert_type' in filters:
                    alerts = [a for a in alerts if a.get('alert_type') == filters['alert_type']]
                if 'src_ip' in filters:
                    alerts = [a for a in alerts if a.get('src_ip') == filters['src_ip']]
            
            if not alerts:
                logger.warning("No alerts to export")
                return
            
            # Get all unique keys
            fieldnames = set()
            for alert in alerts:
                fieldnames.update(alert.keys())
            fieldnames = sorted(list(fieldnames))
            
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(alerts)
            
            logger.info(f"Exported {len(alerts)} alerts to {filename}")
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")

    def export_alerts_json(self, filename, filters=None):
        """
        Export alerts to JSON file
        
        Args:
            filename (str): Output JSON filename
            filters (dict): Optional filters
        """
        try:
            alerts = self.get_alerts(limit=10000)
            
            if filters:
                if 'severity' in filters:
                    alerts = [a for a in alerts if a.get('severity') == filters['severity']]
                if 'alert_type' in filters:
                    alerts = [a for a in alerts if a.get('alert_type') == filters['alert_type']]
            
            with open(filename, 'w') as jsonfile:
                json.dump(alerts, jsonfile, indent=2)
            
            logger.info(f"Exported {len(alerts)} alerts to {filename}")
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")

    def clear_old_alerts(self, days=30):
        """
        Delete alerts older than specified days (for cleanup)
        
        Args:
            days (int): Keep alerts from last N days
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        DELETE FROM alerts 
                        WHERE timestamp < ?
                    ''', (cutoff_date,))
                    
                    deleted = cursor.rowcount
                    conn.commit()
                    logger.info(f"Deleted {deleted} alerts older than {days} days")
        except Exception as e:
            logger.error(f"Error clearing old alerts: {e}")

    def get_database_size(self):
        """
        Get database file size in MB
        
        Returns:
            float: Database size in MB
        """
        try:
            size_bytes = Path(self.db_path).stat().st_size
            return size_bytes / (1024 * 1024)  # Convert to MB
        except Exception as e:
            logger.error(f"Error getting database size: {e}")
            return 0

    def get_database_info(self):
        """
        Get comprehensive database information
        
        Returns:
            dict: Database statistics and info
        """
        return {
            'path': self.db_path,
            'size_mb': round(self.get_database_size(), 2),
            'total_alerts': self.get_total_alert_count(),
            'statistics': self.get_statistics(),
            'blocked_ips': len(self.get_blocked_ips())
        }