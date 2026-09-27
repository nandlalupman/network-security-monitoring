"""
Database Module (Person 4 — Part 1)
=====================================
Handles all SQLite database operations:
  - Creating tables
  - Inserting alerts and traffic stats
  - Querying data for the Flask API

Tables:
  1. alerts         — Stores detected security alerts
  2. traffic_stats  — Stores per-analysis traffic statistics
  3. analysis_runs  — Stores metadata about each PCAP analysis

Usage:
    from backend.database import Database
    db = Database()
    db.insert_alert(alert_dict)
    alerts = db.get_alerts()
"""

import sqlite3
import os
import json
from datetime import datetime, timezone


# Path to the SQLite database file (stored in the project root)
DB_DIR = os.path.join(os.path.dirname(__file__), "..")
DB_PATH = os.path.join(DB_DIR, "nsm_platform.db")


class Database:
    """Simple SQLite database wrapper for the NSM platform."""

    def __init__(self, db_path=None):
        """
        Initialize the database connection and create tables if needed.
        Args:
            db_path: Optional custom path to the .db file (useful for testing)
        """
        self.db_path = db_path or DB_PATH
        # For :memory: databases, keep one persistent connection (tables would vanish otherwise)
        self._memory_conn = None
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
        self.create_tables()

    def get_connection(self):
        """Returns a database connection.
        For :memory: returns the persistent connection so tables survive.
        For file-based databases opens a new connection each time.
        """
        if self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ──────────────────────────────────────────
    # TABLE CREATION
    # ──────────────────────────────────────────
    def create_tables(self):
        """Creates all required tables if they don't already exist."""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Table 1: Security Alerts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                details TEXT NOT NULL,
                confidence REAL NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Table 2: Traffic Statistics (per analysis run)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                total_packets INTEGER DEFAULT 0,
                tcp_count INTEGER DEFAULT 0,
                udp_count INTEGER DEFAULT 0,
                icmp_count INTEGER DEFAULT 0,
                other_count INTEGER DEFAULT 0,
                avg_packet_size REAL DEFAULT 0,
                unique_src_ips INTEGER DEFAULT 0,
                unique_dst_ips INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Table 3: Analysis Runs (tracks each PCAP upload/analysis)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                total_packets INTEGER DEFAULT 0,
                total_alerts INTEGER DEFAULT 0,
                status TEXT DEFAULT 'completed',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        if self._memory_conn is None:
            conn.close()

    # ──────────────────────────────────────────
    # INSERT OPERATIONS
    # ──────────────────────────────────────────
    def insert_alert(self, alert):
        """
        Inserts a single alert dictionary into the alerts table.
        Args:
            alert (dict): Alert dictionary matching the project schema
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO alerts
                (alert_id, timestamp, attack_type, severity, src_ip, dst_ip, details, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["alert_id"],
                alert["timestamp"],
                alert["attack_type"],
                alert["severity"],
                alert["src_ip"],
                alert["dst_ip"],
                alert["details"],
                alert["confidence"],
            ))
            conn.commit()
        finally:
            if self._memory_conn is None:
                conn.close()

    def insert_alerts_batch(self, alerts):
        """Inserts multiple alerts at once (more efficient)."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            for alert in alerts:
                cursor.execute("""
                    INSERT OR IGNORE INTO alerts
                    (alert_id, timestamp, attack_type, severity, src_ip, dst_ip, details, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert["alert_id"],
                    alert["timestamp"],
                    alert["attack_type"],
                    alert["severity"],
                    alert["src_ip"],
                    alert["dst_ip"],
                    alert["details"],
                    alert["confidence"],
                ))
            conn.commit()
        finally:
            if self._memory_conn is None:
                conn.close()

    def insert_traffic_stats(self, analysis_id, packets):
        """
        Calculates and stores traffic statistics from parsed packets.
        Args:
            analysis_id (str): Unique ID for this analysis run
            packets (list): List of parsed packet dictionaries
        """
        # Calculate statistics from the packet list
        total = len(packets)
        tcp_count = sum(1 for p in packets if p["protocol"] == "TCP")
        udp_count = sum(1 for p in packets if p["protocol"] == "UDP")
        icmp_count = sum(1 for p in packets if p["protocol"] == "ICMP")
        other_count = sum(1 for p in packets if p["protocol"] == "OTHER")
        avg_size = sum(p["length"] for p in packets) / total if total > 0 else 0
        unique_src = len(set(p["src_ip"] for p in packets))
        unique_dst = len(set(p["dst_ip"] for p in packets))

        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO traffic_stats
                (analysis_id, total_packets, tcp_count, udp_count, icmp_count,
                 other_count, avg_packet_size, unique_src_ips, unique_dst_ips)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (analysis_id, total, tcp_count, udp_count, icmp_count,
                  other_count, avg_size, unique_src, unique_dst))
            conn.commit()
        finally:
            if self._memory_conn is None:
                conn.close()

    def insert_analysis_run(self, analysis_id, filename, total_packets, total_alerts):
        """Records metadata about a completed analysis run."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO analysis_runs
                (analysis_id, filename, total_packets, total_alerts)
                VALUES (?, ?, ?, ?)
            """, (analysis_id, filename, total_packets, total_alerts))
            conn.commit()
        finally:
            if self._memory_conn is None:
                conn.close()

    # ──────────────────────────────────────────
    # QUERY OPERATIONS
    # ──────────────────────────────────────────
    def get_alerts(self, limit=50):
        """Returns the most recent alerts, ordered by timestamp (newest first)."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT alert_id, timestamp, attack_type, severity,
                       src_ip, dst_ip, details, confidence
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            if self._memory_conn is None:
                conn.close()

    def get_traffic_stats(self):
        """Returns the most recent traffic statistics."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT * FROM traffic_stats
                ORDER BY created_at DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            return dict(row) if row else {}
        finally:
            if self._memory_conn is None:
                conn.close()

    def get_summary(self):
        """
        Returns attack type counts for the dashboard summary cards.
        Output: {"port_scan": 12, "brute_force": 4, "syn_flood": 1, ...}
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT attack_type, COUNT(*) as count
                FROM alerts
                GROUP BY attack_type
            """)
            rows = cursor.fetchall()
            summary = {}
            for row in rows:
                summary[row["attack_type"]] = row["count"]
            return summary
        finally:
            if self._memory_conn is None:
                conn.close()

    def get_severity_counts(self):
        """Returns count of alerts grouped by severity level."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM alerts
                GROUP BY severity
            """)
            rows = cursor.fetchall()
            return {row["severity"]: row["count"] for row in rows}
        finally:
            if self._memory_conn is None:
                conn.close()

    def get_total_packets(self):
        """Returns the total number of packets analyzed across all runs."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT COALESCE(SUM(total_packets), 0) as total FROM traffic_stats")
            row = cursor.fetchone()
            return row["total"] if row else 0
        finally:
            if self._memory_conn is None:
                conn.close()

    def clear_all(self):
        """Clears all data from all tables. Useful for testing."""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM traffic_stats")
            cursor.execute("DELETE FROM analysis_runs")
            conn.commit()
        finally:
            if self._memory_conn is None:
                conn.close()


# ──────────────────────────────────────────
# SELF-TEST
# ──────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  DATABASE MODULE — SELF-TEST")
    print("=" * 50)

    db = Database()
    db.clear_all()

    # Test inserting an alert
    test_alert = {
        "alert_id": "test123",
        "timestamp": "2026-09-18T10:32:01.500Z",
        "attack_type": "port_scan",
        "severity": "high",
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "details": "Scanned 25 ports in 3 seconds",
        "confidence": 0.9,
    }
    db.insert_alert(test_alert)
    print("[+] Inserted test alert")

    # Test querying alerts
    alerts = db.get_alerts()
    assert len(alerts) == 1, f"Expected 1 alert, got {len(alerts)}"
    print(f"[+] Retrieved {len(alerts)} alert(s)")

    # Test summary
    summary = db.get_summary()
    assert summary.get("port_scan") == 1
    print(f"[+] Summary: {summary}")

    # Test traffic stats
    test_packets = [
        {"protocol": "TCP", "length": 60, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
        {"protocol": "UDP", "length": 40, "src_ip": "1.1.1.1", "dst_ip": "3.3.3.3"},
        {"protocol": "TCP", "length": 80, "src_ip": "4.4.4.4", "dst_ip": "2.2.2.2"},
    ]
    db.insert_traffic_stats("test-run-1", test_packets)
    stats = db.get_traffic_stats()
    print(f"[+] Traffic stats: TCP={stats['tcp_count']}, UDP={stats['udp_count']}, Total={stats['total_packets']}")

    # Cleanup
    db.clear_all()
    print("\n[+] ALL DATABASE TESTS PASSED!")
