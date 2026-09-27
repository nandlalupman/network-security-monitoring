"""
Extra Detection Rules Module (Person 3)
=========================================
Adds additional simple detection rules beyond the core three.
Also used for testing, debugging, and integration support.

Additional Rules Implemented:
  1. Suspicious Traffic — Unusual protocols or very large packets
  2. ICMP Sweep        — One IP pinging many different targets (network recon)

Usage:
    from anomaly.extra_rules import detect_extra
    extra_alerts = detect_extra(parsed_packets)
"""

import uuid
from datetime import datetime, timezone


# ──────────────────────────────────────────
# CONFIGURABLE THRESHOLDS
# ──────────────────────────────────────────
LARGE_PACKET_SIZE = 1500         # Bytes — packets larger than this are flagged
ICMP_SWEEP_THRESHOLD = 5         # Number of unique IPs pinged to flag as sweep
ICMP_SWEEP_TIME_WINDOW = 30      # Seconds


def generate_alert_id():
    """Creates a short unique ID for each alert."""
    return uuid.uuid4().hex[:8]


def parse_timestamp(ts_string):
    """Converts ISO 8601 timestamp string to datetime object."""
    try:
        return datetime.fromisoformat(ts_string)
    except ValueError:
        return datetime.fromisoformat(ts_string.replace("Z", "+00:00"))


# ──────────────────────────────────────────
# RULE 4: Suspicious Traffic Detection
# ──────────────────────────────────────────
def detect_suspicious_traffic(packets):
    """
    RULE: Flag packets that use uncommon protocols (OTHER) or
    have unusually large sizes (> 1500 bytes).

    This is a simple anomaly rule that catches traffic that
    doesn't fit normal patterns.
    """
    alerts = []

    for pkt in packets:
        reasons = []

        # Check for unknown/unusual protocol
        if pkt["protocol"] == "OTHER":
            reasons.append("unusual protocol detected")

        # Check for oversized packets
        if pkt["length"] > LARGE_PACKET_SIZE:
            reasons.append(f"large packet size ({pkt['length']} bytes)")

        if reasons:
            alert = {
                "alert_id": generate_alert_id(),
                "timestamp": pkt["timestamp"],
                "attack_type": "suspicious_traffic",
                "severity": "low",
                "src_ip": pkt["src_ip"],
                "dst_ip": pkt["dst_ip"],
                "details": "; ".join(reasons),
                "confidence": 0.4,
            }
            alerts.append(alert)

    return alerts


# ──────────────────────────────────────────
# RULE 5: ICMP Sweep Detection
# ──────────────────────────────────────────
def detect_icmp_sweep(packets):
    """
    RULE: If one source IP sends ICMP packets to more than
    ICMP_SWEEP_THRESHOLD different destination IPs within a
    time window -> ICMP Sweep (network reconnaissance).
    """
    alerts = []

    # Filter ICMP packets
    icmp_packets = [p for p in packets if p["protocol"] == "ICMP"]

    if len(icmp_packets) < ICMP_SWEEP_THRESHOLD:
        return alerts

    # Group by source IP
    groups = {}
    for pkt in icmp_packets:
        src = pkt["src_ip"]
        if src not in groups:
            groups[src] = []
        groups[src].append(pkt)

    # Check each source IP
    for src_ip, group_packets in groups.items():
        group_packets.sort(key=lambda p: p["timestamp"])

        # Sliding window to count unique destination IPs
        for i in range(len(group_packets)):
            start_time = parse_timestamp(group_packets[i]["timestamp"])
            unique_targets = set()

            for j in range(i, len(group_packets)):
                end_time = parse_timestamp(group_packets[j]["timestamp"])
                if (end_time - start_time).total_seconds() > ICMP_SWEEP_TIME_WINDOW:
                    break
                unique_targets.add(group_packets[j]["dst_ip"])

            if len(unique_targets) >= ICMP_SWEEP_THRESHOLD:
                alert = {
                    "alert_id": generate_alert_id(),
                    "timestamp": group_packets[i]["timestamp"],
                    "attack_type": "suspicious_traffic",
                    "severity": "medium",
                    "src_ip": src_ip,
                    "dst_ip": "multiple targets",
                    "details": f"ICMP sweep: pinged {len(unique_targets)} unique IPs",
                    "confidence": 0.6,
                }
                alerts.append(alert)
                break

    return alerts


# ──────────────────────────────────────────
# MAIN: Run all extra detection rules
# ──────────────────────────────────────────
def detect_extra(packets):
    """
    Runs all additional detection rules.
    Returns a list of alert dictionaries.
    """
    all_alerts = []

    print("[*] Running Suspicious Traffic detection...")
    suspicious = detect_suspicious_traffic(packets)
    print(f"    Found {len(suspicious)} suspicious traffic alert(s)")
    all_alerts.extend(suspicious)

    print("[*] Running ICMP Sweep detection...")
    icmp = detect_icmp_sweep(packets)
    print(f"    Found {len(icmp)} ICMP sweep alert(s)")
    all_alerts.extend(icmp)

    return all_alerts


# ──────────────────────────────────────────
# SELF-TEST
# ──────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  EXTRA RULES — SELF-TEST")
    print("=" * 50)

    # Test suspicious traffic
    print("\n--- Test: Suspicious Traffic ---")
    test_pkts = [
        {
            "timestamp": "2026-09-18T10:00:00.000000+00:00",
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "src_port": None,
            "dst_port": None,
            "protocol": "OTHER",
            "flags": "",
            "length": 2000,
        }
    ]
    results = detect_suspicious_traffic(test_pkts)
    print(f"  Found {len(results)} alert(s)")
    assert len(results) == 1, "Expected 1 suspicious traffic alert"
    print("  PASSED!")

    # Test ICMP sweep
    print("\n--- Test: ICMP Sweep ---")
    icmp_pkts = []
    for i in range(6):
        icmp_pkts.append({
            "timestamp": f"2026-09-18T10:00:0{i}.000000+00:00",
            "src_ip": "192.168.1.100",
            "dst_ip": f"10.0.0.{i + 1}",
            "src_port": None,
            "dst_port": None,
            "protocol": "ICMP",
            "flags": "",
            "length": 64,
        })
    results = detect_icmp_sweep(icmp_pkts)
    print(f"  Found {len(results)} alert(s)")
    assert len(results) == 1, "Expected 1 ICMP sweep alert"
    print("  PASSED!")

    print("\n[+] ALL EXTRA RULE TESTS PASSED!")
