"""
Detection Engine Module (Person 2)
====================================
Implements simple rule-based detection for three attack types:
  1. Port Scan   — One IP hits many different ports on a target
  2. SYN Flood   — One IP sends excessive SYN packets to a target
  3. Brute Force — One IP makes many connection attempts to a login port

How it works:
  1. Receive a list of parsed packet dictionaries (from packet_parser)
  2. Group packets by source IP and time windows
  3. Apply simple threshold-based rules
  4. Return a list of alert dictionaries matching the project schema

Usage:
    from detection.detector import detect_all
    alerts = detect_all(parsed_packets)
"""

import uuid
from datetime import datetime, timezone


# ============================================================
# CONFIGURABLE THRESHOLDS (easy to explain in a viva)
# ============================================================
# These numbers control when an alert is triggered.
# You can adjust them to reduce false positives/negatives.

PORT_SCAN_THRESHOLD = 10       # Number of unique ports to be considered a scan
PORT_SCAN_TIME_WINDOW = 10     # Seconds — scan must happen within this window

SYN_FLOOD_THRESHOLD = 20       # Number of SYN packets to be considered a flood
SYN_FLOOD_TIME_WINDOW = 10     # Seconds — SYNs must arrive within this window

BRUTE_FORCE_THRESHOLD = 8      # Number of connection attempts to trigger alert
BRUTE_FORCE_TIME_WINDOW = 30   # Seconds — attempts must happen within this window
BRUTE_FORCE_PORTS = [22, 23, 3389, 21, 3306, 5432]  # SSH, Telnet, RDP, FTP, MySQL, PostgreSQL


# ============================================================
# HELPER: Generate a unique alert ID
# ============================================================
def generate_alert_id():
    """Creates a short unique ID for each alert (first 8 chars of a UUID)."""
    return uuid.uuid4().hex[:8]


# ============================================================
# HELPER: Parse ISO timestamp string to a datetime object
# ============================================================
def parse_timestamp(ts_string):
    """
    Converts an ISO 8601 timestamp string to a datetime object.
    Example: "2026-09-26T18:41:34.510001+00:00" -> datetime object
    """
    # Handle both formats: with timezone and without
    try:
        return datetime.fromisoformat(ts_string)
    except ValueError:
        # Fallback: try replacing Z with +00:00
        return datetime.fromisoformat(ts_string.replace("Z", "+00:00"))


# ============================================================
# RULE 1: Port Scan Detection
# ============================================================
def detect_port_scan(packets):
    """
    RULE: If one source IP connects to more than PORT_SCAN_THRESHOLD
    different destination ports on the SAME target within
    PORT_SCAN_TIME_WINDOW seconds → Port Scan detected.

    How it works:
      1. Group packets by (src_ip, dst_ip) pair
      2. Sort each group by timestamp
      3. Use a sliding window to count unique destination ports
      4. If unique ports exceed threshold → generate alert
    """
    alerts = []

    # Step 1: Group packets by (source IP, destination IP)
    groups = {}
    for pkt in packets:
        key = (pkt["src_ip"], pkt["dst_ip"])
        if key not in groups:
            groups[key] = []
        groups[key].append(pkt)

    # Step 2: Check each group for port scanning behavior
    for (src_ip, dst_ip), group_packets in groups.items():
        # Only check TCP packets (port scans use TCP SYN)
        tcp_packets = [p for p in group_packets if p["protocol"] == "TCP" and p["dst_port"] is not None]

        if len(tcp_packets) < PORT_SCAN_THRESHOLD:
            continue  # Not enough packets to be a scan

        # Sort by time
        tcp_packets.sort(key=lambda p: p["timestamp"])

        # Step 3: Sliding window — check consecutive packets
        for i in range(len(tcp_packets)):
            start_time = parse_timestamp(tcp_packets[i]["timestamp"])
            unique_ports = set()

            for j in range(i, len(tcp_packets)):
                end_time = parse_timestamp(tcp_packets[j]["timestamp"])
                time_diff = (end_time - start_time).total_seconds()

                if time_diff > PORT_SCAN_TIME_WINDOW:
                    break  # Outside the time window

                unique_ports.add(tcp_packets[j]["dst_port"])

            # Step 4: Check threshold
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                # Calculate time span for the details message
                first_time = parse_timestamp(tcp_packets[i]["timestamp"])
                last_relevant = None
                for j in range(i, len(tcp_packets)):
                    if (parse_timestamp(tcp_packets[j]["timestamp"]) - first_time).total_seconds() <= PORT_SCAN_TIME_WINDOW:
                        last_relevant = tcp_packets[j]
                time_span = (parse_timestamp(last_relevant["timestamp"]) - first_time).total_seconds()

                alert = {
                    "alert_id": generate_alert_id(),
                    "timestamp": tcp_packets[i]["timestamp"],
                    "attack_type": "port_scan",
                    "severity": "high",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "details": f"Scanned {len(unique_ports)} ports in {time_span:.1f} seconds",
                    "confidence": min(len(unique_ports) / (PORT_SCAN_THRESHOLD * 2), 1.0),
                }
                alerts.append(alert)
                break  # One alert per (src, dst) pair is enough

    return alerts


# ============================================================
# RULE 2: SYN Flood Detection
# ============================================================
def detect_syn_flood(packets):
    """
    RULE: If one source IP sends more than SYN_FLOOD_THRESHOLD
    SYN packets to the SAME target+port within SYN_FLOOD_TIME_WINDOW
    seconds → SYN Flood detected.

    How it works:
      1. Filter for TCP packets with the SYN flag
      2. Group by (src_ip, dst_ip, dst_port)
      3. Count SYNs in a sliding time window
      4. If count exceeds threshold → generate alert
    """
    alerts = []

    # Step 1: Filter SYN-only packets
    syn_packets = [
        p for p in packets
        if p["protocol"] == "TCP" and "SYN" in p.get("flags", "") and "ACK" not in p.get("flags", "")
    ]

    # Step 2: Group by (src_ip, dst_ip, dst_port)
    groups = {}
    for pkt in syn_packets:
        key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
        if key not in groups:
            groups[key] = []
        groups[key].append(pkt)

    # Step 3: Check each group
    for (src_ip, dst_ip, dst_port), group_packets in groups.items():
        if len(group_packets) < SYN_FLOOD_THRESHOLD:
            continue

        # Sort by time
        group_packets.sort(key=lambda p: p["timestamp"])

        # Sliding window
        for i in range(len(group_packets)):
            start_time = parse_timestamp(group_packets[i]["timestamp"])
            count = 0

            for j in range(i, len(group_packets)):
                end_time = parse_timestamp(group_packets[j]["timestamp"])
                time_diff = (end_time - start_time).total_seconds()

                if time_diff > SYN_FLOOD_TIME_WINDOW:
                    break
                count += 1

            # Step 4: Check threshold
            if count >= SYN_FLOOD_THRESHOLD:
                time_span = (parse_timestamp(group_packets[min(i + count - 1, len(group_packets) - 1)]["timestamp"]) - start_time).total_seconds()

                alert = {
                    "alert_id": generate_alert_id(),
                    "timestamp": group_packets[i]["timestamp"],
                    "attack_type": "syn_flood",
                    "severity": "critical",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "details": f"{count} SYN packets to port {dst_port} in {time_span:.1f} seconds",
                    "confidence": min(count / (SYN_FLOOD_THRESHOLD * 2), 1.0),
                }
                alerts.append(alert)
                break  # One alert per group

    return alerts


# ============================================================
# RULE 3: Brute Force Detection
# ============================================================
def detect_brute_force(packets):
    """
    RULE: If one source IP makes more than BRUTE_FORCE_THRESHOLD
    connection attempts to a known login port (SSH, RDP, etc.)
    on the same target within BRUTE_FORCE_TIME_WINDOW seconds
    → Brute Force detected.

    How it works:
      1. Filter TCP packets going to known login ports (22, 23, 3389, etc.)
      2. Group by (src_ip, dst_ip, dst_port)
      3. Count connections in a time window
      4. If count exceeds threshold → generate alert
    """
    alerts = []

    # Step 1: Filter packets to known login service ports
    login_packets = [
        p for p in packets
        if p["protocol"] == "TCP" and p["dst_port"] in BRUTE_FORCE_PORTS
    ]

    # Step 2: Group by (src_ip, dst_ip, dst_port)
    groups = {}
    for pkt in login_packets:
        key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
        if key not in groups:
            groups[key] = []
        groups[key].append(pkt)

    # Step 3: Check each group
    for (src_ip, dst_ip, dst_port), group_packets in groups.items():
        if len(group_packets) < BRUTE_FORCE_THRESHOLD:
            continue

        # Sort by time
        group_packets.sort(key=lambda p: p["timestamp"])

        # Sliding window
        for i in range(len(group_packets)):
            start_time = parse_timestamp(group_packets[i]["timestamp"])
            count = 0

            for j in range(i, len(group_packets)):
                end_time = parse_timestamp(group_packets[j]["timestamp"])
                time_diff = (end_time - start_time).total_seconds()

                if time_diff > BRUTE_FORCE_TIME_WINDOW:
                    break
                count += 1

            # Step 4: Check threshold
            if count >= BRUTE_FORCE_THRESHOLD:
                # Map port numbers to service names for readability
                service_names = {22: "SSH", 23: "Telnet", 3389: "RDP", 21: "FTP", 3306: "MySQL", 5432: "PostgreSQL"}
                service = service_names.get(dst_port, f"port {dst_port}")
                time_span = (parse_timestamp(group_packets[min(i + count - 1, len(group_packets) - 1)]["timestamp"]) - start_time).total_seconds()

                alert = {
                    "alert_id": generate_alert_id(),
                    "timestamp": group_packets[i]["timestamp"],
                    "attack_type": "brute_force",
                    "severity": "high",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "details": f"{count} {service} login attempts in {time_span:.1f} seconds",
                    "confidence": min(count / (BRUTE_FORCE_THRESHOLD * 2), 1.0),
                }
                alerts.append(alert)
                break  # One alert per group

    return alerts


# ============================================================
# MAIN FUNCTION: Run all detection rules
# ============================================================
def detect_all(packets):
    """
    Runs ALL detection rules on a list of parsed packets.
    Returns a combined list of alert dictionaries.

    Args:
        packets (list[dict]): Parsed packet dictionaries from packet_parser

    Returns:
        list[dict]: List of alert dictionaries matching the alert schema
    """
    all_alerts = []

    print("[*] Running Port Scan detection...")
    port_scan_alerts = detect_port_scan(packets)
    print(f"    Found {len(port_scan_alerts)} port scan alert(s)")
    all_alerts.extend(port_scan_alerts)

    print("[*] Running SYN Flood detection...")
    syn_flood_alerts = detect_syn_flood(packets)
    print(f"    Found {len(syn_flood_alerts)} SYN flood alert(s)")
    all_alerts.extend(syn_flood_alerts)

    print("[*] Running Brute Force detection...")
    brute_force_alerts = detect_brute_force(packets)
    print(f"    Found {len(brute_force_alerts)} brute force alert(s)")
    all_alerts.extend(brute_force_alerts)

    print(f"\n[+] Total alerts generated: {len(all_alerts)}")
    return all_alerts


# ============================================================
# SELF-TEST: Run this file directly with manually created data
# ============================================================
if __name__ == "__main__":
    import json

    print("=" * 60)
    print("  DETECTION ENGINE — SELF-TEST WITH MANUAL DATA")
    print("=" * 60)

    # -------------------------------------------
    # Test 1: Port Scan (15 different ports in 2 seconds)
    # -------------------------------------------
    print("\n--- Test 1: Port Scan ---")
    scan_packets = []
    for i in range(15):
        scan_packets.append({
            "timestamp": f"2026-09-18T10:00:0{i // 10}.{i % 10}00000+00:00",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 50000 + i,
            "dst_port": 20 + i,   # 15 different destination ports
            "protocol": "TCP",
            "flags": "SYN",
            "length": 54,
        })
    scan_alerts = detect_port_scan(scan_packets)
    print(f"  Result: {len(scan_alerts)} alert(s)")
    if scan_alerts:
        print(f"  Details: {scan_alerts[0]['details']}")
    assert len(scan_alerts) == 1, "FAILED: Expected 1 port scan alert"
    print("  PASSED!")

    # -------------------------------------------
    # Test 2: SYN Flood (25 SYNs to same port in 3 seconds)
    # -------------------------------------------
    print("\n--- Test 2: SYN Flood ---")
    flood_packets = []
    for i in range(25):
        flood_packets.append({
            "timestamp": f"2026-09-18T10:00:0{i // 10}.{i % 10}00000+00:00",
            "src_ip": "192.168.1.200",
            "dst_ip": "10.0.0.2",
            "src_port": 40000 + i,
            "dst_port": 80,       # ALL going to the same port
            "protocol": "TCP",
            "flags": "SYN",
            "length": 54,
        })
    flood_alerts = detect_syn_flood(flood_packets)
    print(f"  Result: {len(flood_alerts)} alert(s)")
    if flood_alerts:
        print(f"  Details: {flood_alerts[0]['details']}")
    assert len(flood_alerts) == 1, "FAILED: Expected 1 SYN flood alert"
    print("  PASSED!")

    # -------------------------------------------
    # Test 3: Brute Force (12 SSH attempts in 10 seconds)
    # -------------------------------------------
    print("\n--- Test 3: Brute Force ---")
    brute_packets = []
    for i in range(12):
        brute_packets.append({
            "timestamp": f"2026-09-18T10:00:0{i // 10}.{i % 10}00000+00:00",
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "src_port": 60000 + i,
            "dst_port": 22,       # SSH port
            "protocol": "TCP",
            "flags": "SYN",
            "length": 54,
        })
    brute_alerts = detect_brute_force(brute_packets)
    print(f"  Result: {len(brute_alerts)} alert(s)")
    if brute_alerts:
        print(f"  Details: {brute_alerts[0]['details']}")
    assert len(brute_alerts) == 1, "FAILED: Expected 1 brute force alert"
    print("  PASSED!")

    # -------------------------------------------
    # Test 4: Normal traffic (should NOT trigger alerts)
    # -------------------------------------------
    print("\n--- Test 4: Normal Traffic (no alerts expected) ---")
    normal_packets = [
        {
            "timestamp": "2026-09-18T10:00:00.000000+00:00",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "src_port": 55000,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "SYN",
            "length": 54,
        },
        {
            "timestamp": "2026-09-18T10:00:05.000000+00:00",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "src_port": 55001,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "ACK",
            "length": 54,
        },
        {
            "timestamp": "2026-09-18T10:00:10.000000+00:00",
            "src_ip": "192.168.1.11",
            "dst_ip": "10.0.0.2",
            "src_port": 55002,
            "dst_port": 8080,
            "protocol": "TCP",
            "flags": "SYN-ACK",
            "length": 54,
        },
    ]
    normal_alerts = detect_all(normal_packets)
    assert len(normal_alerts) == 0, "FAILED: Expected 0 alerts for normal traffic"
    print("  PASSED! (0 false positives)")

    # -------------------------------------------
    # Summary
    # -------------------------------------------
    print("\n" + "=" * 60)
    print("  ALL 4 TESTS PASSED!")
    print("=" * 60)

    # Print a sample alert in full JSON format
    print("\n--- Sample Alert (JSON) ---")
    print(json.dumps(scan_alerts[0], indent=2))
