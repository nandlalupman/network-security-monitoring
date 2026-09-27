"""
Test Cases -- NSM Platform (Person 3)
======================================
Comprehensive test cases for all detection rules.
Run this file to verify the entire detection system is working correctly.

Usage:
    python tests/test_cases.py
"""

import sys
import os
import json

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.detector import detect_port_scan, detect_syn_flood, detect_brute_force, detect_all
from anomaly.extra_rules import detect_suspicious_traffic, detect_icmp_sweep, detect_extra
from backend.database import Database
from schema.validate_schema import validate_packet, validate_alert

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
PASS = "[PASS]"
FAIL = "[FAIL]"
results = []


def run_test(name, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, name, detail))
    print(f"  {status} {name}" + (f" -- {detail}" if detail else ""))


def make_tcp_pkt(src, dst, sport, dport, flags="SYN", ts="2026-09-18T10:00:00.000000+00:00", length=54):
    return {
        "timestamp": ts,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": "TCP",
        "flags": flags,
        "length": length,
    }


def make_icmp_pkt(src, dst, ts="2026-09-18T10:00:00.000000+00:00"):
    return {
        "timestamp": ts,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": None,
        "dst_port": None,
        "protocol": "ICMP",
        "flags": "",
        "length": 64,
    }


# ═══════════════════════════════════════════════
# SECTION 1: Schema Validation Tests
# ═══════════════════════════════════════════════
def test_schema():
    print("\n[Section 1] Schema Validation Tests")
    print("-" * 50)

    # Valid packet
    try:
        p = make_tcp_pkt("1.1.1.1", "2.2.2.2", 1234, 80)
        validate_packet(p)
        run_test("Valid packet passes schema", True)
    except Exception as e:
        run_test("Valid packet passes schema", False, str(e))

    # Missing field
    try:
        bad = {"src_ip": "1.1.1.1"}
        validate_packet(bad)
        run_test("Incomplete packet rejected", False, "Should have raised ValueError")
    except ValueError:
        run_test("Incomplete packet rejected", True)

    # Valid alert
    try:
        alert = {
            "alert_id": "abc123",
            "timestamp": "2026-09-18T10:00:00Z",
            "attack_type": "port_scan",
            "severity": "high",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "details": "25 ports in 3 seconds",
            "confidence": 0.9,
        }
        validate_alert(alert)
        run_test("Valid alert passes schema", True)
    except Exception as e:
        run_test("Valid alert passes schema", False, str(e))

    # Bad confidence
    try:
        alert["confidence"] = 1.5
        validate_alert(alert)
        run_test("Bad confidence value rejected", False, "Should have raised ValueError")
    except ValueError:
        run_test("Bad confidence value rejected", True)


# ═══════════════════════════════════════════════
# SECTION 2: Port Scan Detection Tests
# ═══════════════════════════════════════════════
def test_port_scan():
    print("\n[Section 2] Port Scan Detection Tests")
    print("-" * 50)

    # TRUE POSITIVE: 15 ports in 2 seconds
    packets = [make_tcp_pkt("10.0.0.1", "192.168.1.1", 50000 + i, 20 + i,
                             ts=f"2026-09-18T10:00:0{i//10}.{i%10}00000+00:00")
               for i in range(15)]
    alerts = detect_port_scan(packets)
    run_test("Port scan: 15 ports -> 1 alert", len(alerts) == 1,
             f"Got {len(alerts)} alerts")

    # Check alert format
    if alerts:
        a = alerts[0]
        run_test("Port scan alert has correct attack_type",
                 a["attack_type"] == "port_scan")
        run_test("Port scan alert has correct severity",
                 a["severity"] == "high")
        run_test("Port scan alert has correct src_ip",
                 a["src_ip"] == "10.0.0.1")
        run_test("Port scan details mention ports",
                 "port" in a["details"].lower())

    # TRUE NEGATIVE: only 5 ports (below threshold of 10)
    few_packets = [make_tcp_pkt("10.0.0.2", "192.168.1.1", 50000 + i, 100 + i)
                   for i in range(5)]
    alerts_neg = detect_port_scan(few_packets)
    run_test("Port scan: 5 ports -> no alert (true negative)",
             len(alerts_neg) == 0, f"Got {len(alerts_neg)} alerts")

    # TRUE NEGATIVE: 15 ports but spread over 60 seconds (outside window)
    # Each packet is 4 seconds apart, so 15 packets = 56 seconds total
    slow_packets = [make_tcp_pkt("10.0.0.3", "192.168.1.1", 50000 + i, 200 + i,
                                 ts=f"2026-09-18T10:{(i * 4) // 60:02d}:{(i * 4) % 60:02d}.000000+00:00")
                    for i in range(15)]
    alerts_slow = detect_port_scan(slow_packets)
    run_test("Port scan: 15 ports over 60s -> no alert (slow scan)",
             len(alerts_slow) == 0, f"Got {len(alerts_slow)} alerts")


# ═══════════════════════════════════════════════
# SECTION 3: SYN Flood Detection Tests
# ═══════════════════════════════════════════════
def test_syn_flood():
    print("\n[Section 3] SYN Flood Detection Tests")
    print("-" * 50)

    # TRUE POSITIVE: 25 SYNs to port 80 in 3 seconds
    packets = [make_tcp_pkt("10.0.0.1", "192.168.1.1", 50000 + i, 80, "SYN",
                             ts=f"2026-09-18T10:00:0{i//10}.{i%10}00000+00:00")
               for i in range(25)]
    alerts = detect_syn_flood(packets)
    run_test("SYN flood: 25 SYNs to port 80 -> 1 alert", len(alerts) == 1,
             f"Got {len(alerts)} alerts")

    if alerts:
        a = alerts[0]
        run_test("SYN flood alert has correct attack_type",
                 a["attack_type"] == "syn_flood")
        run_test("SYN flood alert severity is critical",
                 a["severity"] == "critical")
        run_test("SYN flood details mention SYN",
                 "SYN" in a["details"])

    # TRUE NEGATIVE: SYN-ACK packets (normal handshake, not a flood)
    synack_packets = [make_tcp_pkt("10.0.0.2", "192.168.1.1", 50000 + i, 80, "SYN-ACK",
                                   ts=f"2026-09-18T10:00:0{i//10}.{i%10}00000+00:00")
                      for i in range(25)]
    alerts_synack = detect_syn_flood(synack_packets)
    run_test("SYN flood: SYN-ACK packets do not trigger (true negative)",
             len(alerts_synack) == 0, f"Got {len(alerts_synack)} alerts")

    # TRUE NEGATIVE: only 10 SYNs (below threshold of 20)
    few_syns = [make_tcp_pkt("10.0.0.3", "192.168.1.1", 50000 + i, 443, "SYN")
                for i in range(10)]
    alerts_few = detect_syn_flood(few_syns)
    run_test("SYN flood: 10 SYNs -> no alert (true negative)",
             len(alerts_few) == 0, f"Got {len(alerts_few)} alerts")


# ═══════════════════════════════════════════════
# SECTION 4: Brute Force Detection Tests
# ═══════════════════════════════════════════════
def test_brute_force():
    print("\n[Section 4] Brute Force Detection Tests")
    print("-" * 50)

    # TRUE POSITIVE: 12 SSH attempts in 10 seconds
    packets = [make_tcp_pkt("10.0.0.1", "192.168.1.1", 50000 + i, 22, "SYN",
                             ts=f"2026-09-18T10:00:0{i//10}.{i%10}00000+00:00")
               for i in range(12)]
    alerts = detect_brute_force(packets)
    run_test("Brute force: 12 SSH attempts -> 1 alert", len(alerts) == 1,
             f"Got {len(alerts)} alerts")

    if alerts:
        a = alerts[0]
        run_test("Brute force alert has correct attack_type",
                 a["attack_type"] == "brute_force")
        run_test("Brute force details mention SSH",
                 "SSH" in a["details"])
        run_test("Brute force alert has high severity",
                 a["severity"] == "high")

    # TRUE POSITIVE: RDP brute force (port 3389)
    rdp_packets = [make_tcp_pkt("10.0.0.2", "192.168.1.1", 50000 + i, 3389, "SYN",
                                ts=f"2026-09-18T10:00:0{i//10}.{i%10}00000+00:00")
                   for i in range(10)]
    alerts_rdp = detect_brute_force(rdp_packets)
    run_test("Brute force: 10 RDP attempts -> 1 alert", len(alerts_rdp) == 1,
             f"Got {len(alerts_rdp)} alerts")

    # TRUE NEGATIVE: SSH on non-login port (port 8080 -- not in login ports list)
    normal_packets = [make_tcp_pkt("10.0.0.3", "192.168.1.1", 50000 + i, 8080, "SYN",
                                   ts=f"2026-09-18T10:00:0{i//10}.{i%10}00000+00:00")
                      for i in range(12)]
    alerts_norm = detect_brute_force(normal_packets)
    run_test("Brute force: connections to port 8080 -> no alert (true negative)",
             len(alerts_norm) == 0, f"Got {len(alerts_norm)} alerts")


# ═══════════════════════════════════════════════
# SECTION 5: Extra Rules Tests
# ═══════════════════════════════════════════════
def test_extra_rules():
    print("\n[Section 5] Extra Rules Tests")
    print("-" * 50)

    # Suspicious: large packet
    large_pkt = make_tcp_pkt("1.1.1.1", "2.2.2.2", 1234, 80, length=2000)
    alerts = detect_suspicious_traffic([large_pkt])
    run_test("Suspicious traffic: large packet (2000 bytes) flagged", len(alerts) == 1,
             f"Got {len(alerts)} alerts")

    # Suspicious: unusual protocol
    weird_pkt = {**make_tcp_pkt("1.1.1.1", "2.2.2.2", 1234, 80), "protocol": "OTHER"}
    alerts2 = detect_suspicious_traffic([weird_pkt])
    run_test("Suspicious traffic: OTHER protocol flagged", len(alerts2) == 1,
             f"Got {len(alerts2)} alerts")

    # Normal-size TCP packet should NOT be flagged
    normal_pkt = make_tcp_pkt("1.1.1.1", "2.2.2.2", 1234, 80, length=100)
    alerts3 = detect_suspicious_traffic([normal_pkt])
    run_test("Suspicious traffic: normal packet not flagged (true negative)",
             len(alerts3) == 0, f"Got {len(alerts3)} alerts")

    # ICMP sweep: 6 different targets
    icmp_pkts = [make_icmp_pkt("10.0.0.1", f"192.168.1.{i}",
                               ts=f"2026-09-18T10:00:0{i}.000000+00:00")
                 for i in range(6)]
    alerts4 = detect_icmp_sweep(icmp_pkts)
    run_test("ICMP sweep: 6 unique targets -> 1 alert", len(alerts4) == 1,
             f"Got {len(alerts4)} alerts")


# ═══════════════════════════════════════════════
# SECTION 6: Database Tests
# ═══════════════════════════════════════════════
def test_database():
    print("\n[Section 6] Database Tests")
    print("-" * 50)

    # Use a temporary in-memory database for testing
    db = Database(db_path=":memory:")

    # Insert an alert
    test_alert = {
        "alert_id": "testdb01",
        "timestamp": "2026-09-18T10:00:00Z",
        "attack_type": "port_scan",
        "severity": "high",
        "src_ip": "10.0.0.1",
        "dst_ip": "192.168.1.1",
        "details": "Test alert",
        "confidence": 0.9,
    }
    db.insert_alert(test_alert)
    alerts = db.get_alerts()
    run_test("Database: insert and retrieve 1 alert", len(alerts) == 1,
             f"Got {len(alerts)} alerts")

    # Duplicate alert_id should be ignored (INSERT OR IGNORE)
    db.insert_alert(test_alert)
    alerts2 = db.get_alerts()
    run_test("Database: duplicate alert_id ignored", len(alerts2) == 1,
             f"Got {len(alerts2)} alerts")

    # Summary count
    summary = db.get_summary()
    run_test("Database: summary counts port_scan correctly",
             summary.get("port_scan") == 1, f"Summary: {summary}")

    # Traffic stats
    packets = [
        {"protocol": "TCP", "length": 60, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
        {"protocol": "UDP", "length": 40, "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4"},
    ]
    db.insert_traffic_stats("run-001", packets)
    stats = db.get_traffic_stats()
    run_test("Database: traffic stats stored correctly",
             stats["tcp_count"] == 1 and stats["udp_count"] == 1,
             f"TCP={stats.get('tcp_count')}, UDP={stats.get('udp_count')}")

    # Clear
    db.clear_all()
    run_test("Database: clear_all removes all records",
             len(db.get_alerts()) == 0, f"Got {len(db.get_alerts())} alerts after clear")


# ═══════════════════════════════════════════════
# SECTION 7: Full Pipeline Integration Test
# ═══════════════════════════════════════════════
def test_full_pipeline():
    print("\n[Section 7] Full Pipeline Integration Test")
    print("-" * 50)

    # Build a mixed packet list (normal + attack)
    all_packets = []

    # Normal traffic (no alerts expected for these)
    for i in range(3):
        all_packets.append(make_tcp_pkt(f"192.168.1.{i}", "10.0.0.1", 50000 + i, 443, "ACK"))

    # Port scan
    for i in range(12):
        all_packets.append(make_tcp_pkt("172.16.0.100", "10.0.0.1", 60000 + i, 100 + i, "SYN",
                                        ts=f"2026-09-18T10:00:0{i//10}.{i%10}00000+00:00"))

    # SYN flood
    for i in range(22):
        all_packets.append(make_tcp_pkt("172.16.0.200", "10.0.0.2", 50000 + i, 80, "SYN",
                                        ts=f"2026-09-18T10:00:0{i//10}.{i%10}00000+00:00"))

    # Run all detectors
    alerts = detect_all(all_packets)

    run_test("Pipeline: detects port scan from mixed traffic",
             any(a["attack_type"] == "port_scan" for a in alerts))
    run_test("Pipeline: detects SYN flood from mixed traffic",
             any(a["attack_type"] == "syn_flood" for a in alerts))
    run_test("Pipeline: normal traffic does NOT generate false positives",
             not any(a["src_ip"].startswith("192.168.1.") for a in alerts))
    run_test("Pipeline: all alerts have required fields",
             all({"alert_id", "attack_type", "severity", "src_ip", "dst_ip", "details", "confidence"}.issubset(a.keys())
                 for a in alerts))


# ═══════════════════════════════════════════════
# MAIN -- Run all tests
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  NSM PLATFORM -- COMPLETE TEST SUITE")
    print("=" * 60)

    test_schema()
    test_port_scan()
    test_syn_flood()
    test_brute_force()
    test_extra_rules()
    test_database()
    test_full_pipeline()

    # Final summary
    passed = sum(1 for r in results if r[0] == PASS)
    failed = sum(1 for r in results if r[0] == FAIL)
    total = len(results)

    print("\n" + "=" * 60)
    print(f"  TEST RESULTS: {passed}/{total} passed", end="")
    if failed:
        print(f"  |  {failed} FAILED")
        print("\n  Failed tests:")
        for r in results:
            if r[0] == FAIL:
                print(f"    - {r[1]}: {r[2]}")
    else:
        print()
        print("  ALL TESTS PASSED!")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
