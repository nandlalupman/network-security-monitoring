"""
Integration Test: PCAP Parser -> Detection Engine (Step 6)
===========================================================
This script connects Person 1's parser with Person 2's detector
and runs the full pipeline on sample.pcap.

Usage:
    python test_pipeline.py
    python test_pipeline.py path/to/your.pcap
"""

import json
import sys
import os

# Add project root to Python path so imports work
sys.path.insert(0, os.path.dirname(__file__))

from capture.packet_parser import parse_pcap
from detection.detector import detect_all


def run_pipeline(pcap_path):
    """
    Complete pipeline: PCAP file -> parse packets -> detect attacks -> print results
    """
    print("=" * 60)
    print("  NSM PLATFORM - INTEGRATION TEST")
    print("  PCAP -> Parser -> Detection Engine")
    print("=" * 60)

    # Step 1: Parse the PCAP file
    print(f"\n[STEP 1] Parsing PCAP: {pcap_path}")
    print("-" * 40)
    packets = parse_pcap(pcap_path)

    # Step 2: Run detection on parsed packets
    print(f"\n[STEP 2] Running detection rules...")
    print("-" * 40)
    alerts = detect_all(packets)

    # Step 3: Display results
    print(f"\n[STEP 3] Results")
    print("-" * 40)

    if not alerts:
        print("  No attacks detected. Traffic appears normal.")
        return alerts

    # Count by attack type
    summary = {}
    for alert in alerts:
        attack = alert["attack_type"]
        summary[attack] = summary.get(attack, 0) + 1

    print(f"\n  Attack Summary:")
    for attack_type, count in summary.items():
        print(f"    {attack_type}: {count}")

    print(f"\n  Detailed Alerts:")
    print(f"  {'='*56}")
    for i, alert in enumerate(alerts, 1):
        print(f"\n  Alert #{i}")
        print(f"    Type:       {alert['attack_type'].upper()}")
        print(f"    Severity:   {alert['severity'].upper()}")
        print(f"    Source IP:  {alert['src_ip']}")
        print(f"    Target IP:  {alert['dst_ip']}")
        print(f"    Details:    {alert['details']}")
        print(f"    Confidence: {alert['confidence']:.0%}")
        print(f"    Time:       {alert['timestamp']}")

    print(f"\n{'='*60}")
    print(f"  Pipeline complete! {len(alerts)} alert(s) from {len(packets)} packets.")
    print(f"{'='*60}")

    return alerts


if __name__ == "__main__":
    # Default PCAP path
    pcap_file = os.path.join("sample_pcaps", "sample.pcap")

    # Allow override from command line
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]

    if not os.path.exists(pcap_file):
        print(f"[-] File not found: {pcap_file}")
        print("    Run 'python sample_pcaps/generate_sample_pcap.py' first.")
        sys.exit(1)

    alerts = run_pipeline(pcap_file)
