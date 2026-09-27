"""
Packet Parser Module (Person 1)
================================
Reads PCAP files using Scapy and converts raw packets into
standardized Python dictionaries matching the project schema.

Usage:
    from capture.packet_parser import parse_pcap
    packets = parse_pcap("sample_pcaps/sample.pcap")

Each returned packet dictionary looks like:
{
    "timestamp": "2026-09-18T10:32:01.123456",
    "src_ip": "192.168.1.5",
    "dst_ip": "10.0.0.1",
    "src_port": 443,
    "dst_port": 22,
    "protocol": "TCP",
    "flags": "SYN",
    "length": 60
}
"""

from datetime import datetime, timezone
from scapy.all import rdpcap, IP, TCP, UDP, ICMP


# ──────────────────────────────────────────────
# Helper: Convert Scapy TCP flag bits to a readable string
# ──────────────────────────────────────────────
def get_tcp_flags(tcp_layer):
    """
    Scapy stores TCP flags as a single value (e.g. 0x02 = SYN).
    This function converts it to a human-readable string like
    'SYN', 'ACK', 'SYN-ACK', 'FIN', etc.
    """
    flag_names = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
    }

    # Scapy gives us flags as a FlagValue; str() gives letters like "SA"
    raw_flags = str(tcp_layer.flags)
    readable = []
    for letter in raw_flags:
        if letter in flag_names:
            readable.append(flag_names[letter])

    if not readable:
        return ""
    return "-".join(readable)


# ──────────────────────────────────────────────
# Core: Parse a single Scapy packet → dictionary
# ──────────────────────────────────────────────
def parse_packet(pkt):
    """
    Converts one Scapy packet object into a clean dictionary.
    Returns None if the packet has no IP layer (e.g. ARP-only frames).
    """
    # Skip packets without an IP layer
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]

    # Start building the packet dictionary
    packet_dict = {
        "timestamp": datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
        "flags": "",
        "length": len(pkt),
    }

    # Fill in protocol-specific fields
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        packet_dict["protocol"] = "TCP"
        packet_dict["src_port"] = tcp.sport
        packet_dict["dst_port"] = tcp.dport
        packet_dict["flags"] = get_tcp_flags(tcp)

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        packet_dict["protocol"] = "UDP"
        packet_dict["src_port"] = udp.sport
        packet_dict["dst_port"] = udp.dport

    elif pkt.haslayer(ICMP):
        packet_dict["protocol"] = "ICMP"

    return packet_dict


# ──────────────────────────────────────────────
# Main: Parse an entire PCAP file → list of dicts
# ──────────────────────────────────────────────
def parse_pcap(filepath):
    """
    Reads a .pcap file from disk and returns a list of
    packet dictionaries that follow the project schema.

    Args:
        filepath (str): Path to the .pcap file

    Returns:
        list[dict]: List of parsed packet dictionaries
    """
    print(f"[*] Reading PCAP file: {filepath}")
    raw_packets = rdpcap(filepath)
    print(f"[*] Total raw packets read: {len(raw_packets)}")

    parsed = []
    skipped = 0

    for pkt in raw_packets:
        result = parse_packet(pkt)
        if result is not None:
            parsed.append(result)
        else:
            skipped += 1

    print(f"[+] Successfully parsed: {len(parsed)} packets")
    if skipped > 0:
        print(f"[!] Skipped {skipped} non-IP packets (ARP, etc.)")

    return parsed


# ──────────────────────────────────────────────
# Self-test: Run this file directly to test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import sys
    import os

    # Default to the sample PCAP in the project
    pcap_path = os.path.join(os.path.dirname(__file__), "..", "sample_pcaps", "sample.pcap")

    # Allow overriding via command-line argument
    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]

    if not os.path.exists(pcap_path):
        print(f"[-] PCAP file not found: {pcap_path}")
        print("    Run 'python sample_pcaps/generate_sample_pcap.py' first to create it.")
        sys.exit(1)

    packets = parse_pcap(pcap_path)

    # Print first 5 packets for quick visual verification
    print("\n--- First 5 Parsed Packets ---")
    for i, pkt in enumerate(packets[:5]):
        print(json.dumps(pkt, indent=2))
        if i < 4:
            print("---")

    # Summary statistics
    protocols = {}
    for pkt in packets:
        proto = pkt["protocol"]
        protocols[proto] = protocols.get(proto, 0) + 1

    print(f"\n--- Protocol Summary ---")
    for proto, count in sorted(protocols.items()):
        print(f"  {proto}: {count}")
    print(f"  TOTAL: {len(packets)}")
