"""
Sample PCAP Generator
======================
Creates a realistic sample.pcap file containing simulated network traffic
with embedded attack patterns for testing the NSM platform.

Attacks embedded:
  1. Port Scan   – One IP rapidly connects to many ports on a target
  2. SYN Flood   – One IP sends many SYN packets to a single port
  3. Brute Force – One IP sends many connections to SSH port (22)

Run this script once to create sample_pcaps/sample.pcap:
    python sample_pcaps/generate_sample_pcap.py
"""

import os
import random
from scapy.all import IP, TCP, UDP, ICMP, wrpcap, Ether

# We will collect all packets here
packets = []

# Base timestamp (Scapy uses float epoch seconds)
import time
base_time = time.time() - 300  # Start 5 minutes ago


def make_tcp_packet(src, dst, sport, dport, flags="S", ts_offset=0):
    """Helper: create a simple TCP packet with a given timestamp."""
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    pkt.time = base_time + ts_offset
    return pkt


def make_udp_packet(src, dst, sport, dport, ts_offset=0):
    """Helper: create a simple UDP packet."""
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    pkt.time = base_time + ts_offset
    return pkt


def make_icmp_packet(src, dst, ts_offset=0):
    """Helper: create a simple ICMP ping packet."""
    pkt = Ether() / IP(src=src, dst=dst) / ICMP()
    pkt.time = base_time + ts_offset
    return pkt


# ──────────────────────────────────────────────
# 1. Normal background traffic (30 packets)
# ──────────────────────────────────────────────
print("[*] Generating normal background traffic...")
normal_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
normal_targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
normal_ports = [80, 443, 8080, 53, 8443]

for i in range(30):
    src = random.choice(normal_ips)
    dst = random.choice(normal_targets)
    dport = random.choice(normal_ports)
    sport = random.randint(49152, 65535)

    if random.random() < 0.7:
        # TCP traffic (majority)
        flags = random.choice(["S", "SA", "A", "PA", "FA"])
        packets.append(make_tcp_packet(src, dst, sport, dport, flags, ts_offset=i * 2))
    elif random.random() < 0.5:
        # UDP traffic
        packets.append(make_udp_packet(src, dst, sport, dport, ts_offset=i * 2))
    else:
        # ICMP ping
        packets.append(make_icmp_packet(src, dst, ts_offset=i * 2))


# ──────────────────────────────────────────────
# 2. PORT SCAN ATTACK (25 SYN packets to different ports)
# ──────────────────────────────────────────────
print("[*] Generating port scan attack...")
attacker_ip = "192.168.1.100"
scan_target = "10.0.0.1"
scan_start_offset = 70  # starts at ~70 seconds in

# Attacker scans 25 different ports in 3 seconds
scan_ports = random.sample(range(1, 1024), 25)
for i, port in enumerate(scan_ports):
    ts = scan_start_offset + (i * 0.12)  # very fast, ~0.12s apart
    packets.append(make_tcp_packet(attacker_ip, scan_target, random.randint(49152, 65535), port, "S", ts))


# ──────────────────────────────────────────────
# 3. SYN FLOOD ATTACK (50 SYN packets to port 80)
# ──────────────────────────────────────────────
print("[*] Generating SYN flood attack...")
flood_attacker = "192.168.1.200"
flood_target = "10.0.0.2"
flood_start_offset = 120

# 50 SYN packets in 5 seconds to port 80
for i in range(50):
    ts = flood_start_offset + (i * 0.1)  # 10 SYN packets per second
    sport = random.randint(1024, 65535)
    packets.append(make_tcp_packet(flood_attacker, flood_target, sport, 80, "S", ts))


# ──────────────────────────────────────────────
# 4. BRUTE FORCE ATTACK (20 connections to SSH port 22)
# ──────────────────────────────────────────────
print("[*] Generating brute force attack...")
brute_attacker = "192.168.1.50"
brute_target = "10.0.0.1"
brute_start_offset = 180

# 20 connection attempts to port 22 in quick succession
for i in range(20):
    ts = brute_start_offset + (i * 0.5)  # one attempt every 0.5 seconds
    sport = random.randint(49152, 65535)
    # SYN → SYN-ACK → ACK → RST pattern (simplified: just SYN + RST)
    packets.append(make_tcp_packet(brute_attacker, brute_target, sport, 22, "S", ts))
    packets.append(make_tcp_packet(brute_attacker, brute_target, sport, 22, "R", ts + 0.2))


# ──────────────────────────────────────────────
# 5. More normal traffic at the end (15 packets)
# ──────────────────────────────────────────────
print("[*] Generating trailing normal traffic...")
for i in range(15):
    src = random.choice(normal_ips)
    dst = random.choice(normal_targets)
    dport = random.choice(normal_ports)
    sport = random.randint(49152, 65535)
    packets.append(make_tcp_packet(src, dst, sport, dport, "A", ts_offset=250 + i * 3))


# ──────────────────────────────────────────────
# Sort all packets by timestamp and write to file
# ──────────────────────────────────────────────
packets.sort(key=lambda p: float(p.time))

output_dir = os.path.join(os.path.dirname(__file__))
output_path = os.path.join(output_dir, "sample.pcap")

wrpcap(output_path, packets)

total = len(packets)
print(f"\n[+] Sample PCAP created: {output_path}")
print(f"[+] Total packets: {total}")
print(f"    - Normal traffic:  45 packets")
print(f"    - Port scan:       25 packets (attacker: {attacker_ip} -> {scan_target})")
print(f"    - SYN flood:       50 packets (attacker: {flood_attacker} -> {flood_target})")
print(f"    - Brute force:     40 packets (attacker: {brute_attacker} -> {brute_target})")
print(f"\n[+] Ready for testing with: python capture/packet_parser.py")
