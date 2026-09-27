# Project Report — Network Security Monitoring Platform
## B.Tech 3rd Year Academic Project Report Structure

---

## Title Page

**Project Title:** Network Security Monitoring (NSM) Platform

**Team Members:**
- Person 1 — [Name] — Roll No. [XXX] — Packet Processing
- Person 2 — [Name] — Roll No. [XXX] — Detection Engine
- Person 3 — [Name] — Roll No. [XXX] — Extra Rules & Testing
- Person 4 — [Name] — Roll No. [XXX] — Backend & Database
- Person 5 — [Name] — Roll No. [XXX] — Dashboard & UI

**Guided By:** [Professor Name], Department of Computer Science

**Institution:** [College Name], [University Name]

**Academic Year:** 2025–2026 | Semester: [V/VI]

---

## Certificate Page

*"This is to certify that the project titled **Network Security Monitoring Platform** has been carried out by the above-mentioned students in partial fulfillment of the requirements for the award of the degree of Bachelor of Technology in Computer Science Engineering."*

---

## Abstract

*(Write 200–300 words covering the following points)*

- The increasing complexity of cyber threats requires automated monitoring systems.
- Our project builds a web-based Network Security Monitoring Platform.
- Uses Python and Scapy to parse PCAP network traffic files.
- Applies rule-based detection to identify Port Scans, SYN Floods, and Brute Force attacks.
- Stores results in a SQLite database and serves them via a Flask REST API.
- Displays threat intelligence on a real-time browser dashboard using Chart.js.
- Successfully detects all three attack types with minimal false positives.
- Designed to be beginner-friendly and easily extensible.

---

## Table of Contents

1. Introduction
2. Problem Statement
3. Objectives
4. System Architecture
5. Technology Stack
6. Module Descriptions
7. Detection Rules
8. API Documentation
9. Database Design
10. Dashboard Design
11. Testing & Results
12. Limitations
13. Future Enhancements
14. Conclusion
15. References

---

## Chapter 1 — Introduction

### 1.1 Background
Network security monitoring is the process of continuously analyzing network traffic to identify security threats. With the rise of cyber attacks, organizations need tools that can detect malicious activity in real time.

### 1.2 Motivation
Existing commercial solutions (Splunk, IBM QRadar) are expensive and complex. This project demonstrates that a functional NSM platform can be built using open-source tools with basic knowledge of Python and web development.

### 1.3 Scope of the Project
- Analyze pre-recorded PCAP files
- Detect three types of attacks using rule-based detection
- Display results via a web dashboard
- Provide a REST API for extensibility

---

## Chapter 2 — Problem Statement

Modern networks generate massive amounts of traffic. Security teams need automated tools to identify attacks within this traffic. Manual inspection is impractical. The problem is to design and implement a system that can:

1. Parse raw network packet data
2. Apply detection rules to identify attacks
3. Store and serve the results
4. Visualize them in a user-friendly dashboard

---

## Chapter 3 — Objectives

1. Parse PCAP files using Scapy and extract packet metadata
2. Implement rule-based detection for Port Scan, SYN Flood, and Brute Force attacks
3. Store detected alerts in a SQLite database
4. Create a Flask REST API serving detection results
5. Build a responsive web dashboard showing traffic statistics and alerts

---

## Chapter 4 — System Architecture

### 4.1 Architecture Diagram

```
 ┌──────────────────┐
 │   PCAP File      │  Pre-recorded or uploaded network traffic
 └────────┬─────────┘
          ↓
 ┌──────────────────┐
 │  Packet Parser   │  Scapy reads packets, extracts fields
 │  (Person 1)      │  Output: List of packet dictionaries
 └────────┬─────────┘
          ↓
 ┌──────────────────┐
 │Detection Engine  │  Rule-based: Port Scan, SYN Flood,
 │  (Person 2&3)    │  Brute Force, Suspicious Traffic
 └────────┬─────────┘
          ↓
 ┌──────────────────┐
 │SQLite Database   │  Tables: alerts, traffic_stats,
 │  (Person 4)      │  analysis_runs
 └────────┬─────────┘
          ↓
 ┌──────────────────┐
 │  Flask REST API  │  Endpoints: /api/alerts, /api/summary,
 │  (Person 4)      │  /api/traffic-stats, /api/upload
 └────────┬─────────┘
          ↓
 ┌──────────────────┐
 │  Web Dashboard   │  HTML+CSS+JS+Chart.js
 │  (Person 5)      │  Displays stats, charts, alert table
 └──────────────────┘
```

### 4.2 Data Flow
Each packet goes through the pipeline in sequence. The parser outputs a standardized JSON object. The detection engine processes lists of these objects. Alerts are stored in SQLite and fetched by the dashboard via REST API calls.

---

## Chapter 5 — Technology Stack

| Component | Technology | Reason |
|-----------|-----------|--------|
| Backend Language | Python 3.13 | Industry standard, rich libraries |
| Web Framework | Flask 3.1 | Lightweight, beginner-friendly |
| Packet Analysis | Scapy 2.7 | Best Python library for PCAP parsing |
| Database | SQLite 3 | Built-in Python, no server needed |
| Frontend | HTML5 + CSS3 + JavaScript | Universal, no build step needed |
| Charts | Chart.js 4.4 | Simple, free, responsive charts |
| API Style | REST / JSON | Simple, widely understood |

---

## Chapter 6 — Module Descriptions

### 6.1 Packet Parser (`capture/packet_parser.py`) — Person 1
Reads PCAP files using Scapy's `rdpcap()`. For each packet with an IP layer, extracts: timestamp, source/destination IPs, source/destination ports, protocol (TCP/UDP/ICMP), TCP flags, and packet length. Returns a list of standardized dictionaries.

**Key Functions:**
- `parse_pcap(filepath)` — reads entire PCAP
- `parse_packet(pkt)` — converts one Scapy packet to dict
- `get_tcp_flags(tcp_layer)` — converts flag bits to readable string

### 6.2 Detection Engine (`detection/detector.py`) — Person 2
Implements rule-based detection using sliding time windows and threshold comparisons.

**Key Functions:**
- `detect_port_scan(packets)` — threshold: 10 ports / 10 seconds
- `detect_syn_flood(packets)` — threshold: 20 SYNs / 10 seconds
- `detect_brute_force(packets)` — threshold: 8 attempts / 30 seconds
- `detect_all(packets)` — runs all three rules

### 6.3 Extra Rules (`anomaly/extra_rules.py`) — Person 3
Adds supplemental detection rules and assists with testing.

**Rules:**
- `detect_suspicious_traffic()` — flags oversized packets and unknown protocols
- `detect_icmp_sweep()` — detects network reconnaissance via ICMP pings

### 6.4 Database (`backend/database.py`) — Person 4
SQLite wrapper class with methods for creating tables, inserting records, and querying data.

**Tables:** `alerts`, `traffic_stats`, `analysis_runs`

### 6.5 Flask API (`backend/app.py`) — Person 4
REST API server that ties all modules together. Serves the dashboard and exposes 7 API endpoints.

### 6.6 Dashboard (`dashboard/`) — Person 5
Single-page web application with a dark glassmorphism theme. Shows 6 stat cards, 3 Chart.js charts, and a detailed alerts table. Auto-refreshes every 10 seconds.

---

## Chapter 7 — Detection Rules

*(See Detection Rules section in README and VIVA_QA.md for detailed explanations)*

| Rule | Threshold | Time Window | Severity |
|------|-----------|-------------|----------|
| Port Scan | ≥10 unique ports | 10 seconds | High |
| SYN Flood | ≥20 SYN packets | 10 seconds | Critical |
| Brute Force | ≥8 login attempts | 30 seconds | High |
| Suspicious Traffic | Packet > 1500B or unknown protocol | Per packet | Low |
| ICMP Sweep | ≥5 unique target IPs | 30 seconds | Medium |

---

## Chapter 8 — Database Design

### Schema

**Table: alerts**
```sql
CREATE TABLE alerts (
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
);
```

**Table: traffic_stats**
```sql
CREATE TABLE traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    total_packets INTEGER,
    tcp_count INTEGER,
    udp_count INTEGER,
    icmp_count INTEGER,
    avg_packet_size REAL,
    unique_src_ips INTEGER,
    unique_dst_ips INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

---

## Chapter 9 — Testing & Results

### 9.1 Unit Tests
Each module has a standalone self-test runnable with `python module_name.py`.

### 9.2 Integration Test
`test_pipeline.py` runs the full PCAP → Parse → Detect pipeline.

### 9.3 Test Results (sample.pcap — 160 packets)

| Attack Type | Expected | Detected | Result |
|------------|----------|----------|--------|
| Port Scan | 1 | 1 | PASS |
| SYN Flood | 2 | 2 | PASS |
| Brute Force | 1 | 1 | PASS |
| False Positives | 0 | 0 | PASS |

### 9.4 Full Test Suite
Running `python tests/test_cases.py` executes 30+ individual test cases across all modules.

---

## Chapter 10 — Limitations

1. Uses pre-recorded PCAP files; not real-time live capture
2. Rule-based detection cannot detect novel/unknown attacks
3. No user authentication on the dashboard
4. Thresholds may need tuning for different network environments
5. PCAP files must fit in memory (large files may be slow)

---

## Chapter 11 — Future Enhancements

1. **Live Packet Capture** — Use Scapy's `sniff()` for real-time monitoring
2. **Machine Learning** — Add anomaly detection using unsupervised clustering
3. **Email Alerts** — Send notifications via SMTP for critical events
4. **User Authentication** — Login system for the dashboard
5. **PDF Export** — Generate security reports automatically
6. **IP Geolocation** — Show attacker locations on a world map

---

## Chapter 12 — Conclusion

The Network Security Monitoring Platform successfully demonstrates core concepts of network security analysis:
- Packet parsing and protocol analysis using Scapy
- Rule-based intrusion detection with sliding time windows
- Data persistence using SQLite
- REST API design using Flask
- Real-time data visualization using Chart.js

The system detected all three embedded attack patterns (Port Scan, SYN Flood, Brute Force) in the test PCAP file with no false positives in normal traffic. The project is modular, well-documented, and easily extensible for future enhancements.

---

## References

1. Scapy Documentation — https://scapy.readthedocs.io
2. Flask Documentation — https://flask.palletsprojects.com
3. Chart.js Documentation — https://www.chartjs.org/docs
4. SQLite Documentation — https://www.sqlite.org/docs.html
5. Bejtlich, R. (2004). *The Tao of Network Security Monitoring*. Addison-Wesley.
6. SANS Institute — Network Security Monitoring Guidelines
7. RFC 793 — Transmission Control Protocol (TCP)
