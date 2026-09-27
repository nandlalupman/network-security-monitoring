# NSM Platform — Viva Questions & Answers
## Network Security Monitoring Platform — B.Tech Academic Project 2026

---

## Section 1: Project Overview

**Q1. What is your project about? Explain in 2 sentences.**

> Our project is a Network Security Monitoring (NSM) Platform that reads pre-recorded network traffic files (PCAP), detects attacks using rule-based detection, and displays results on a real-time web dashboard. The system can detect Port Scans, SYN Floods, and Brute Force attacks and shows all detected threats in a browser-based interface.

---

**Q2. What is a PCAP file?**

> PCAP stands for "Packet Capture." It is a file format used to store recorded network traffic. Tools like Wireshark and Scapy can read these files. In our project, we use pre-recorded PCAP files to simulate attack scenarios without needing live network access.

---

**Q3. What is the overall data flow in your system?**

```
PCAP File
   ↓
Scapy Parser (capture/packet_parser.py)
   ↓
Packet Dictionary (JSON format)
   ↓
Detection Engine (detection/detector.py)
   ↓
Alert Dictionary (JSON format)
   ↓
SQLite Database (nsm_platform.db)
   ↓
Flask REST API (backend/app.py)
   ↓
Web Dashboard (dashboard/index.html)
```

---

## Section 2: Technology Choices

**Q4. Why did you use Python?**

> Python has excellent libraries for network packet analysis (Scapy), web development (Flask), and database operations (sqlite3). Its simple syntax made it easier for our team to understand and debug the code.

---

**Q5. Why Flask instead of Django?**

> Flask is a micro-framework — lightweight and beginner-friendly. We only needed a simple REST API with a few endpoints, so Flask was the right tool. Django would be overkill for this scope.

---

**Q6. Why SQLite instead of MySQL or PostgreSQL?**

> SQLite is built into Python — no separate server installation needed. For a project of this scale (academic demonstration), SQLite is sufficient. It stores data in a single `.db` file, which is easy to share and back up.

---

**Q7. Why Scapy for packet parsing?**

> Scapy is a powerful Python library specifically designed for network packet manipulation and analysis. It can read PCAP files and gives us easy access to every layer (Ethernet, IP, TCP, UDP, ICMP) of a packet. The `rdpcap()` function loads an entire PCAP in one line.

---

**Q8. Why Chart.js for the dashboard?**

> Chart.js is a simple, free JavaScript library for creating responsive charts in the browser. It requires no extra setup — just a `<script>` tag. It supports bar charts, doughnut charts, and more, which we needed for traffic and attack visualization.

---

## Section 3: Detection Rules

**Q9. Explain how Port Scan detection works.**

> A port scan is when an attacker tries to connect to many different ports on a target machine to find which services are open. Our rule:
> - Groups packets by `(source IP, destination IP)` pair
> - Uses a **10-second sliding time window**
> - Counts unique destination ports within that window
> - If **≥10 unique destination ports** are detected → **Port Scan alert triggered**
>
> Example: If `192.168.1.100` connects to ports 22, 23, 80, 443, 8080... within 5 seconds, it's flagged.

---

**Q10. Explain how SYN Flood detection works.**

> A SYN Flood is a Denial-of-Service attack. The attacker sends thousands of TCP SYN packets without completing the handshake, exhausting server resources. Our rule:
> - Filters for **SYN-only** packets (not SYN-ACK, not ACK)
> - Groups by `(source IP, destination IP, destination port)`
> - If **≥20 SYN packets** arrive in a **10-second window** → **SYN Flood alert triggered**

---

**Q11. Explain how Brute Force detection works.**

> A brute force attack involves repeatedly trying different passwords on a login service. Our rule:
> - Filters packets going to **known login ports**: SSH (22), Telnet (23), RDP (3389), FTP (21), MySQL (3306)
> - Groups by `(source IP, destination IP, destination port)`
> - If **≥8 connection attempts** within **30 seconds** → **Brute Force alert triggered**

---

**Q12. What is a sliding time window and why do you use it?**

> A sliding time window is a technique where instead of checking fixed intervals (like "every 10 seconds"), we look at a window that "slides" through time relative to each packet. For example, for each packet, we look at all packets within 10 seconds after it. This avoids missing attacks that straddle two fixed intervals. It's more accurate than fixed windows.

---

**Q13. What are false positives and false negatives?**

> - **False Positive**: The system raises an alert when there is NO actual attack. Example: A developer port-scanning their own server gets flagged.
> - **False Negative**: The system MISSES a real attack. Example: An attacker scans slowly over 30 minutes and doesn't trigger the threshold.
>
> Our thresholds are tunable (`PORT_SCAN_THRESHOLD`, `SYN_FLOOD_THRESHOLD`, etc.) to balance between the two.

---

**Q14. Why did you NOT use Machine Learning?**

> For the detection requirements of this project (Port Scan, SYN Flood, Brute Force), rule-based detection is well-understood, transparent, and easily explainable. Machine learning would add significant complexity (training data, feature engineering, model evaluation) without meaningful benefit at this scale. ML is mentioned as a future enhancement in our project.

---

## Section 4: Backend & API

**Q15. What REST API endpoints did you create and what do they do?**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/status` | GET | Check if the server is running |
| `/api/alerts` | GET | Get recent security alerts from DB |
| `/api/traffic-stats` | GET | Get packet protocol counts |
| `/api/summary` | GET | Get attack type counts for dashboard cards |
| `/api/analyze` | POST | Analyze the default sample.pcap |
| `/api/upload` | POST | Upload and analyze a custom PCAP file |
| `/api/clear` | POST | Clear all data from the database |

---

**Q16. What is CORS and why do you use `flask-cors`?**

> CORS stands for Cross-Origin Resource Sharing. Browsers block JavaScript on one domain (e.g., `localhost:3000`) from making requests to another domain (e.g., `localhost:5000`) by default. `flask-cors` adds the required HTTP headers so our dashboard JavaScript can call the Flask API without being blocked.

---

**Q17. What database tables did you create?**

> We have three tables:
> 1. **`alerts`** — stores detected security alerts (alert_id, attack_type, severity, src_ip, dst_ip, etc.)
> 2. **`traffic_stats`** — stores traffic statistics per analysis run (TCP count, UDP count, packet sizes, etc.)
> 3. **`analysis_runs`** — records metadata about each PCAP analysis (filename, total packets, total alerts)

---

## Section 5: Dashboard & Frontend

**Q18. How does the dashboard get updated with new data?**

> The dashboard uses JavaScript's `setInterval()` function to call the Flask REST API every **10 seconds** automatically. It also updates immediately when the user clicks "Analyze PCAP" or "Upload". Chart.js charts are initialized once and then updated with new data using `chart.update()` — no page reload needed.

---

**Q19. Why did you not use React or a frontend framework?**

> Plain HTML + CSS + JavaScript is simpler, easier to understand, and doesn't require a build step or Node.js. Since our frontend requirements were straightforward (charts, a table, stat cards), vanilla JavaScript with Chart.js was sufficient and kept the project beginner-friendly.

---

## Section 6: Individual Modules (For Each Person)

**Q20. Person 1 — What does `parse_packet()` return for a UDP packet?**

> For a UDP packet, `parse_packet()` returns a dictionary with `protocol = "UDP"`, with `src_port` and `dst_port` from the UDP layer, and `flags = ""` (empty string) since UDP has no flags.

---

**Q21. Person 2 — What happens if two different attackers are port-scanning the same target simultaneously?**

> The detection engine groups packets by `(src_ip, dst_ip)` pair. Two different source IPs scanning the same target would be in two separate groups and would each generate their own independent alert. This is handled correctly.

---

**Q22. Person 3 — What is an ICMP Sweep and how do you detect it?**

> An ICMP sweep (also called a ping sweep) is when an attacker pings many different IP addresses to discover which hosts are online. We detect it by checking if a single source IP sends ICMP packets to **≥5 different destination IPs within 30 seconds**.

---

**Q23. Person 4 — Why do you use `INSERT OR IGNORE` in the database?**

> Each alert has a unique `alert_id`. If the same PCAP is analyzed twice, the same alerts would be generated with the same IDs. `INSERT OR IGNORE` prevents duplicate rows — if a row with the same `alert_id` already exists, the insert is silently skipped.

---

**Q24. Person 5 — How does the confidence bar in the alerts table work?**

> Each alert has a `confidence` value between 0.0 and 1.0. In the dashboard, we multiply it by 100 to get a percentage. The bar width is set to that percentage using inline CSS (`style="width: 90%"`). The color changes from green (high confidence) to yellow to red (low confidence) based on the value.

---

## Section 7: General CS Concepts

**Q25. What is a TCP three-way handshake?**

> The TCP three-way handshake establishes a connection:
> 1. Client sends **SYN** (synchronize)
> 2. Server responds **SYN-ACK** (synchronize-acknowledge)
> 3. Client sends **ACK** (acknowledge)
>
> A SYN Flood attack exploits this by sending many SYNs but never completing step 3, leaving the server waiting and consuming resources.

---

**Q26. What is the difference between TCP and UDP?**

> - **TCP** (Transmission Control Protocol): Connection-oriented, reliable, ordered delivery. Has a handshake. Used for HTTP, SSH, FTP.
> - **UDP** (User Datagram Protocol): Connectionless, no guarantee of delivery or order. Faster, no overhead. Used for DNS, video streaming, gaming.

---

**Q27. How would you improve this project if you had more time?**

> 1. Add **live packet capture** using Scapy's `sniff()` function
> 2. Add **email/SMS alerts** for critical detections
> 3. Add **Machine Learning** anomaly detection as a supplemental layer
> 4. Add **user authentication** for the dashboard
> 5. Add **PDF report generation** for detected attacks
> 6. Add **IP geolocation** to show attacker locations on a map
