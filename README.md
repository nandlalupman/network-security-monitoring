# Network Security Monitoring (NSM) Platform

A web-based Network Security Monitoring platform that analyzes PCAP network traffic files, detects attacks using rule-based detection, and displays results on a real-time dashboard.

**Academic Project — B.Tech 3rd Year (2026)**

---

## Architecture

```
PCAP File (.pcap)
       |
       v
[Packet Parser]  ----  Scapy reads packets, outputs JSON dictionaries
       |
       v
[Detection Engine]  --  Rule-based detection (Port Scan, SYN Flood, Brute Force)
       |
       v
[SQLite Database]  ---  Stores alerts and traffic statistics
       |
       v
[Flask REST API]  ----  Serves data over HTTP endpoints
       |
       v
[Web Dashboard]  -----  HTML + CSS + JavaScript + Chart.js
```

## Team Division

| Person | Module | Folder | Key File |
|--------|--------|--------|----------|
| Person 1 | Packet Processing | `capture/` | `packet_parser.py` |
| Person 2 | Detection Engine | `detection/` | `detector.py` |
| Person 3 | Extra Rules & Testing | `anomaly/` | `extra_rules.py` |
| Person 4 | Backend API & Database | `backend/` | `app.py`, `database.py` |
| Person 5 | Dashboard UI | `dashboard/` | `index.html`, `style.css`, `script.js` |

## Folder Structure

```
nsm-platform/
├── capture/
│   ├── __init__.py
│   └── packet_parser.py        # Scapy PCAP parser
├── detection/
│   ├── __init__.py
│   └── detector.py             # Core detection rules
├── anomaly/
│   ├── __init__.py
│   └── extra_rules.py          # Additional detection rules
├── backend/
│   ├── __init__.py
│   ├── app.py                  # Flask REST API server
│   └── database.py             # SQLite database operations
├── dashboard/
│   ├── index.html              # Main dashboard page
│   ├── style.css               # Styling
│   └── script.js               # Frontend logic
├── sample_pcaps/
│   ├── generate_sample_pcap.py # Script to create test PCAP
│   └── sample.pcap             # Pre-generated test PCAP
├── schema/
│   ├── schema.json             # Frozen data contract
│   └── validate_schema.py      # Schema validator
├── test_pipeline.py            # Integration test script
├── requirements.txt
├── README.md
└── venv/                       # Python virtual environment
```

## Prerequisites

- Python 3.10 or higher
- Windows 10/11 (tested) or Linux/macOS
- A modern web browser (Chrome, Firefox, Edge)

## Setup Instructions

### 1. Clone/Download the Project

```powershell
cd C:\path\to\your\projects
# If downloaded as ZIP, extract it
```

### 2. Create Virtual Environment

```powershell
cd nsm-platform
python -m venv venv
```

### 3. Activate Virtual Environment

```powershell
# Windows (PowerShell)
.\venv\Scripts\Activate

# Windows (CMD)
venv\Scripts\activate.bat

# Linux/Mac
source venv/bin/activate
```

### 4. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 5. Generate Sample PCAP (Optional — already included)

```powershell
python sample_pcaps\generate_sample_pcap.py
```

### 6. Run the Server

```powershell
python backend\app.py
```

### 7. Open the Dashboard

Open your browser and go to: **http://localhost:5000**

## How to Use

1. Open `http://localhost:5000` in your browser.
2. Click **"Analyze PCAP"** to analyze the default `sample.pcap`.
3. Or click **"Upload"** to upload your own PCAP file.
4. The dashboard will show:
   - Total packets analyzed
   - Detected attacks (Port Scan, SYN Flood, Brute Force)
   - Traffic protocol distribution chart
   - Attack summary chart
   - Recent alerts table with severity, IPs, and details
5. Click **"Clear"** to reset all data.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Server health check |
| GET | `/api/alerts` | Get recent security alerts |
| GET | `/api/traffic-stats` | Get traffic statistics |
| GET | `/api/summary` | Get attack type counts |
| POST | `/api/analyze` | Analyze default sample.pcap |
| POST | `/api/upload` | Upload and analyze a PCAP file |
| POST | `/api/clear` | Clear all data |

## Detection Rules

### 1. Port Scan (Person 2)
- **Condition**: One source IP connects to ≥10 different destination ports on the same target within 10 seconds.
- **Severity**: High

### 2. SYN Flood (Person 2)
- **Condition**: One source IP sends ≥20 SYN packets to the same target port within 10 seconds.
- **Severity**: Critical

### 3. Brute Force (Person 2)
- **Condition**: One source IP makes ≥8 connection attempts to a login port (SSH, RDP, etc.) within 30 seconds.
- **Severity**: High

### 4. Suspicious Traffic (Person 3)
- **Condition**: Packets using unknown protocols or exceeding 1500 bytes.
- **Severity**: Low

### 5. ICMP Sweep (Person 3)
- **Condition**: One source IP pings ≥5 unique destination IPs within 30 seconds.
- **Severity**: Medium

## Testing

### Test Individual Modules

```powershell
# Test the PCAP parser
python capture\packet_parser.py

# Test the detection engine
python detection\detector.py

# Test extra rules
python anomaly\extra_rules.py

# Test the database
python backend\database.py

# Test the schema validator
python schema\validate_schema.py
```

### Test Full Pipeline

```powershell
python test_pipeline.py
```

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.13 + Flask |
| Packet Parsing | Scapy |
| Database | SQLite |
| Frontend | HTML + CSS + JavaScript |
| Charts | Chart.js |
| API Format | REST (JSON) |

## Future Enhancements

1. **Machine Learning**: Anomaly detection using unsupervised ML models.
2. **Live Capture**: Real-time packet capture using Scapy sniff.
3. **Email Alerts**: Send email notifications on critical alerts.
4. **User Authentication**: Login system for the dashboard.
5. **Export Reports**: PDF/CSV export of analysis results.

## License

This project is for academic purposes only.

---

*Developed as a B.Tech 3rd Year academic project — September 2026*
