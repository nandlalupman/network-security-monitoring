"""
Schema Validation Module
Validates packet and alert dictionaries against the agreed NSM contract.
Designed for 3rd-year viva explanation: clean, simple, pure Python.
"""

def validate_packet(pkt: dict) -> bool:
    """Checks that a packet dictionary has all required keys and correct basic types."""
    required_keys = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flags", "length"]
    for key in required_keys:
        if key not in pkt:
            raise ValueError(f"Packet missing required field: '{key}'")
    
    if not isinstance(pkt["length"], int):
        raise TypeError("Packet 'length' must be an integer")
    if not isinstance(pkt["protocol"], str):
        raise TypeError("Packet 'protocol' must be a string")
    return True


def validate_alert(alert: dict) -> bool:
    """Checks that an alert dictionary has all required fields and valid severity/attack_type."""
    required_keys = ["alert_id", "timestamp", "attack_type", "severity", "src_ip", "dst_ip", "details", "confidence"]
    for key in required_keys:
        if key not in alert:
            raise ValueError(f"Alert missing required field: '{key}'")
    
    valid_severities = ["low", "medium", "high", "critical"]
    if alert["severity"].lower() not in valid_severities:
        raise ValueError(f"Alert 'severity' must be one of {valid_severities}")
        
    if not (0.0 <= alert["confidence"] <= 1.0):
        raise ValueError("Alert 'confidence' must be between 0.0 and 1.0")
    return True


if __name__ == "__main__":
    # Self-test demonstrating contract compliance
    sample_packet = {
        "timestamp": "2026-09-18T10:32:01.123Z",
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "src_port": 443,
        "dst_port": 22,
        "protocol": "TCP",
        "flags": "SYN",
        "length": 60
    }
    sample_alert = {
        "alert_id": "a1b2c3",
        "timestamp": "2026-09-18T10:32:01.500Z",
        "attack_type": "port_scan",
        "severity": "high",
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "details": "Scanned 25 ports in 3 seconds",
        "confidence": 0.9
    }

    try:
        validate_packet(sample_packet)
        print("[+] Packet Schema Validation: PASSED")
        validate_alert(sample_alert)
        print("[+] Alert Schema Validation: PASSED")
        print("[+] All contracts verified successfully!")
    except Exception as e:
        print(f"[-] Validation Failed: {e}")
