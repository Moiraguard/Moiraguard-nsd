import json
from datetime import datetime
from config import LOG_FILE_PATH

def log_event(event_type, source_ip, scan_type, ports_scanned=None, severity="medium", message="", interface=None):
    """
    Logs network scan events in a JSON format for SIEM integration.
    
    :param event_type: Type of event (e.g., 'port_scan', 'ping_sweep')
    :param source_ip: The IP address of the scanner
    :param scan_type: The type of scan (e.g., 'SYN scan')
    :param ports_scanned: List of ports scanned (if applicable)
    :param severity: Severity of the event (e.g., 'low', 'medium', 'high')
    :param message: A message describing the event
    :param interface: The network interface where the scan was detected
    """
    log_data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",  # ISO 8601 format timestamp
        "event_type": event_type,
        "source_ip": source_ip,
        "scan_type": scan_type,
        "ports_scanned": ports_scanned if ports_scanned else [],
        "severity": severity,
        "message": message,
        "interface": interface  # Added interface information
    }
    
    # Write the log entry to the configured file
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(json.dumps(log_data) + "\n")
    
    print(f"Logged event from {source_ip} on interface {interface}: {message}")