# src/detector.py

from scapy.all import sniff, IP, TCP, ICMP
from logger import log_event

def detect_scan(packet):
    """
    Analyzes packets to detect network scans such as ping sweeps or port scans.
    
    :param packet: Captured packet to analyze
    """
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        
        # Detect ICMP Echo Request (Ping Sweep)
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            log_event(
                event_type="ping_sweep",
                source_ip=source_ip,
                scan_type="ICMP Echo Request",
                message=f"Ping sweep detected from {source_ip}."
            )
        
        # Detect TCP SYN Packets (Port Scanning)
        elif packet.haslayer(TCP) and packet[TCP].flags == "S":
            dest_port = packet[TCP].dport
            log_event(
                event_type="port_scan",
                source_ip=source_ip,
                scan_type="TCP SYN scan",
                ports_scanned=[dest_port],
                severity="high",
                message=f"Port scanning detected on port {dest_port} from {source_ip}."
            )

def start_sniffer(interface="eth0"):
    """
    Starts the packet sniffer to monitor network traffic for suspicious activities.
    
    :param interface: The network interface to sniff on (e.g., 'eth0', 'wlan0')
    """
    print(f"[*] Starting sniffer on interface {interface}...")
    try:
        sniff(iface=interface, prn=detect_scan, store=False)
    except PermissionError:
        print("[!] Permission denied. Please run as root or use sudo.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
