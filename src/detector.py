import socket
from datetime import datetime
from scapy.all import sniff, IP, TCP, ICMP
import psutil


class Detector:
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.is_running = False
        self.host_ip = self.get_host_ip()
        self.selected_interface=None
    
    def get_ip_address(self,interface):
        # Get all network interfaces and their addresses
        addrs = psutil.net_if_addrs()
        
        # Check if the interface exists in the system
        if interface in addrs:
            for addr in addrs[interface]:
                # Look for an IPv4 address (can also be adjusted for IPv6)
                if addr.family == socket.AF_INET:
                    self.host_ip  = addr.address
                    return addr.address
        else:
            return f"Interface {interface} not found."

    def get_host_ip(self):
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

    def detect_scan(self, packet):
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            host_ip = self.get_ip_address(self.selected_interface)
            print("host_ip")
            print(host_ip)
            # Ignore packets from or to the host machine
            if source_ip == host_ip :#or dest_ip == host_ip
                return

            # Ping Sweep detection (ICMP Echo Request)
            if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                self.alert_callback(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    event_type="Ping Sweep",
                    source_ip=source_ip,
                    scan_type="ICMP Echo Request",
                    ports_scanned="-",
                    severity="Medium",
                )
            # Port Scan detection (TCP SYN scan)
            elif packet.haslayer(TCP) and packet[TCP].flags == "S":
                dest_port = packet[TCP].dport
                self.alert_callback(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    event_type="Port Scan",
                    source_ip=source_ip,
                    scan_type="TCP SYN scan",
                    ports_scanned=str(dest_port),
                    severity="High",
                )

    def start_sniffer(self, interface=None):
        self.is_running = True
        try:
            self.selected_interface= interface
            sniff(iface=interface, prn=self.detect_scan, store=False, stop_filter=lambda x: not self.is_running)
        except PermissionError:
            print("[!] Permission denied. Run as root or use sudo.")
        except Exception as e:
            print(f"[!] Error occurred: {e}")

    def stop_sniffer(self):
        self.is_running = False
