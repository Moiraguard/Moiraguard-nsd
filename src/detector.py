from datetime import datetime
from scapy.all import sniff, IP, TCP, ICMP
import socket
import psutil

class Detector:
    def __init__(self, alert_callback, notify_callback):
        self.alert_callback = alert_callback
        self.notify_callback = notify_callback  # Callback to notify GUI
        self.is_running = False
        self.host_ip = self.get_host_ip()
        self.selected_interface = None
        self.last_notification = {}  # To track last notifications by IP and scan type
        self.notification_cooldown = 10  # Cooldown period in seconds

    def get_ip_address(self, interface):
        """
        Get the IP address for a specific interface.
        """
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for addr in addrs[interface]:
                if addr.family == socket.AF_INET:
                    self.host_ip = addr.address
                    return addr.address
        else:
            return f"Interface {interface} not found."

    def get_host_ip(self):
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

    def should_notify(self, source_ip, event_type):
        """
        Determine if a notification should be sent based on cooldown and type.
        """
        now = datetime.utcnow()
        key = (source_ip, event_type)
        
        if key in self.last_notification:
            last_time = self.last_notification[key]
            if (now - last_time).total_seconds() < self.notification_cooldown:
                return False

        self.last_notification[key] = now
        return True

    def detect_scan(self, packet):
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            host_ip = self.get_ip_address(self.selected_interface)

            # Ignore packets from or to the host machine
            if source_ip == host_ip:
                return

            # Ping Sweep detection (ICMP Echo Request)
            if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                event = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "Ping Sweep",
                    "source_ip": source_ip,
                    "scan_type": "ICMP Echo Request",
                    "ports_scanned": "-",
                    "severity": "Medium",
                }
                self.alert_callback(**event)

                if self.should_notify(source_ip, "Ping Sweep"):
                    self.notify_callback(f"Ping Sweep detected from {source_ip}", "Medium")

            # Port Scan detection (TCP SYN scan)
            elif packet.haslayer(TCP) and packet[TCP].flags == "S":
                dest_port = packet[TCP].dport
                event = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "Port Scan",
                    "source_ip": source_ip,
                    "scan_type": "TCP SYN scan",
                    "ports_scanned": str(dest_port),
                    "severity": "High",
                }
                self.alert_callback(**event)

                if self.should_notify(source_ip, "Port Scan"):
                    self.notify_callback(f"Port Scan detected from {source_ip} on port {dest_port}", "High")

    def start_sniffer(self, interface=None):
        self.is_running = True
        try:
            self.selected_interface = interface
            sniff(iface=interface, prn=self.detect_scan, store=False, stop_filter=lambda x: not self.is_running)
        except PermissionError:
            print("[!] Permission denied. Run as root or use sudo.")
        except Exception as e:
            print(f"[!] Error occurred: {e}")

    def stop_sniffer(self):
        self.is_running = False
