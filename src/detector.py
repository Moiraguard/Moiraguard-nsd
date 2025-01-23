from datetime import datetime
from scapy.all import sniff, IP, TCP, ICMP
import socket
import psutil
import threading
import netifaces

class Detector:
    def __init__(self, alert_callback, notify_callback):
        self.alert_callback = alert_callback
        self.notify_callback = notify_callback
        self.is_running = False
        self.threads = {}
        self.host_ips = set()  # Store IPs of the selected interfaces
        self.last_notification = {}
        self.notification_cooldown = 10

    def get_host_ips(self, interfaces):
        """
        Retrieve the IP addresses of the selected interfaces.
        """
        self.host_ips.clear()
        for interface in interfaces:
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        self.host_ips.add(addr_info['addr'])
            except ValueError:
                print(f"[!] Interface {interface} not found or has no IP address.")

    def should_notify(self, source_ip, event_type):
        now = datetime.utcnow()
        key = (source_ip, event_type)
        
        if key in self.last_notification:
            last_time = self.last_notification[key]
            if (now - last_time).total_seconds() < self.notification_cooldown:
                return False

        self.last_notification[key] = now
        return True

    def detect_scan(self, packet, interface):
        if packet.haslayer(IP):
            source_ip = packet[IP].src

            # Ignore traffic from our own IPs
            if source_ip in self.host_ips:
                return

            # Ping Sweep detection
            if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                event = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "Ping Sweep",
                    "source_ip": source_ip,
                    "scan_type": "ICMP Echo Request",
                    "ports_scanned": "-",
                    "severity": "Medium",
                    "interface": interface
                }
                self.alert_callback(**event)

                if self.should_notify(source_ip, "Ping Sweep"):
                    self.notify_callback(
                        f"Ping Sweep detected from {source_ip} on interface {interface}", 
                        "Medium"
                    )

            # Port Scan detection
            elif packet.haslayer(TCP) and packet[TCP].flags == "S":
                dest_port = packet[TCP].dport
                event = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "Port Scan",
                    "source_ip": source_ip,
                    "scan_type": "TCP SYN scan",
                    "ports_scanned": str(dest_port),
                    "severity": "High",
                    "interface": interface
                }
                self.alert_callback(**event)

                if self.should_notify(source_ip, "Port Scan"):
                    self.notify_callback(
                        f"Port Scan detected from {source_ip} on port {dest_port} (interface {interface})", 
                        "High"
                    )

    def start_interface_sniffer(self, interface):
        try:
            sniff(
                iface=interface, 
                prn=lambda packet: self.detect_scan(packet, interface), 
                store=False, 
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"[!] Error on interface {interface}: {e}")

    def start_specific_interfaces(self, interfaces):
        """
        Start monitoring on specific interfaces.
        
        :param interfaces: List of interfaces to monitor
        """
        self.is_running = True
        self.get_host_ips(interfaces)  # Retrieve IPs of the selected interfaces
        for interface in interfaces:
            thread = threading.Thread(
                target=self.start_interface_sniffer, 
                args=(interface,)
            )
            self.threads[interface] = thread
            thread.start()

    def start_all_interfaces(self):
        """
        Start monitoring on all available interfaces (excluding loopback).
        """
        self.is_running = True
        interfaces = [
            iface for iface in psutil.net_if_addrs().keys() 
            if not iface.startswith('lo')  # Exclude loopback
        ]
        self.get_host_ips(interfaces)  # Retrieve IPs of all interfaces
        for interface in interfaces:
            thread = threading.Thread(
                target=self.start_interface_sniffer, 
                args=(interface,)
            )
            self.threads[interface] = thread
            thread.start()

    def stop_sniffer(self):
        self.is_running = False
        for thread in self.threads.values():
            thread.join()
        self.threads.clear()