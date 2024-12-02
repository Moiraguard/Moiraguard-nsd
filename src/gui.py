import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
    QPushButton, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QColor
from threading import Thread
from detector import Detector
import psutil
import socket
import netifaces


class NetworkScanDetectorGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Scan Detector")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #303A44; color: white;")

        self.detector = Detector(self.add_alert)
        self.monitoring_thread = None

        # Main layout
        self.main_layout = QVBoxLayout()

        # Header with logo and title
        header_layout = QHBoxLayout()
        self.logo_label = QLabel()
        self.set_logo("logo.png")  # Path to the logo
        header_layout.addWidget(self.logo_label)

        self.title_label = QLabel("Network Scan Detector")
        self.title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin-left: 20px;")
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()
        self.main_layout.addLayout(header_layout)

        # Host IP Label
        self.ip_label = QLabel("Host IP: Not Selected")
        self.ip_label.setStyleSheet("font-size: 14px; margin: 10px 0;")
        self.main_layout.addWidget(self.ip_label)

        # Network interface selection
        self.interfaces = self.get_available_interfaces()
        self.interface_combobox = QComboBox(self)
        self.interface_combobox.addItem("Select Interface")
        self.interface_combobox.addItems(self.interfaces)
        self.interface_combobox.setStyleSheet("background-color: #2E4053; color: white;")
        self.interface_combobox.currentIndexChanged.connect(self.update_host_ip)
        self.main_layout.addWidget(self.interface_combobox)

        # Buttons
        self.button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setStyleSheet("background-color: #4CAF50; color: white; font-size: 14px; padding: 10px;")
        self.start_button.clicked.connect(self.start_monitoring)
        self.button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setStyleSheet("background-color: #FF5733; color: white; font-size: 14px; padding: 10px;")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.hide()
        self.button_layout.addWidget(self.stop_button)

        self.main_layout.addLayout(self.button_layout)

        # Alert Table
        self.alert_table = QTableWidget()
        self.alert_table.setRowCount(0)
        self.alert_table.setColumnCount(6)
        self.alert_table.setHorizontalHeaderLabels(
            ["Timestamp", "Event Type", "Source IP", "Scan Type", "Ports Scanned", "Severity"]
        )
        self.alert_table.horizontalHeader().setStretchLastSection(True)
        self.alert_table.setStyleSheet("background-color: #2E4053; color: white; gridline-color: #404E5C;")
        self.main_layout.addWidget(self.alert_table)

        self.setLayout(self.main_layout)

    def set_logo(self, logo_path):
        """
        Load and set the logo with resizing.
        """
        try:
            pixmap = QPixmap(logo_path)
            scaled_pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(scaled_pixmap)
        except Exception as e:
            print(f"Failed to load logo: {e}")

    def get_host_ip_by_interface(self, interface):
        """
        Retrieve the IP address for a specific interface.
        """
        try:
            addrs = netifaces.ifaddresses(interface)
            return addrs[netifaces.AF_INET][0]['addr']
        except KeyError:
            return "Unknown"

    def get_available_interfaces(self):
        """
        Get a list of available network interfaces.
        """
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())

    def update_host_ip(self):
        """
        Update the host IP label based on the selected interface.
        """
        selected_interface = self.interface_combobox.currentText()
        if selected_interface != "Select Interface":
            self.ip_label.setText(f"Host IP: {self.get_host_ip_by_interface(selected_interface)}")
        else:
            self.ip_label.setText("Host IP: Not Selected")

    def add_alert(self, timestamp, event_type, source_ip, scan_type, ports_scanned, severity):
        """
        Add a detected event to the alert table.
        """
        row_position = self.alert_table.rowCount()
        self.alert_table.insertRow(row_position)
        self.alert_table.setItem(row_position, 0, QTableWidgetItem(timestamp))
        self.alert_table.setItem(row_position, 1, QTableWidgetItem(event_type))
        self.alert_table.setItem(row_position, 2, QTableWidgetItem(source_ip))
        self.alert_table.setItem(row_position, 3, QTableWidgetItem(scan_type))
        self.alert_table.setItem(row_position, 4, QTableWidgetItem(ports_scanned))
        severity_item = QTableWidgetItem(severity)
        severity_item.setForeground(QColor("red") if severity == "High" else QColor("yellow"))
        self.alert_table.setItem(row_position, 5, severity_item)

        self.alert_table.scrollToBottom()

    def start_monitoring(self):
        selected_interface = self.interface_combobox.currentText()
        if selected_interface != "Select Interface":
            self.switch_to_monitoring_mode()
            self.monitoring_thread = Thread(target=self.detector.start_sniffer, args=(selected_interface,))
            self.monitoring_thread.start()
        else:
            print("Please select an interface.")

    def stop_monitoring(self):
        self.detector.stop_sniffer()
        self.switch_to_idle_mode()

    def switch_to_monitoring_mode(self):
        self.start_button.hide()
        self.interface_combobox.setDisabled(True)
        self.stop_button.show()

    def switch_to_idle_mode(self):
        self.start_button.show()
        self.interface_combobox.setDisabled(False)
        self.stop_button.hide()


def main():
    app = QApplication(sys.argv)
    window = NetworkScanDetectorGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
