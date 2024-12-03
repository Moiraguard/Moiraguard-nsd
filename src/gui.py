import sys
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
    QPushButton, QTableWidget, QTableWidgetItem, QFileDialog
)
from PyQt5.QtWidgets import QMessageBox, QFileDialog
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QColor
from threading import Thread
from detector import Detector
import psutil
import socket
import netifaces
from datetime import datetime
import os
from PyQt5.QtCore import QThreadPool, QRunnable, QObject, pyqtSignal,QThread
import os
import json
from datetime import datetime
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QMainWindow, QApplication
from PyQt5.QtCore import pyqtSignal, QThreadPool


class NetworkScanDetectorGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Scan Detector")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #303A44; color: white;")

        self.detector = Detector(self.add_alert)
        self.monitoring_thread = None
        self.alerts = []  # To store alerts before exporting

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

        # Clear and Export buttons
        self.clear_button = QPushButton("Clear Alerts")
        self.clear_button.setStyleSheet("background-color: #FFC107; color: white; font-size: 14px; padding: 10px;")
        self.clear_button.clicked.connect(self.clear_alerts)
        self.button_layout.addWidget(self.clear_button)

        self.export_button = QPushButton("Export to JSON")
        self.export_button.setStyleSheet("background-color: #03A9F4; color: white; font-size: 14px; padding: 10px;")
        self.export_button.clicked.connect(self.export_to_json)
        self.button_layout.addWidget(self.export_button)

        self.main_layout.addLayout(self.button_layout)

        # Alert Table
        self.alert_table = QTableWidget()
        self.alert_table.setRowCount(0)
        self.alert_table.setColumnCount(6)
        self.alert_table.setHorizontalHeaderLabels(["Timestamp", "Event Type", "Source IP", "Scan Type", "Ports Scanned", "Severity"])
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
        Add a detected event to the alert table and store it in the alerts list.
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

        # Store the alert data in the list
        self.alerts.append({
            "timestamp": timestamp,
            "event_type": event_type,
            "source_ip": source_ip,
            "scan_type": scan_type,
            "ports_scanned": ports_scanned,
            "severity": severity
        })

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

    def clear_alerts(self):
        """
        Clears all the alerts from the table and the internal alerts list.
        """
        self.alert_table.setRowCount(0)
        self.alerts.clear()



    def export_to_json(self):
        """
        Exports the current alerts to a JSON file directly within the function.
        Saves it to the current directory where the tool is located.
        """
        if not self.alerts:
            QMessageBox.warning(self, "No Data", "No alerts to export.")
            return

        # Get the current timestamp for the filename
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"alerts_{timestamp}.json"

        # Get the current directory where the tool is located
        current_directory = os.getcwd()

        # Create the full path for the file
        file_path = os.path.join(current_directory, filename)

        try:
            # Write the alerts to the JSON file
            with open(file_path, 'w') as json_file:
                json.dump(self.alerts, json_file, indent=4)

            # Show success message with the file path
            QMessageBox.information(self, "Export Success", f"Alerts successfully exported to {file_path}")

        except Exception as e:
            # Show failure message in case of an error
            QMessageBox.warning(self, "Export Failed", f"Failed to export alerts: {str(e)}")

    def on_export_success(self, file_path):
        """
        Handler for successful export.
        """
        QMessageBox.information(self, "Export Successful", f"Alerts exported successfully to:\n{file_path}")


    def on_export_failure(self, error_message):
        """
        Handler for export failure.
        """
        QMessageBox.critical(self, "Export Failed", f"Failed to export alerts: {error_message}")

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
