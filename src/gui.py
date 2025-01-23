import os
if not os.environ.get('XDG_RUNTIME_DIR'):
    os.environ['XDG_RUNTIME_DIR'] = f'/run/user/{os.getuid()}'
import sys
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
    QPushButton, QTableWidget, QTableWidgetItem, QSystemTrayIcon, QMenu, QAction, QMessageBox
)
from PyQt5.QtGui import QPixmap, QColor, QIcon
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QTimer
from threading import Thread
from detector import Detector
import psutil
import netifaces
from datetime import datetime
import os

class NetworkScanDetectorGUI(QWidget):
    # Signals for thread-safe GUI updates
    alert_signal = pyqtSignal(dict)
    notification_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("MoiraGuard - Network Scan Detector")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #303A44; color: white;")

        self.detector = Detector(self.add_alert_threadsafe, self.notify_threadsafe)
        self.monitoring_thread = None
        self.alerts = []  # To store alerts before exporting
        # Main layout
        self.main_layout = QVBoxLayout()
        # Connect signals to slots
        self.alert_signal.connect(self.add_alert)
        self.notification_signal.connect(self.show_notification)

        # In the __init__ method, add a notification bar
        self.notification_bar = QLabel("")
        self.notification_bar.setStyleSheet("background-color: #FFD700; color: black; font-size: 14px; padding: 5px;")
        self.notification_bar.setAlignment(Qt.AlignCenter)
        self.notification_bar.hide()
        self.main_layout.addWidget(self.notification_bar)



        # Set up the system tray icon
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("src/Moiraguard_logo_bg.ico"))  # Set your desired icon
        self.tray_icon.setVisible(True)

        # Set up tray menu
        tray_menu = QMenu(self)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close_application)
        tray_menu.addAction(exit_action)
        self.tray_icon.setContextMenu(tray_menu)
        
        # Connect the tray icon to restore the window when clicked
        self.tray_icon.activated.connect(self.restore_window)

        # Header with logo and title
        header_layout = QHBoxLayout()
        self.logo_label = QLabel()
        self.set_logo("src/Moiraguard_logo_bg.png")
        header_layout.addWidget(self.logo_label)

        self.title_label = QLabel("MoiraGuard - Network Scan Detector")
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
        try:
            pixmap = QPixmap(logo_path)
            scaled_pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(scaled_pixmap)
        except Exception as e:
            print(f"Failed to load logo: {e}")

    def notify_threadsafe(self, message, severity):
        """
        Emit a signal to display notifications in a thread-safe manner.
        """
        self.notification_signal.emit(message, severity)

    def add_alert_threadsafe(self, **event):
        """
        Emit a signal to add alerts to the table in a thread-safe manner.
        """
        self.alert_signal.emit(event)

    def show_notification(self, message, severity):
        """
        Display a desktop notification using the system tray icon.
        """
        icon = QSystemTrayIcon.Information  # Default icon
        if severity == "High":
            icon = QSystemTrayIcon.Critical
        elif severity == "Medium":
            icon = QSystemTrayIcon.Warning

        # Show a desktop notification
        self.tray_icon.showMessage(f"{severity} Alert", message, icon)

        # Hide the notification after 5 seconds
        QTimer.singleShot(5000, self.notification_bar.hide)

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

    def add_alert(self, event):
        timestamp = event['timestamp']
        event_type = event['event_type']
        source_ip = event['source_ip']
        scan_type = event['scan_type']
        ports_scanned = event['ports_scanned']
        severity = event['severity']

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
        self.alerts.append({
            "timestamp": timestamp,
            "event_type": event_type,
            "source_ip": source_ip,
            "scan_type": scan_type,
            "ports_scanned": ports_scanned,
            "severity": severity
        })

    def get_available_interfaces(self):
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())

    def update_host_ip(self):
        selected_interface = self.interface_combobox.currentText()
        if selected_interface != "Select Interface":
            self.ip_label.setText(f"Host IP: {self.get_host_ip_by_interface(selected_interface)}")
        else:
            self.ip_label.setText("Host IP: Not Selected")

    def get_host_ip_by_interface(self, interface):
        try:
            addrs = netifaces.ifaddresses(interface)
            return addrs[netifaces.AF_INET][0]['addr']
        except KeyError:
            return "Unknown"

    def clear_alerts(self):
        self.alert_table.setRowCount(0)
        self.alerts.clear()

    def export_to_json(self):
        if not self.alerts:
            QMessageBox.warning(self, "No Data", "No alerts to export.")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"mouiraguard-nsd_alerts_{timestamp}.json"
        current_dir = os.getcwd()

        print(current_dir)
        log_dir = current_dir +"/logs/"
        file_path = os.path.join(log_dir, filename)
        print(os.path.join(log_dir, filename))
        print(log_dir)
        try:
            with open(file_path, 'w') as json_file:
                json.dump(self.alerts, json_file, indent=4)

            QMessageBox.information(self, "Export Success", f"Alerts successfully exported to {file_path}")

        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Failed to export alerts: {str(e)}")

    def close_application(self):
        self.tray_icon.setVisible(False)
        sys.exit()

    def restore_window(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.show()
            self.activateWindow()
            self.raise_()
    def closeEvent(self, event):
        """
        Override close event to minimize the application to the system tray.
        """
        if self.tray_icon.isVisible():
            self.hide()  # Hide the main window
            self.tray_icon.showMessage(
                "MoiraGuard NSD is Running",
                "Double-click the tray icon to restore it.",
                QSystemTrayIcon.Information,
            )
            event.ignore()  # Prevent the application from closing
        else:
            event.accept()  # Allow the application to close

    def restore_window(self, reason):
        """
        Restore the main window when the tray icon is activated.
        """
        if reason == QSystemTrayIcon.Trigger:  # Triggered on a single or double-click
            self.show()  # Show the main window
            self.activateWindow()  # Bring it to the foreground


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkScanDetectorGUI()
    window.show()
    sys.exit(app.exec_())
