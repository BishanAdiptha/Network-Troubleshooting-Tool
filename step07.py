import platform
import socket
from PySide6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QTextEdit, QPushButton,
    QHBoxLayout, QScrollArea, QFrame
)
from PySide6.QtCore import Qt, QTimer
from main import load_trusted_macs, save_trusted_macs
from router_devices_fetcher import get_connected_devices  # NEW IMPORT

class Step07Tab(QWidget):
    def __init__(self, tabs, selected_interface):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = selected_interface

        layout = QVBoxLayout()

        title = QLabel("\nStep 07\nConnected Devices Scan\n")
        title.setAlignment(Qt.AlignHCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("Here are all devices currently connected to your network:")
        desc.setStyleSheet("font-size: 14px; color: black; margin-bottom: 10px;")
        layout.addWidget(desc)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout()
        self.scroll_content.setLayout(self.scroll_layout)
        self.scroll.setWidget(self.scroll_content)
        layout.addWidget(self.scroll)

        self.status_box = QTextEdit()
        self.status_box.setReadOnly(True)
        self.status_box.setStyleSheet("""
            QTextEdit {
                background: #0f1b2a;
                color: white;
                font-family: Consolas;
                font-size: 14px;
                border-radius: 10px;
                padding: 10px;
                border: none;
            }
        """)
        layout.addWidget(self.status_box)

        self.prev_btn = QPushButton("«« Previous")
        self.prev_btn.setStyleSheet("""
            QPushButton {
                background-color: #0094ff;
                color: white;
                padding: 8px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #007acc;
            }
        """)
        self.prev_btn.clicked.connect(self.go_back_to_step6)

        self.next_btn = QPushButton("Next »»")
        self.next_btn.setStyleSheet("""
            QPushButton {
                background-color: #0094ff;
                color: white;
                padding: 8px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #007acc;
            }
        """)
        self.next_btn.clicked.connect(self.go_to_needhelp)

        nav_layout = QHBoxLayout()
        nav_layout.addWidget(self.prev_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)

        layout.addLayout(nav_layout)
        self.setLayout(layout)

        self.show_loading_message()
        QTimer.singleShot(500, self.run_scan)

    def show_loading_message(self):
        self.scroll_layout.setSpacing(10)
        self.clear_device_list()
        loading = QLabel("⏳ Scanning devices... Please wait...")
        loading.setStyleSheet("font-size:16px; color:#666;")
        loading.setAlignment(Qt.AlignCenter)
        self.scroll_layout.addWidget(loading)

    def run_scan(self):
        self.clear_device_list()
        trusted_macs = load_trusted_macs()
        unauthorized_found = False

        devices = get_connected_devices()
        if not devices:
            self.status_box.setPlainText("❌ Could not fetch any devices from router.")
            return

        for name, ip, mac in devices:
            device_frame = QFrame()
            device_frame.setStyleSheet("background: #f9fafb; border: 1px solid #ccc; border-radius: 10px; padding: 10px;")
            device_layout = QHBoxLayout()
            device_frame.setLayout(device_layout)

            hostname_label = QLabel(f"<b>{name}</b>")
            hostname_label.setStyleSheet("font-size: 14px;")
            ip_label = QLabel(ip)
            mac_label = QLabel(mac)

            for l in (hostname_label, ip_label, mac_label):
                l.setStyleSheet("background:transparent; border:none; font-size:13px; color:#333;")

            device_layout.addWidget(hostname_label)
            device_layout.addWidget(ip_label)
            device_layout.addWidget(mac_label)

            if mac.lower() in trusted_macs:
                status_label = QLabel("<span style='color:green;'>Known</span>")
                status_label.setStyleSheet("padding:5px;")
                device_layout.addWidget(status_label)
            else:
                unauthorized_found = True
                status_label = QLabel("<span style='color:red;'>Unknown</span>")
                status_label.setStyleSheet("padding:5px;")
                device_layout.addWidget(status_label)

                trust_btn = QPushButton("Trust")
                trust_btn.setStyleSheet("""
                    QPushButton {
                        background-color: green; 
                        color: white; 
                        padding: 5px; 
                        border-radius: 8px;
                    }
                    QPushButton:hover {
                        background-color: #00cc00;
                    }
                """)
                trust_btn.clicked.connect(lambda _, m=mac: self.trust_mac(m))

                untrust_btn = QPushButton("Untrust")
                untrust_btn.setStyleSheet("""
                    QPushButton {
                        background-color: red; 
                        color: white; 
                        padding: 5px; 
                        border-radius: 8px;
                    }
                    QPushButton:hover {
                        background-color: #ff4d4d;
                    }
                """)
                untrust_btn.clicked.connect(lambda _, m=mac: self.untrust_mac(m))

                device_layout.addWidget(trust_btn)
                device_layout.addWidget(untrust_btn)

            self.scroll_layout.addWidget(device_frame)

        if unauthorized_found:
            self.status_box.setPlainText("🚨 Unauthorized devices detected! Please trust or untrust them.")
        else:
            self.status_box.setPlainText("✅ No unauthorized devices found.")

    def clear_device_list(self):
        for i in reversed(range(self.scroll_layout.count())):
            widget = self.scroll_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

    def trust_mac(self, mac):
        trusted_macs = load_trusted_macs()
        if mac.lower() not in trusted_macs:
            trusted_macs.append(mac.lower())
            save_trusted_macs(trusted_macs)
        self.show_loading_message()
        QTimer.singleShot(300, self.run_scan)

    def untrust_mac(self, mac):
        self.status_box.setPlainText("🚨 Unsafe device detected! It's recommended to change your Wi-Fi password immediately.")

    def go_back_to_step6(self):
        from step06 import Step06Tab
        step6 = Step06Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step6, "Troubleshoot")
        self.tabs.setCurrentIndex(0)

    def go_to_needhelp(self):
        from needhelp import NeedHelpTab
        help_tab = NeedHelpTab(self.tabs)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, help_tab, "Troubleshoot")
        self.tabs.setCurrentIndex(0)
