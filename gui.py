#gui.py

import sys
import subprocess
import platform
import psutil
import socket
import threading
import shutil

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTabWidget, QScrollArea, QFrame,
    QLabel, QTextEdit, QPushButton, QHBoxLayout, QToolButton, QMenu,
    QMessageBox, QFileDialog, QDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor

from main import check_cable_or_wifi_gui
from step08 import Step08Tab
from step09 import Step09Tab
import monitor
import anomaly


def detect_internet_adapter():
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for interface, addresses in interfaces.items():
        if not stats.get(interface) or not stats[interface].isup:
            continue
        for addr in addresses:
            if addr.family == socket.AF_INET and not addr.address.startswith('169.') and addr.address != '0.0.0.0':
                try:
                    subprocess.check_output(["ping", "-n", "1", "-w", "500", "8.8.8.8"], timeout=2)
                    return interface
                except:
                    pass
    return None


def list_interfaces():
    if platform.system() != "Windows":
        return []
    result = subprocess.getoutput("netsh interface show interface")
    lines = result.strip().splitlines()[3:]
    interfaces = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            state = parts[1]
            name = " ".join(parts[3:])
            interfaces.append((name, state))
    return interfaces


def check_interface(name):
    return check_cable_or_wifi_gui(name)


class InterfaceCard(QFrame):
    def __init__(self, name, state, click_callback):
        super().__init__()
        self.name = name
        self.state = state
        self.click_callback = click_callback
        self.setObjectName("interfaceCard")

        self.label_name = QLabel(name)
        self.label_name.setAlignment(Qt.AlignCenter)

        self.label_status = QLabel(state)
        self.label_status.setAlignment(Qt.AlignCenter)

        layout = QVBoxLayout()
        layout.addWidget(self.label_name)
        layout.addWidget(self.label_status)
        self.setLayout(layout)

        self.update_style(selected=False)

    def mousePressEvent(self, event):
        self.click_callback(self.name)

    def update_style(self, selected=False):
        color = "green" if self.state.lower() == "connected" else "red"
        if selected:
            self.setStyleSheet("QFrame#interfaceCard { border: 2px solid #007bff; background: #007bff; border-radius: 8px; padding: 10px; }")
            self.label_name.setStyleSheet("color: white; font-weight: bold;")
            self.label_status.setStyleSheet("color: white; font-weight: bold;")
        else:
            self.setStyleSheet(f"QFrame#interfaceCard {{ border: 2px solid {color}; background: white; border-radius: 8px; padding: 10px; }}")
            self.label_name.setStyleSheet("color: black; font-weight: bold;")
            self.label_status.setStyleSheet(f"color: {color}; font-weight: bold;")


class Step01Tab(QWidget):
    def __init__(self, tabs):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = None

        layout = QVBoxLayout()

        title = QLabel("\nStep 01\nPhysical Connectivity Check\n")
        title.setAlignment(Qt.AlignHCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("Choose your network interface that you’re using right now:")
        layout.addWidget(desc)

        self.button_container = QVBoxLayout()
        self.interface_cards = []
        self.load_interface_buttons()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_content.setLayout(self.button_container)
        scroll.setStyleSheet("background: transparent;")
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

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

        next_btn = QPushButton("Next  »»")
        next_btn.setStyleSheet("""
            QPushButton {
                background: #0094ff;
                color: white;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #007acc;
            }
        """)
        next_btn.clicked.connect(self.go_to_step2)

        nav_layout = QHBoxLayout()
        nav_layout.addStretch()
        nav_layout.addWidget(next_btn)
        layout.addLayout(nav_layout)

        self.setLayout(layout)

    def load_interface_buttons(self):
        interfaces = list_interfaces()
        for name, state in interfaces:
            card = InterfaceCard(name, state, self.show_status)
            self.interface_cards.append(card)
            self.button_container.addWidget(card)

    def show_status(self, name):
        output, guidance = check_interface(name)
        text = output
        if guidance:
            text += "\n\n📋 Additional Physical Checks:\n\n" + "\n".join(guidance)

        self.selected_interface = name
        self.status_box.clear()

        lines_to_show = []
        color_mapping = {
            "✅": "limegreen", "⚠️": "orange", "❌": "red",
            "💡": "deepskyblue", "📋": "deepskyblue", "📶": "plum", "✈️": "plum"
        }

        for line in text.splitlines():
            color = "white"
            for symbol, c in color_mapping.items():
                if line.strip().startswith(symbol):
                    color = c
                    break
            safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            lines_to_show.append(f'<span style="color: {color};">{safe_line}</span>')

        cursor = self.status_box.textCursor()
        cursor.insertHtml("<pre style='font-family: Consolas;'>")
        for line in lines_to_show:
            cursor.insertHtml(line + "<br>")
        cursor.insertHtml("</pre>")
        cursor.movePosition(QTextCursor.End)

        for card in self.interface_cards:
            card.update_style(selected=(card.name == name))

    def go_to_step2(self):
        if not self.selected_interface:
            self.status_box.clear()
            self.status_box.setPlainText("⚠️ Please select an interface before proceeding.")
            return

        from step02 import Step02Tab
        step2 = Step02Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step2, "Troubleshoot")
        self.tabs.setCurrentIndex(0)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Troubleshoot Application")
        self.setMinimumSize(800, 600)

        try:
            with open("style.qss") as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            pass

        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane { border: none; }")
        self.tabs.addTab(Step01Tab(self.tabs), "Troubleshoot")

        auto_interface = detect_internet_adapter()
        if auto_interface:
            threading.Thread(target=monitor.start_monitoring, args=(auto_interface,), daemon=True).start()
            self.tabs.addTab(Step08Tab(self.tabs, auto_interface), "First Network Connections")
            self.tabs.addTab(Step09Tab(self.tabs), "Anomaly Notifications")
        else:
            self.tabs.addTab(QWidget(), "First Network Connections")
            self.tabs.addTab(QWidget(), "Anomaly Notifications")

        self.refresh_button = QToolButton()
        self.refresh_button.setText("⟳")
        self.refresh_button.setStyleSheet("font-size: 18px; margin-right: 4px;")
        self.refresh_button.clicked.connect(self.refresh_action)

        self.menu_button = QToolButton()
        self.menu_button.setText("☰")
        self.menu_button.setPopupMode(QToolButton.InstantPopup)
        self.menu_button.setStyleSheet("font-size: 18px; margin-right: 10px;")

        self.menu = QMenu(self)
        self.menu.setStyleSheet("""
            QMenu::item {
                padding: 6px 20px;
            }
            QMenu::item:selected {
                background-color: #0078d7;
                color: white;
            }
        """)

        self.menu.addAction("⚙ Settings", self.show_settings)
        self.menu.addAction("💾 Save Anomaly Logs", self.save_anomaly_logs)
        self.menu.addAction("💾 Save Network Connections", self.save_network_connections)
        self.menu.addAction("❓ Help", self.show_help)
        self.menu.addAction("📄 About", self.show_about)
        self.menu_button.setMenu(self.menu)

        corner_widget = QWidget()
        corner_layout = QHBoxLayout(corner_widget)
        corner_layout.setContentsMargins(0, 0, 0, 0)
        corner_layout.setSpacing(0)
        corner_layout.addWidget(self.refresh_button)
        corner_layout.addWidget(self.menu_button)
        self.tabs.setCornerWidget(corner_widget, Qt.TopRightCorner)

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def refresh_action(self):
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, Step01Tab(self.tabs), "Troubleshoot")

        self.tabs.removeTab(2)
        self.tabs.removeTab(1)

        auto_interface = detect_internet_adapter()
        if auto_interface:
            threading.Thread(target=monitor.start_monitoring, args=(auto_interface,), daemon=True).start()
            self.tabs.insertTab(1, Step08Tab(self.tabs, auto_interface), "First Network Connections")
            self.tabs.insertTab(2, Step09Tab(self.tabs), "Anomaly Notifications")
        else:
            self.tabs.insertTab(1, QWidget(), "First Network Connections")
            self.tabs.insertTab(2, QWidget(), "Anomaly Notifications")

        self.tabs.setCurrentIndex(0)

    def save_anomaly_logs(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Anomaly Logs", "anomaly_logs.txt", "Text Files (*.txt)")
        if file_path:
            shutil.copyfile("anomaly_logs.txt", file_path)

    def save_network_connections(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Network Connections", "first_network_connections.txt", "Text Files (*.txt)")
        if file_path:
            shutil.copyfile("first_network_connections.txt", file_path)

    def show_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setMinimumWidth(300)

        layout = QHBoxLayout(dialog)

        clear_anomaly_btn = QPushButton("🧹 Clear Anomaly Logs")
        clear_anomaly_btn.setStyleSheet("QPushButton:hover { background-color: #f08080; }")
        clear_anomaly_btn.clicked.connect(lambda: open("anomaly_logs.txt", "w").close())

        clear_network_btn = QPushButton("🧹 Clear Network Connections")
        clear_network_btn.setStyleSheet("QPushButton:hover { background-color: #f08080; }")
        clear_network_btn.clicked.connect(lambda: open("first_network_connections.txt", "w").close())

        layout.addWidget(clear_anomaly_btn)
        layout.addWidget(clear_network_btn)
        dialog.setLayout(layout)
        dialog.exec()

    def show_help(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Help")
        msg.setTextFormat(Qt.RichText)
        msg.setText(
            'For support, contact the developer through <a href="https://www.linkedin.com/in/bishan-ranamuka-18aa4726b" style="color:#007bff;">LinkedIn</a>.'
        )
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setStyleSheet("QLabel { color: black; font-size: 14px; }")
        msg.setIcon(QMessageBox.Information)
        msg.setTextInteractionFlags(Qt.TextBrowserInteraction)
        msg.exec()

    def show_about(self):
        QMessageBox.about(self, "About", "Network Troubleshoot Application\nVersion 1.0\n© 2025 Bishan Adiptha")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
