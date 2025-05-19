# step03.py
import platform
import subprocess
import re
from PySide6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCursor

from main import ping_router

class Step03Tab(QWidget):
    def __init__(self, tabs, selected_interface):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = selected_interface

        layout = QVBoxLayout()

        title = QLabel("\nStep 03\nRouter Status Check\n")
        title.setAlignment(Qt.AlignHCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("Checking if your router is reachable by pinging the gateway...")
        desc.setStyleSheet("font-size: 14px; color: black; margin-bottom: 10px;")
        layout.addWidget(desc)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setStyleSheet("""
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
        layout.addWidget(self.output_box)

        self.prev_btn = QPushButton("««  Previous")
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
        self.prev_btn.clicked.connect(self.go_back_to_step2)

        self.next_btn = QPushButton("Next  »»")
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
        self.next_btn.clicked.connect(self.go_to_step4)

        nav_layout = QHBoxLayout()
        nav_layout.addWidget(self.prev_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)

        layout.addLayout(nav_layout)
        self.setLayout(layout)

        self.output_box.setPlainText("🌐 Detecting default gateway and checking router reachability...\n\nPlease wait...")
        QTimer.singleShot(500, self.check_router)

    def check_router(self):
        if platform.system() != "Windows":
            self.output_box.setText("⚠️ This tool only supports Windows.")
            return

        default_gateway = self.extract_default_gateway()

        if not default_gateway:
            self.output_box.setText("❌ No default gateway detected. Cannot perform router ping check.")
            return

        ping_result, success = ping_router(default_gateway)

        self.output_box.clear()
        self.lines_to_show = []

        self.lines_to_show.append(f'<span style="color: deepskyblue;">🌐 Default Gateway detected: {default_gateway}</span>')
        self.lines_to_show.append("")

        for line in ping_result.splitlines():
            safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(" ", "&nbsp;")
            self.lines_to_show.append(f'<span style="color: white;">{safe_line}</span>')

        self.lines_to_show.append("")

        if success:
            self.lines_to_show.append(f'<span style="color: limegreen;">✅ Router is reachable at {default_gateway}</span>')
        else:
            self.lines_to_show.append(f'<span style="color: red;">❌ Router is NOT reachable at {default_gateway}</span>')
            self.lines_to_show.append('<span style="color: deepskyblue;">💡 Suggested Steps:</span>')
            self.lines_to_show.append('<span style="color: white;"> - Check Ethernet/Wi-Fi connection</span>')
            self.lines_to_show.append('<span style="color: white;"> - Restart your router</span>')
            self.lines_to_show.append('<span style="color: white;"> - Ensure router is powered ON</span>')

        self.current_line_index = 0
        self.cursor = self.output_box.textCursor()
        self.timer = QTimer()
        self.timer.timeout.connect(self.insert_next_line)
        self.timer.start(150)

    def insert_next_line(self):
        if self.current_line_index < len(self.lines_to_show):
            self.cursor.insertHtml(self.lines_to_show[self.current_line_index] + "<br>")
            self.output_box.setTextCursor(self.cursor)
            self.current_line_index += 1
        else:
            self.timer.stop()

    def extract_default_gateway(self):
        try:
            output = subprocess.getoutput("netsh interface ip show config")
            matches = re.findall(r"Default Gateway:\s+(\d+\.\d+\.\d+\.\d+)", output)
            if matches:
                return matches[0]
        except:
            pass
        return ""

    def go_back_to_step2(self):
        from step02 import Step02Tab
        step2 = Step02Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step2, "Troubleshoot")
        self.tabs.setCurrentIndex(0)

    def go_to_step4(self):
        from step04 import Step04Tab
        step4 = Step04Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step4, "Troubleshoot")
        self.tabs.setCurrentIndex(0)
