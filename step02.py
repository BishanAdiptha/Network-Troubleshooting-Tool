# step02.py
import platform
import subprocess
import re
from PySide6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCursor

from main import check_ip_and_dhcp_info

class Step02Tab(QWidget):
    def __init__(self, tabs, selected_interface):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = selected_interface

        layout = QVBoxLayout()

        title = QLabel("\nStep 02\nIP/DHCP Diagnostics\n")
        title.setAlignment(Qt.AlignHCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("Checking your IP address and DHCP settings...")
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
        self.prev_btn.clicked.connect(self.go_back_to_step1)

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
        self.next_btn.clicked.connect(self.go_to_step3)

        nav_layout = QHBoxLayout()
        nav_layout.addWidget(self.prev_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)

        layout.addLayout(nav_layout)
        self.setLayout(layout)

        # 🚀 Animation delay
        self.output_box.setPlainText("🔍 Running IP and DHCP diagnostics...\n\nPlease wait...")
        QTimer.singleShot(500, self.run_diagnostics)

    def run_diagnostics(self):
        if platform.system() != "Windows":
            self.output_box.setText("⚠️ This diagnostic tool only works on Windows.")
            return

        ipconfig_output = subprocess.getoutput("ipconfig /all")
        ipconfig_filtered = self.extract_ipconfig_section(ipconfig_output, self.selected_interface)
        dhcp_diagnostics = check_ip_and_dhcp_info(self.selected_interface)

        self.output_box.clear()

        # Typing animation preparation
        self.lines_to_show = []

        # Windows IP Config Section
        for line in ipconfig_filtered.strip().splitlines():
            safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(" ", "&nbsp;")
            self.lines_to_show.append(f'<span style="color: white;">{safe_line}</span>')

        self.lines_to_show.append("")  # gap line

        # DHCP check lines with colors
        color_mapping = {
            "✅": "limegreen",
            "⚠️": "orange",
            "❌": "red",
            "💡": "deepskyblue"
        }

        for line in dhcp_diagnostics.strip().splitlines():
            color = "white"
            for symbol, c in color_mapping.items():
                if line.startswith(symbol):
                    color = c
                    break
            safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(" ", "&nbsp;")
            self.lines_to_show.append(f'<span style="color: {color};">{safe_line}</span>')

        # Start animation
        self.current_line_index = 0
        self.cursor = self.output_box.textCursor()
        self.timer = QTimer()
        self.timer.timeout.connect(self.insert_next_line)
        self.timer.start(120)

    def insert_next_line(self):
        if self.current_line_index < len(self.lines_to_show):
            self.cursor.insertHtml(self.lines_to_show[self.current_line_index] + "<br>")
            self.output_box.setTextCursor(self.cursor)
            self.current_line_index += 1
        else:
            self.timer.stop()

    def extract_ipconfig_section(self, output, selected_interface):
        blocks = re.split(r"\r?\n(?=\S)", output.strip())
        global_block = ""
        selected_block = ""
        selected_interface_lower = selected_interface.lower().strip()

        for block in blocks:
            lines = block.strip().splitlines()
            if not lines:
                continue
            header = lines[0].strip().lower()

            if header == "windows ip configuration":
                global_block = block.strip()
            elif (f"ethernet adapter {selected_interface_lower}:" in header or
                  f"wireless lan adapter {selected_interface_lower}:" in header):
                selected_block = block.strip()

        formatted_global = self.format_block(global_block)
        formatted_selected = self.format_block(selected_block)

        return f"{formatted_global}\n\n{formatted_selected}" if formatted_selected else formatted_global

    def format_block(self, block):
        lines = block.splitlines()
        formatted_lines = []
        for line in lines:
            if ":" in line:
                left, right = line.split(":", 1)
                formatted_lines.append(f"{left.strip():<40}: {right.strip()}")
            else:
                formatted_lines.append(line.strip())
        return "\n".join(formatted_lines)

    def go_back_to_step1(self):
        from gui import Step01Tab
        step1 = Step01Tab(self.tabs)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step1, "Troubleshoot")
        self.tabs.setCurrentIndex(0)

    def go_to_step3(self):
        from step03 import Step03Tab
        step3 = Step03Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step3, "Troubleshoot")
        self.tabs.setCurrentIndex(0)
