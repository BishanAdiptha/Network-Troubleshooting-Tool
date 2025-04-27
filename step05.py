# step05.py
import platform
import subprocess
from PySide6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCursor

class Step05Tab(QWidget):
    def __init__(self, tabs, selected_interface):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = selected_interface

        layout = QVBoxLayout()

        title = QLabel("\nStep 05\nInternet Access Check\n")
        title.setAlignment(Qt.AlignHCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("Checking if your internet is accessible by pinging 8.8.8.8...")
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
        self.prev_btn.clicked.connect(self.go_back_to_step4)

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
        self.next_btn.clicked.connect(self.go_to_step6)

        nav_layout = QHBoxLayout()
        nav_layout.addWidget(self.prev_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)

        layout.addLayout(nav_layout)
        self.setLayout(layout)

        self.output_box.setPlainText("🌎 Pinging 8.8.8.8 to check internet access...\n\nPlease wait...")
        QTimer.singleShot(500, self.check_internet_access)

    def check_internet_access(self):
        command = "ping -n 4 8.8.8.8" if platform.system() == "Windows" else "ping -c 4 8.8.8.8"
        result = subprocess.getoutput(command)

        success = "TTL=" in result or "bytes from" in result

        self.output_box.clear()
        self.lines_to_show = []

        self.lines_to_show.append('<span style="color: deepskyblue;">🌎 Pinging 8.8.8.8 to check internet access...</span>')
        safe_result = result.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>").replace(" ", "&nbsp;")
        self.lines_to_show.append(f'<pre style="color: white;">{safe_result}</pre>')

        if success:
            self.lines_to_show.append('<span style="color: limegreen;">✅ Internet is accessible!</span>')
        else:
            self.lines_to_show.append('<span style="color: red;">❌ Cannot reach the internet.</span>')
            self.lines_to_show.append('<span style="color: deepskyblue;">💡 Suggested Steps:</span>')
            self.lines_to_show.append('<span style="color: white;"> - Check Wi-Fi/Ethernet connection</span>')
            self.lines_to_show.append('<span style="color: white;"> - Restart your router or modem</span>')
            self.lines_to_show.append('<span style="color: white;"> - Contact your ISP</span>')

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

    def go_back_to_step4(self):
        from step04 import Step04Tab
        step4 = Step04Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step4, "Troubleshoot")
        self.tabs.setCurrentIndex(0)

    def go_to_step6(self):
        from step06 import Step06Tab
        step6 = Step06Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step6, "Troubleshoot")
        self.tabs.setCurrentIndex(0)
