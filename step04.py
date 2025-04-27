# step04.py
import platform
import subprocess
import socket
from PySide6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCursor
from main import check_dns_resolution

class Step04Tab(QWidget):
    def __init__(self, tabs, selected_interface):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = selected_interface

        layout = QVBoxLayout()

        title = QLabel("\nStep 04\nDNS Resolution Check\n")
        title.setAlignment(Qt.AlignHCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("Checking if DNS is resolving domain names properly...")
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
        self.prev_btn.clicked.connect(self.go_back_to_step3)

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
        self.next_btn.clicked.connect(self.go_to_step5)

        nav_layout = QHBoxLayout()
        nav_layout.addWidget(self.prev_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)

        layout.addLayout(nav_layout)
        self.setLayout(layout)

        # ✨ Immediate animation start
        self.output_box.setPlainText("🌐 Attempting to resolve DNS for google.com...\n\nPlease wait...")
        QTimer.singleShot(500, self.check_dns_resolution_step04)




    def check_dns_resolution_step04(self):
        success, error_message = check_dns_resolution()


        self.output_box.clear()
        self.lines_to_show = []

        self.lines_to_show.append('<span style="color: deepskyblue;">🌐 Attempting to resolve DNS for google.com...</span>')

        if success:
            self.lines_to_show.append('<span style="color: limegreen;">✅ DNS resolution successful. Domain reachable.</span>')
        else:
            self.lines_to_show.append('<span style="color: red;">❌ DNS resolution failed.</span>')
            self.lines_to_show.append(f'<span style="color: white;">Error: {error_message}</span>')
            self.lines_to_show.append('<span style="color: deepskyblue;">💡 Suggested Steps:</span>')
            self.lines_to_show.append('<span style="color: white;"> - Check your DNS settings</span>')
            self.lines_to_show.append('<span style="color: white;"> - Try setting 8.8.8.8 or 1.1.1.1 manually</span>')


        self.current_line_index = 0
        self.cursor = self.output_box.textCursor()
        self.timer = QTimer()
        self.timer.timeout.connect(self.insert_next_line)
        self.timer.start(100)


    def insert_next_line(self):
        if self.current_line_index < len(self.lines_to_show):
            self.cursor.insertHtml(self.lines_to_show[self.current_line_index] + "<br>")
            self.output_box.setTextCursor(self.cursor)
            self.current_line_index += 1
        else:
            self.timer.stop()

    def go_back_to_step3(self):
        from step03 import Step03Tab
        step3 = Step03Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step3, "Troubleshoot")
        self.tabs.setCurrentIndex(0)

    def go_to_step5(self):
        from step05 import Step05Tab
        step5 = Step05Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step5, "Troubleshoot")
        self.tabs.setCurrentIndex(0)

        
