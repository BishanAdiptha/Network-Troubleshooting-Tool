# step06.py
import subprocess
import platform
import speedtest
from PySide6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCursor



class Step06Tab(QWidget):
    def __init__(self, tabs, selected_interface):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = selected_interface

        layout = QVBoxLayout()

        title = QLabel("\nStep 06\nSpeed Test\n")
        title.setAlignment(Qt.AlignHCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("Checking your network download and upload speed...")
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
        self.prev_btn.clicked.connect(self.go_back_to_step5)

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
        self.next_btn.clicked.connect(self.go_to_step7)

        nav_layout = QHBoxLayout()  # ✅ Create nav_layout here
        nav_layout.addWidget(self.prev_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)
        layout.addLayout(nav_layout)


        self.setLayout(layout)

        self.output_box.setPlainText("🚀 Testing network speed...\n\nPlease wait...")
        QTimer.singleShot(500, self.run_speed_test)

    def run_speed_test(self):
        self.output_box.clear()
        self.lines_to_show = []

        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1_000_000  # Mbps
            upload_speed = st.upload() / 1_000_000      # Mbps

            self.lines_to_show.append('<span style="color: limegreen;">✅ Speed Test Successful</span>')
            self.lines_to_show.append(f'<span style="color: white;">⬇ Download Speed: {download_speed:.2f} Mbps</span>')
            self.lines_to_show.append(f'<span style="color: white;">⬆ Upload Speed: {upload_speed:.2f} Mbps</span>')

            if download_speed < 5:
                self.lines_to_show.append('<span style="color: orange;">⚠️ Download speed is low</span>')
            if upload_speed < 1:
                self.lines_to_show.append('<span style="color: orange;">⚠️ Upload speed is low</span>')

        except Exception as e:
            safe_error = str(e).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            self.lines_to_show.append(f'<span style="color: red;">❌ Speed Test Failed: {safe_error}</span>')

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

    def go_back_to_step5(self):
        from step05 import Step05Tab
        step5 = Step05Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step5, "Troubleshoot")
        self.tabs.setCurrentIndex(0)

    def go_to_step7(self):
        from step07 import Step07Tab
        step7 = Step07Tab(self.tabs, self.selected_interface)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step7, "Troubleshoot")
        self.tabs.setCurrentIndex(0)

