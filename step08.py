# step08.py

import monitor
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel
from PySide6.QtCore import Qt, Signal

class Step08Tab(QWidget):
    new_connection_signal = Signal(str)  # Signal for thread-safe GUI updates

    def __init__(self, tabs, selected_interface):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = selected_interface

        layout = QVBoxLayout()

        title = QLabel("\nFirst Network Connections Monitoring\n")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("These are first-time network connections detected automatically on your network:")
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("font-size: 14px; margin-bottom: 10px;")
        layout.addWidget(desc)

        self.text_box = QTextEdit()
        self.text_box.setReadOnly(True)
        self.text_box.setStyleSheet("""
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
        layout.addWidget(self.text_box)

        self.setLayout(layout)

        self.text_box.setPlainText("🔍 Waiting for first network connections...")
        self.first_message_received = False

        # Connect signal to function
        self.new_connection_signal.connect(self.display_first_connection)

        # Register this screen's callback
        monitor.first_connection_callback = self.safe_display_first_connection

    def safe_display_first_connection(self, text):
        self.new_connection_signal.emit(text)

    def display_first_connection(self, text):
        if not self.first_message_received:
            self.text_box.clear()
            self.first_message_received = True
        self.text_box.append(text)
