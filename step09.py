# step09.py

import anomaly
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel
from PySide6.QtCore import Qt, Signal

class Step09Tab(QWidget):
    new_anomaly_signal = Signal(str)  # Create a signal to safely update GUI from threads

    def __init__(self, tabs):
        super().__init__()
        self.tabs = tabs

        layout = QVBoxLayout()

        title = QLabel("\nAnomaly Notifications\n")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        desc = QLabel("Real-time anomaly detections will appear below if suspicious activity occurs:")
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

        self.text_box.setPlainText("🔍 Waiting for anomaly detections...")
        self.first_anomaly_received = False

        # Connect the signal to the function
        self.new_anomaly_signal.connect(self.display_anomaly)

        # Assign our safe function to anomaly.py
        anomaly.anomaly_callback = self.safe_display_anomaly

    def safe_display_anomaly(self, text):
        self.new_anomaly_signal.emit(text)

    def display_anomaly(self, text):
        if not self.first_anomaly_received:
            self.text_box.clear()
            self.first_anomaly_received = True
        self.text_box.append(text)
