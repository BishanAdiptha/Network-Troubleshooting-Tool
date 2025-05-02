#step09.py
import anomaly
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel
from PySide6.QtCore import Qt, QTimer

class Step09Tab(QWidget):
    def __init__(self, tabs):
        super().__init__()
        self.tabs = tabs
        self.first_anomaly_received = False

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

        self.timer = QTimer()
        self.timer.timeout.connect(self.poll_anomaly_queue)
        self.timer.start(500)

    def poll_anomaly_queue(self):
        while not anomaly.anomaly_queue.empty():
            message = anomaly.anomaly_queue.get()
            self.display_anomaly(message)

    def display_anomaly(self, text):
        if not self.first_anomaly_received:
            self.text_box.clear()
            self.first_anomaly_received = True
        self.text_box.append(text)
