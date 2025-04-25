import sys
import subprocess
import platform
from PySide6.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTextEdit, QScrollArea, QFrame
)
from PySide6.QtCore import Qt

from main import check_cable_or_wifi_gui

def list_interfaces():
    if platform.system() != "Windows":
        return []

    result = subprocess.getoutput("netsh interface show interface")
    lines = result.strip().splitlines()[3:]  # Skip header
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
        self.label_name.setObjectName("interfaceName")

        self.label_status = QLabel(state)
        self.label_status.setAlignment(Qt.AlignCenter)
        self.label_status.setObjectName("interfaceStatus")

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.label_name)
        self.layout.addWidget(self.label_status)
        self.setLayout(self.layout)

        self.update_style(selected=False)

    def mousePressEvent(self, event):
        self.click_callback(self.name)

    def update_style(self, selected=False):
        color = "green" if self.state.lower() == "connected" else "red"
        if selected:
            self.setStyleSheet("QFrame#interfaceCard { border: 2px solid #007bff; background-color: #007bff; border-radius: 8px; padding: 10px; }")
            self.label_name.setStyleSheet("color: white; font-weight: 600;")
            self.label_status.setStyleSheet("color: white; font-weight: bold;")
        else:
            self.setStyleSheet(f"QFrame#interfaceCard {{ border: 2px solid {color}; border-radius: 8px; padding: 10px; background-color: white; }}")
            self.label_name.setStyleSheet("color: black; font-weight: 600;")
            self.label_status.setStyleSheet(f"color: {color}; font-weight: bold;")

class Step01Tab(QWidget):
    def __init__(self):
        super().__init__()
        self.selected_card = None

        self.layout = QVBoxLayout()

        self.title = QLabel("Step 01\nPhysical Connectivity Check")
        self.title.setAlignment(Qt.AlignHCenter)
        self.title.setStyleSheet("font-size: 24px; font-weight: bold;")
        self.layout.addWidget(self.title)

        self.desc = QLabel("Choose your network interface that you’re using right now:")
        self.desc.setAlignment(Qt.AlignHCenter)
        self.layout.addWidget(self.desc)

        self.button_container = QVBoxLayout()
        self.interface_cards = []
        self.load_interface_buttons()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_content.setLayout(self.button_container)
        scroll.setStyleSheet("QWidget { background-color: transparent; }")
        scroll.setWidget(scroll_content)
        self.layout.addWidget(scroll)

        self.status_label = QLabel("Status:")
        self.layout.addWidget(self.status_label)

        self.status_box = QTextEdit()
        self.status_box.setReadOnly(True)
        self.status_box.setStyleSheet("background: #0f1b2a; color: white; font-size: 14px; border-radius: 10px; padding: 10px;")
        self.layout.addWidget(self.status_box)

        self.next_btn = QPushButton("Next  »»")
        self.next_btn.setStyleSheet("background-color: #0094ff; color: white; padding: 8px 20px; border-radius: 6px;")

        next_btn_layout = QHBoxLayout()
        next_btn_layout.addStretch()
        next_btn_layout.addWidget(self.next_btn)
        self.layout.addLayout(next_btn_layout)

        self.setLayout(self.layout)

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
            text += "\n\n📋 Additional Physical Checks:\n" + "\n".join(guidance)
        self.status_box.setText(text)

        for card in self.interface_cards:
            card.update_style(selected=(card.name == name))

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Troubleshoot Application")
        self.setMinimumSize(800, 600)
        self.setStyleSheet(open("style.qss", "r").read())

        layout = QVBoxLayout()

        self.tabs = QTabWidget()
        self.tabs.addTab(Step01Tab(), "Troubleshoot")
        self.tabs.addTab(QWidget(), "First Network Connections")
        self.tabs.addTab(QWidget(), "Anomaly Notifications")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())