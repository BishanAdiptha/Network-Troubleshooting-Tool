import platform
import subprocess
import re
from PySide6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
)
from PySide6.QtCore import Qt

from main import check_ip_and_dhcp_info

class Step02Tab(QWidget):
    def __init__(self, tabs, selected_interface, switch_to_step3_callback):
        super().__init__()
        self.tabs = tabs
        self.selected_interface = selected_interface
        self.switch_to_step3_callback = switch_to_step3_callback

        layout = QVBoxLayout()

        self.title = QLabel("Step 02\nIP/DHCP Diagnostics")
        self.title.setAlignment(Qt.AlignHCenter)
        self.title.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(self.title)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setStyleSheet(
            "background: #0f1b2a; color: white; font-size: 14px; border-radius: 10px; padding: 10px;"
        )
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
        self.next_btn.clicked.connect(self.switch_to_step3_callback)

        nav_layout = QHBoxLayout()
        nav_layout.addWidget(self.prev_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_btn)

        layout.addLayout(nav_layout)
        self.setLayout(layout)

        self.run_diagnostics()

    def run_diagnostics(self):
        if platform.system() != "Windows":
            self.output_box.setText("⚠ This diagnostic tool only works on Windows.")
            return

        # Step 1: Extract filtered ipconfig output
        ipconfig_output = subprocess.getoutput("ipconfig /all")
        ipconfig_filtered = self.extract_ipconfig_section(ipconfig_output, self.selected_interface)

        # Step 2: Get additional DHCP checks output
        dhcp_diagnostics = check_ip_and_dhcp_info(self.selected_interface)

        # Step 3: Merge both nicely
        full_text = f"{ipconfig_filtered.strip()}\n\n-----\n\n{dhcp_diagnostics.strip()}"
        self.output_box.setText(full_text)

    def extract_ipconfig_section(self, ipconfig_output, selected_interface):
        blocks = re.split(r"\r?\n(?=\S)", ipconfig_output.strip())
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
                  f"wireless lan adapter {selected_interface_lower}:" in header or
                  f"unknown adapter {selected_interface_lower}:" in header):
                selected_block = block.strip()

        return f"{global_block}\n\n{selected_block}" if selected_block else global_block

    def go_back_to_step1(self):
        from gui import Step01Tab  # local import to avoid circular import
        step1 = Step01Tab(self.tabs)
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step1, "Troubleshoot")
        self.tabs.setCurrentIndex(0)
