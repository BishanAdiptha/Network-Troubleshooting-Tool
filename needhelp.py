# needhelp.py
from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout
from PySide6.QtCore import Qt

class NeedHelpTab(QWidget):
    def __init__(self, tabs):
        super().__init__()
        self.tabs = tabs

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop)

        # 🔵 Title
        title = QLabel("\nNeed More Help?\n")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 28px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        # 🔵 Black Status Box
        self.status_box = QTextEdit()
        self.status_box.setReadOnly(True)
        self.status_box.setStyleSheet("""
            QTextEdit {
                background: #0f1b2a;
                color: white;
                font-family: Consolas;
                font-size: 16px;
                border-radius: 12px;
                padding: 14px;
                border: none;
            }
        """)
        layout.addWidget(self.status_box)

        # Insert the help messages inside black box
        help_text = """
<span style='color: deepskyblue;'>Restart your PC:</span><br>
If you've tried the previous steps but you're still not connected, restarting your PC often fixes connection issues.<br><br>
<span style='color: deepskyblue;'>Still not working?</span><br>
If restarting doesn’t help, contact your <b>ISP</b> or a professional network technician.
"""
        self.status_box.setHtml(help_text)

        # 🔵 Previous Button
        self.prev_btn = QPushButton("««  Previous")
        self.prev_btn.setStyleSheet("""
            QPushButton {
                background-color: #0094ff;
                color: white;
                padding: 10px 20px;
                border-radius: 8px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #007acc;
            }
        """)
        self.prev_btn.clicked.connect(self.go_back_to_step7)

        nav_layout = QHBoxLayout()
        nav_layout.addWidget(self.prev_btn)
        nav_layout.setAlignment(Qt.AlignCenter)
        layout.addLayout(nav_layout)

        self.setLayout(layout)

    def go_back_to_step7(self):
        from step07 import Step07Tab
        step7 = Step07Tab(self.tabs, selected_interface="Ethernet")  # 🔵 Pass real selected_interface dynamically if possible
        self.tabs.removeTab(0)
        self.tabs.insertTab(0, step7, "Troubleshoot")
        self.tabs.setCurrentIndex(0)
