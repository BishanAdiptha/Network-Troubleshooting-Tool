```
To install and begin using the Network Troubleshooting Tool with Anomaly Detection, follow these simple steps:

  System Requirements:
    - Ensure you are running Windows 10 or higher.
    - Install Python 3.10+

  Installation Steps:
    - Download the tool folder from zip file.
    - Open Command Prompt and navigate to the project directory.

  Run:
      pip install -r requirements.txt
    - to install all required libraries (e.g., PySide6, speedtest, scapy, pyshark).

  Grant Admin Permissions:
    - Right-click Command Prompt and Run as Administrator (required for packet sniffing).

  Run the Application:
    - In the project folder, execute:
      python gui.py
    - The graphical user interface will launch immediately.

  Using the Application:
    - Begin with Step 01: Physical Connectivity Check to select your active network.
    - Navigate through the tabs to test IP/DHCP, router reachability, DNS, and internet access.
    - Use Step 06 for speed testing, Step 07 for connected devices, and
    - Step 08/09 for real-time monitoring of new connections and anomaly alerts.

  Saving Logs (Optional):
    - Click the ☰ menu (top-right) and choose "Save Anomaly Logs" or "Save Network Connections" for offline review.
```
