from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import time

CHROMEDRIVER_PATH = r"C:\Users\bisha\OneDrive\Desktop\fuck\chromedriver-win64\chromedriver.exe"
ROUTER_URL = "http://192.168.8.1"
USERNAME = "user"
PASSWORD = "MjXDdfXT"

def get_connected_devices():
    all_devices = []
    try:
        service = Service(CHROMEDRIVER_PATH)
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')          # ✅ run silently
        options.add_argument('--disable-gpu')       # for compatibility
        options.add_argument('--no-sandbox')        # safety in headless
        options.add_argument('--log-level=3')       # suppress warnings
        driver = webdriver.Chrome(service=service, options=options)
        wait = WebDriverWait(driver, 15)

        driver.get(ROUTER_URL)

        # Login if required
        try:
            login_link = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.ID, "loginlink"))
            )
            login_link.click()
            wait.until(EC.presence_of_element_located((By.ID, "txtUsr")))
            wait.until(EC.presence_of_element_located((By.ID, "txtPwd")))
            driver.find_element(By.ID, "txtUsr").clear()
            driver.find_element(By.ID, "txtUsr").send_keys(USERNAME)
            driver.find_element(By.ID, "txtPwd").clear()
            driver.find_element(By.ID, "txtPwd").send_keys(PASSWORD)
            driver.find_element(By.XPATH, '//input[@value="Login"]').click()
            time.sleep(5)
        except Exception:
            pass  # Login not needed or already done

        # Navigate to Device Settings → Connected Devices
        device_settings_tab = wait.until(
            EC.element_to_be_clickable((By.XPATH, '//a[@onclick="tosms(\'#device_settings\')"]'))
        )
        device_settings_tab.click()
        time.sleep(2)

        connected_tab = wait.until(
            EC.element_to_be_clickable((By.XPATH, '//a[@data-trans="station_info"]'))
        )
        connected_tab.click()
        time.sleep(6)  # give enough time for JS rendering

        soup = BeautifulSoup(driver.page_source, "html.parser")

        # Wireless devices
        wireless_rows = soup.select('tbody[data-bind="foreach:deviceInfo"] tr')
        for row in wireless_rows:
            cols = row.find_all("td")
            if len(cols) >= 6:
                hostname = cols[2].text.strip()
                ip = cols[3].text.strip()
                mac = cols[5].text.strip()
                all_devices.append((hostname or "Unknown", ip, mac))

        # Wired devices
        cable_rows = soup.select('tbody[data-bind="foreach:cableDeviceInfo"] tr')
        for row in cable_rows:
            cols = row.find_all("td")
            if len(cols) >= 5:
                hostname = cols[1].text.strip()
                ip = cols[2].text.strip()
                mac = cols[4].text.strip()
                all_devices.append((hostname or "Unknown", ip, mac))

        # Remove duplicates based on MAC
        seen_macs = set()
        unique_devices = []
        for host, ip, mac in all_devices:
            if mac not in seen_macs:
                seen_macs.add(mac)
                unique_devices.append((host, ip, mac))

        return unique_devices

    except Exception as e:
        print("Router fetch error:", e)
        return []

    finally:
        try:
            driver.quit()
        except:
            pass
