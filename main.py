import scapy.all as scapy
import time
import collections
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging
import subprocess
import platform
import threading
import tkinter as tk
from tkinter import scrolledtext

# GUI Design Variables
WINDOW_BG_COLOR = "#adb5bd"
TEXT_COLOR = "#001219"
BUTTON_COLOR = "#ced4da"

# Set up logging to both console and file
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler('ddos_detection.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(file_handler)

# Global variables for packet monitoring and detection
running = False
packet_rates = collections.defaultdict(int)
source_ips = collections.defaultdict(int)
blocked_ips = collections.defaultdict(float)  # Blocked IPs with their unblock time
traffic_data = pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_length'])
if_model = IsolationForest(contamination=0.5)
scaler = StandardScaler()

whitelist = set(['192.168.1.1', '10.0.0.1'])
blacklist = set()

def block_ip(ip):
    """Block a suspicious IP using netsh on Windows"""
    if platform.system() == "Windows":
        logging.info(f"Blocking IP: {ip}")
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=Block_IP_" + ip, "dir=in", "action=block", "remoteip=" + ip], check=True)
        except Exception as e:
            logging.error(f"Failed to block IP {ip}: {e}")

def unblock_ip(ip):
    """Unblock a previously blocked IP using netsh on Windows"""
    if platform.system() == "Windows":
        logging.info(f"Unblocking IP: {ip}")
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=Block_IP_" + ip], check=True)
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip}: {e}")

def detect_ddos(packet):
    if not running:
        return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    protocol = packet[scapy.IP].proto
    packet_length = len(packet)

    if src_ip in whitelist:
        return

    packet_rates[src_ip] += 1
    source_ips[src_ip] += 1

    # Add traffic to dataframe
    global traffic_data
    traffic_data.loc[len(traffic_data)] = [time.time(), src_ip, dst_ip, protocol, packet_length]
    
    # Update the traffic display in the GUI
    traffic_monitor_text.insert(tk.END, f"{time.time()} - {src_ip} -> {dst_ip} - Protocol: {protocol}, Length: {packet_length}\n")
    traffic_monitor_text.see(tk.END)

    if packet_rates[src_ip] > 100:
        if src_ip not in blacklist:
            block_ip(src_ip)
            blacklist.add(src_ip)
            blocked_ips[src_ip] = time.time() + 60
            blocked_ips_listbox.insert(tk.END, f"{src_ip}")

    # Anomaly detection using Isolation Forest
    if len(traffic_data) > 100:
        normalized_data = scaler.fit_transform(traffic_data[['packet_length']])
        predictions = if_model.fit_predict(normalized_data)
        anomalies = traffic_data[predictions == -1]

        for idx, row in anomalies.iterrows():
            anomaly_ip = row['src_ip']
            if anomaly_ip not in whitelist and anomaly_ip not in blacklist:
                block_ip(anomaly_ip)
                blacklist.add(anomaly_ip)
                blocked_ips[anomaly_ip] = time.time() + 60
                blocked_ips_listbox.insert(tk.END, f"{anomaly_ip}")

    for ip, unblock_time in list(blocked_ips.items()):
        if time.time() > unblock_time:
            unblock_ip(ip)
            blacklist.remove(ip)
            blocked_ips_listbox.delete(tk.END)
            del blocked_ips[ip]

    if time.time() % 1 == 0:
        packet_rates.clear()

def start_protection():
    global running
    running = True
    sniff_thread = threading.Thread(target=lambda: scapy.sniff(filter="ip", prn=detect_ddos))
    sniff_thread.daemon = True
    sniff_thread.start()

def stop_protection():
    global running
    running = False

# GUI Setup
window = tk.Tk()
window.title("DDoS Detection and Protection")
window.geometry("800x600")
window.config(bg=WINDOW_BG_COLOR)

# Traffic monitor text box
traffic_monitor_label = tk.Label(window, text="Traffic Monitor", bg=WINDOW_BG_COLOR, fg=TEXT_COLOR)
traffic_monitor_label.pack(pady=10)
traffic_monitor_text = scrolledtext.ScrolledText(window, width=100, height=20, bg="#f8f9fa", fg=TEXT_COLOR)
traffic_monitor_text.pack(pady=10)

# Blocked IPs list box
blocked_ips_label = tk.Label(window, text="Blocked IPs", bg=WINDOW_BG_COLOR, fg=TEXT_COLOR)
blocked_ips_label.pack(pady=10)
blocked_ips_listbox = tk.Listbox(window, width=50, height=10, bg="#f8f9fa", fg=TEXT_COLOR)
blocked_ips_listbox.pack(pady=10)

# Buttons for controlling protection
start_button = tk.Button(window, text="Start Protection", command=start_protection, bg=BUTTON_COLOR, fg=TEXT_COLOR)
start_button.pack(pady=10)

stop_button = tk.Button(window, text="Stop Protection", command=stop_protection, bg=BUTTON_COLOR, fg=TEXT_COLOR)
stop_button.pack(pady=10)

window.mainloop()
