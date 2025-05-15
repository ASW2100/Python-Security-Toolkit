from scapy.all import sniff, TCP, IP
from collections import defaultdict
from datetime import datetime
import os

ALERT_THRESHOLD = 100  # Number of SYN packets from same IP
TIME_WINDOW = 60       # Time window in seconds

# Store SYN count per IP
syn_counts = defaultdict(list)

def log_alert(ip, count):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[{timestamp}] 🚨 ALERT: Possible SYN flood from {ip} ({count} SYNs)\n"
    print(alert_msg.strip())

    log_file = os.path.join(os.getcwd(), "ids_alerts.log")
    try:
        with open(log_file, "a") as f:
            f.write(alert_msg)
    except Exception as e:
        print(f"[!] Error writing to log file: {e}")

def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip = packet[IP].src
        tcp = packet[TCP]

        # Check for SYN flag
        if tcp.flags & 0x02:  # SYN flag is the second bit (0x02)
            syn_counts[ip].append(datetime.now())

            # Remove timestamps outside the window
            recent_times = [
                t for t in syn_counts[ip]
                if (datetime.now() - t).total_seconds() <= TIME_WINDOW
            ]
            syn_counts[ip] = recent_times

            if len(recent_times) > ALERT_THRESHOLD:
                log_alert(ip, len(recent_times))

def run():
    print("CyberSecBox - IDS Simulator (Press Ctrl+C to stop)")
    print(f"Monitoring SYN floods... (>{ALERT_THRESHOLD} SYNs in {TIME_WINDOW}s)\n")

    try:
        sniff(filter="tcp", prn=process_packet, store=False)
    except PermissionError:
        print("[!] You must run this script with sudo or admin privileges.")
    except KeyboardInterrupt:
        print("\n[+] IDS stopped.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")