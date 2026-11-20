from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import time

# Track ports accessed by each source IP: {src_ip: [(port, timestamp), ...]}
port_scan_tracker = defaultdict(list)

# Detection thresholds
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 5

def detect_port_scan(src_ip, dst_port):
    current_time = time.time()
    
    # Keep only timestamps within the active TIME_WINDOW
    port_scan_tracker[src_ip] = [
        (port, ts) for port, ts in port_scan_tracker[src_ip]
        if current_time - ts <= TIME_WINDOW
    ]
    
    # Record the current destination port and timestamp
    port_scan_tracker[src_ip].append((dst_port, current_time))
    
    # Count unique ports probed by this IP
    unique_ports = {port for port, _ in port_scan_tracker[src_ip]}
    
    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = (f"[{timestamp}] [ALERT] Potential Port Scan detected from {src_ip}! "
                     f"Probed {len(unique_ports)} ports in {TIME_WINDOW}s.")
        
        print(f"\n{alert_msg}\n")
        
        # Save alert to a permanent log file
        with open("security_alerts.log", "a") as log_file:
            log_file.write(alert_msg + "\n")
            
        port_scan_tracker[src_ip].clear()

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags}")
            
            # Monitor SYN packets for potential port scanning
            if flags == "S":
                detect_port_scan(src_ip, dst_port)
                
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def start_sniffer():
    print("Starting Network Packet Sniffer & Traffic Analyzer...")
    print("Press Ctrl+C to stop.\n")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffer()
