#!/usr/bin/env python
# detect.py - DDoS Detection Engine (Optimized for Windows)
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
import sys
import time
import pandas as pd
import joblib
import numpy as np
from collections import defaultdict
import platform
import os
import threading

# Fix Windows console and Scapy performance
if platform.system() == "Windows":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    # Increase Scapy performance on Windows
    conf.sniff_promisc = True
    conf.bufsize = 65536  # Increase buffer size

print("[+] CyberShield Detection Engine Starting...", flush=True)
print("[+] Platform: Windows", flush=True)

# Load ML Model
model = None
try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "model.pkl")
    
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        print("[+] ML Model loaded", flush=True)
    else:
        print("[!] No ML model found - using rule-based detection", flush=True)
except Exception as e:
    print(f"[!] Model error: {e}", flush=True)

# Globals
packet_buffer = []
start_time = time.time()
attack_count = 0
ip_counts = defaultdict(int)
total_packets = 0
baseline_rate = 0
baseline_established = False
normal_traffic_samples = []
last_attack_print = 0

def extract_ml_features(packets):
    if len(packets) == 0:
        return None
    
    total_packets = len(packets)
    timestamps = [pkt.time for pkt in packets]
    
    if len(timestamps) > 1:
        duration = timestamps[-1] - timestamps[0]
    else:
        duration = 1
    
    if duration <= 0:
        duration = 1
    
    rate = total_packets / duration
    
    df = pd.DataFrame([[duration, total_packets, rate]],
                      columns=["Flow Duration", "Total Packets", "Flow Pkts/s"])
    return df

def packet_callback(packet):
    global packet_buffer, start_time, attack_count, ip_counts, total_packets, baseline_rate, baseline_established, normal_traffic_samples, last_attack_print
    
    total_packets += 1
    packet_buffer.append(packet)
    
    if packet.haslayer(IP):
        src_ip = packet["IP"].src
        ip_counts[src_ip] += 1
    
    # Analyze every 2 seconds for faster response
    current_time = time.time()
    if current_time - start_time >= 2:
        packets_in_window = len(packet_buffer)
        
        if packets_in_window > 0:
            # Calculate stats
            timestamps = [pkt.time for pkt in packet_buffer]
            duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 1
            if duration <= 0:
                duration = 1
            
            current_rate = packets_in_window / duration
            unique_ips = len(ip_counts)
            
            # ALWAYS print stats for debugging
            print(f"STATS|{packets_in_window}|{current_rate:.2f}|{unique_ips}", flush=True)
            
            # LOWER THRESHOLDS FOR TESTING - REAL ATTACK DETECTION
            is_attack = False
            attack_reason = ""
            
            # Rule 1: High packet rate (30+ pps is suspicious for local testing)
            if current_rate > 30:  # Lowered from 500 for testing
                is_attack = True
                attack_reason = f"High packet rate: {current_rate:.0f} pps"
            
            # Rule 2: Many unique IPs (10+ IPs indicates distributed attack)
            elif unique_ips > 10 and current_rate > 20:
                is_attack = True
                attack_reason = f"Distributed attack: {unique_ips} unique IPs"
            
            # Rule 3: Rate spike compared to baseline
            elif baseline_established and current_rate > baseline_rate * 3 and current_rate > 30:
                is_attack = True
                attack_reason = f"Rate spike: {current_rate:.0f} pps (baseline: {baseline_rate:.0f})"
            
            # ML Detection (if model available)
            if model is not None and not is_attack and current_rate > 20:
                try:
                    ml_features = extract_ml_features(packet_buffer)
                    if ml_features is not None:
                        prediction = model.predict(ml_features)[0]
                        if prediction == 1:
                            is_attack = True
                            attack_reason = "ML model detected attack pattern"
                except:
                    pass
            
            # Attack detected!
            if is_attack:
                attack_count += 1
                current_time_str = datetime.now().strftime("%H:%M:%S")
                
                # Only print every 2 seconds to avoid spam
                if current_time - last_attack_print >= 2:
                    print(f"\n{'='*60}", flush=True)
                    print(f"[!!!] DDoS ATTACK DETECTED at {current_time_str} !!!", flush=True)
                    print(f"Reason: {attack_reason}", flush=True)
                    print(f"Packets: {packets_in_window} | Rate: {current_rate:.2f} pps | IPs: {unique_ips}", flush=True)
                    print(f"Total Attacks: {attack_count}", flush=True)
                    print(f"{'='*60}\n", flush=True)
                    last_attack_print = current_time
                
                # Send to GUI
                print(f"ATTACK|{packets_in_window}|{current_rate:.2f}|{unique_ips}|{attack_count}|{attack_reason}", flush=True)
            
            # Establish baseline (first 30 seconds)
            if not baseline_established and attack_count == 0:
                if len(normal_traffic_samples) < 15:
                    normal_traffic_samples.append(current_rate)
                    if len(normal_traffic_samples) == 15:
                        baseline_rate = np.mean(normal_traffic_samples) + (np.std(normal_traffic_samples) * 1.5)
                        baseline_established = True
                        print(f"[BASELINE] Established: {baseline_rate:.2f} pps", flush=True)
        
        # Reset for next window
        packet_buffer.clear()
        ip_counts.clear()
        start_time = current_time

def start_sniffing():
    print("\n" + "="*60, flush=True)
    print("STARTING PACKET CAPTURE", flush=True)
    print("="*60, flush=True)
    print("Detection active - Monitoring for DDoS attacks", flush=True)
    print("Press Ctrl+C to stop\n", flush=True)
    
    try:
        # Use filtered sniffing for better performance
        sniff(prn=packet_callback, store=0, filter="ip")
    except PermissionError:
        print("\n[ERROR] Run as Administrator!", flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}", flush=True)
        print("Install Npcap from https://npcap.com", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    from datetime import datetime
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print(f"\n\n[SHUTDOWN] Total attacks detected: {attack_count}", flush=True)
        print(f"[SHUTDOWN] Total packets captured: {total_packets}", flush=True)
        sys.exit(0)