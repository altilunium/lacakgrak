from scapy.all import sniff, IP
import threading
import time
import socket
import os
import ipaddress
import termplotlib as tpl
import numpy as np

traffic_data = {}
lock = threading.Lock()

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_len = len(packet)

        with lock:
            if ip_dst not in traffic_data:
                traffic_data[ip_dst] = {'total': 0}
            if ip_src not in traffic_data:
                traffic_data[ip_src] = {'total': 0}

            traffic_data[ip_dst]['total'] += packet_len
            traffic_data[ip_src]['total'] += packet_len

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def human_readable_bytes(byte_size):
    units = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    if byte_size == 0:
        return '0 Bytes'
    index = 0
    while byte_size >= 1024 and index < len(units) - 1:
        byte_size /= 1024.0
        index += 1
    return f"{byte_size:.2f} {units[index]}"

def print_statistics():
    while True:
        time.sleep(10)
        with lock:
            os.system('cls' if os.name == 'nt' else 'clear')
            sorted_data = sorted(traffic_data.items(), key=lambda item: item[1]['total'], reverse=True)
            
            # Prepare data for the chart
            ips = []
            traffic = []
            for ip, data in sorted_data[:10]:  # Show top 10 IPs
                if is_private_ip(ip):
                    ip = "localhost"
                ips.append(ip)
                traffic.append(data['total'])
                
                ii = human_readable_bytes(data['total'])
                print(f"{ip:<23} : {ii}")
            
            # Create and display the chart
            fig = tpl.figure()
            fig.barh(traffic, ips, force_ascii=True)
            fig.show()

def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    print_statistics()
