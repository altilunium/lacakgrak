from scapy.all import sniff, IP
import threading
import time
import socket
import os

traffic_data = {}
lock = threading.Lock()

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_len = len(packet)

        with lock:
            if ip_dst not in traffic_data:
                traffic_data[ip_dst] = {'inbound': 0, 'outbound': 0}

            # Check if it's inbound or outbound
            if is_local_ip(ip_src):
                traffic_data[ip_dst]['outbound'] += packet_len
            else:
                traffic_data[ip_dst]['inbound'] += packet_len

def is_local_ip(ip):
    try:
        socket.inet_aton(ip)
        return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.")
    except socket.error:
        return False

def print_statistics():
    while True:
        time.sleep(10)
        with lock:
            os.system('cls')
            sorted_data = sorted(traffic_data.items(), key=lambda item: item[1]['inbound'] + item[1]['outbound'], reverse=True)
            for ip, data in sorted_data:
                print(f"{ip} - Inbound: {data['inbound']} bytes, Outbound: {data['outbound']} bytes")
            print("\n" + "-"*50 + "\n")

def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # Start the sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start the statistics printing in the main thread
    print_statistics()
