from scapy.all import sniff, IP
import threading
import time
import socket
import os
import ipaddress

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
        # If the input is not a valid IP address, return False
        return False




def human_readable_bytes(byte_size):
    """
    Convert a byte size into a human-readable format (e.g., KB, MB, GB).
    
    Parameters:
    byte_size (int): The size in bytes to convert.
    
    Returns:
    str: The size in a human-readable format.
    """
    # Define the units and their respective thresholds
    units = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    
    # If byte_size is 0, return '0 Bytes'
    if byte_size == 0:
        return '0 Bytes'
    
    # Calculate the index for the units
    index = 0
    while byte_size >= 1024 and index < len(units) - 1:
        byte_size /= 1024.0
        index += 1
    
    # Format the result with two decimal places
    return f"{byte_size:.2f} {units[index]}"




def print_statistics():
    while True:
        time.sleep(10)
        with lock:
            os.system('cls')
            sorted_data = sorted(traffic_data.items(), key=lambda item: item[1]['total'] , reverse=True)
            for ip, data in sorted_data:
                ii = human_readable_bytes(data['total'])
                if is_private_ip(ip):
                    ip = "localhost"    
                print(f"{ip:<23} : {ii} ") 
                #print(f"{ip} - Inbound: {data['inbound']} bytes, Outbound: {data['outbound']} bytes")
                
                

def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # Start the sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start the statistics printing in the main thread
    print_statistics()
