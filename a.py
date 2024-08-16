from scapy.all import sniff, IP
import threading
import time
import os
import ipaddress
import clipboard

# Defining import variables
traffic_data = {}
lock = threading.Lock()
print('Starting Lacakgrak... Output will appear in 10 seconds.')

def packet_callback(packet):
    """
    Callback function that processes network packets captured by the sniffer.
    
    This function is called for each network packet captured by the sniffer. It extracts the source and destination IP addresses from the packet, and updates the `traffic_data` dictionary with the total bytes sent and received for each IP address. The `lock` object is used to ensure thread-safe access to the `traffic_data` dictionary.
    """
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

def copy_stats_to_clipboard():
    stats = []
    with lock:
        for ip, data in sorted(traffic_data.items(), key=lambda item: item[1]['total'], reverse=True):
            if is_private_ip(ip):
                ip = "localhost"
            stats.append(f"{ip}: {human_readable_bytes(data['total'])}")
    
    stats_text = "\n".join(stats)
    clipboard.copy(stats_text)
    print("\n" + "="*50)
    print("STATISTICS COPIED TO CLIPBOARD SUCCESSFULLY!")
    print("="*50 + "\n")
    time.sleep(2)  # Pause for 2 seconds to ensure the message is seen



def is_private_ip(ip):
    """Checks if the IP is a private one."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def human_readable_bytes(byte_size):
    """Creates a human-readable sum-up of bytes per IP."""
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
            
            print("Top 10 IP Addresses by Traffic:")
            for ip, data in sorted_data[:10]:
                traffic = human_readable_bytes(data['total'])
                print(f"{ip:<23} : {traffic:<15}")



def start_sniffing():
    # Start sniffing
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    try:
        print_statistics()
    except KeyboardInterrupt:
        copy_stats_to_clipboard()
        print('Copying stats...')
    finally:
        print("Exiting...")
