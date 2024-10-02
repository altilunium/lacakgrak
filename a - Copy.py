from scapy.all import sniff, IP, DNS, DNSQR
import threading
import time
import os
import ipaddress
import clipboard
from datetime import datetime, timedelta
import sqlite3
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, messagebox
import tkinter.simpledialog as simpledialog
import re

traffic_data = {}
lock = threading.Lock()
start = datetime.now()

# Define the database path and create a table if not exists
hr = int(start.strftime('%H'))
code = "S"
if hr >= 19:
    code = "I"
elif hr >= 18:
    code = "M"
elif hr >= 15:
    code = "A"
elif hr >= 12:
    code = "Z"
else:
    code = "S"

pa = r"C:\Users\LENOVO\Documents\Research\sniff\dbdb.db"
connection = sqlite3.connect(pa)
cursor = connection.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id TEXT,
        timepoint TEXT,
        datausage TEXT,
        comm TEXT
    )
''')
connection.commit()

cursor = connection.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ips (
        ip TEXT,
        datas INTEGER,
        counts INTEGER,
        host TEXT,
        location TEXT,
        user TEXT
    )
''')
connection.commit()

def append_if_not_exists(my_list, item):
    if item not in my_list:
        my_list.append(item)

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_len = len(packet)

        with lock:
            if ip_dst not in traffic_data:
                traffic_data[ip_dst] = {'total': 0,'tstamp':[]}
            if ip_src not in traffic_data:
                traffic_data[ip_src] = {'total': 0,'tstamp':[]}

            traffic_data[ip_dst]['total'] += packet_len
            traffic_data[ip_src]['total'] += packet_len

            '''
            timestamp = datetime.now().strftime('%H:%M')
            append_if_not_exists(traffic_data[ip_dst]['tstamp'],timestamp)
            append_if_not_exists(traffic_data[ip_src]['tstamp'],timestamp)
            #print(traffic_data[ip_src]['tstamp'])
            '''


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

# Start packet sniffing
def start_sniffing():
    sniff(prn=packet_callback, store=0)

# Display the statistics in the GUI
def update_stats_textbox():
    while True:
        with lock:
            stats_textbox.delete(1.0, tk.END)
            ima = datetime.now()
            stats_textbox.insert(tk.END, f"Start: {start.strftime('%B %d, %Y (%H:%M)')} \nDuration: {ima - start}\n\n")
            
            sorted_data = sorted(traffic_data.items(), key=lambda item: item[1]['total'], reverse=True)
            count = 1
            pa = r"C:\Users\LENOVO\Documents\Research\sniff\dbdb.db"
            connection2 = sqlite3.connect(pa)
            cursor2 = connection2.cursor()
            for ip, data in sorted_data[:15]:  # Limit to top 15 IPs
                ii = human_readable_bytes(data['total'])
                if is_private_ip(ip):
                    ip = "localhost"
                oldip = ip
                cursor2.execute("SELECT user FROM ips WHERE ip = ?", (ip,))
                result = cursor2.fetchone()
                if result:
                    result = re.sub(r'[^a-zA-Z0-9. ]+', '', str(result))
                    print(result)
                    ip = str(result)[:53]
                    if ip == "None":
                        ip = oldip
                stats_textbox.insert(tk.END, f"{ip:<55} : {ii}\n")
        time.sleep(10)

# Copy statistics to clipboard and save to DB
def copy_stats_to_clipboard():
    ima = datetime.now()
    stats = []
    stats.append(f"{start.strftime('%B %d, %Y (%H:%M)')} {ima - start}")
    dursta = f"{start.strftime('%B %d, %Y (%H:%M)')}"
    dursta = code + " " + dursta
    dursta2 = code + f"{start.strftime('%d%b%Y%H%M')}"
    durdur = f"{ima - start}"
    
    maxx = 0
    with lock:
        sorted_data = sorted(traffic_data.items(), key=lambda item: item[1]['total'], reverse=True)
        for ip, data in sorted_data:
            if data['total'] > maxx:
                maxx = data['total']
            ii = human_readable_bytes(data['total'])
            if is_private_ip(ip):
                ip = "localhost"
            stats.append(f"{ip:<23}: {ii}")
            '''
            if ip != "localhost":
                stats.append(f"{traffic_data[ip]['tstamp']}")
            '''
            cursor.execute("SELECT datas, counts FROM ips WHERE ip = ?", (ip,))
            result = cursor.fetchone()
            if result:
                datas, counts = result
                new_datas = datas + data['total']
                new_counts = counts + 1
                cursor.execute("UPDATE ips SET datas = ?, counts = ? WHERE ip = ?", (new_datas, new_counts, ip))
                connection.commit()
            else:
                cursor.execute("INSERT INTO ips (ip, datas, counts) VALUES (?, ?, ?)", (ip, data['total'], 1))
                connection.commit()

    
    stats_text = "\n".join(stats)
    clipboard.copy(stats_text)
    
    # Ask for commit message in a popup
    #commit_message = input("Enter commit message: ")
    commit_message = simpledialog.askstring("Commit Message", "Enter your commit message:")

    
    # Insert into SQLite DB
    cursor.execute('''
    INSERT INTO logs (id, timepoint, datausage, comm)
        VALUES (?, ?, ?, ?)
    ''', (dursta, durdur, maxx, commit_message))
    connection.commit()

    # Save to file
    pa = r"C:\Users\LENOVO\Documents\Research\sniff"
    dirdir = pa + "\\stat\\" + dursta2
    with open(dirdir, 'x') as file:
        file.write(stats_text)

    status_label.config(text="Statistics copied to clipboard!")
    

# Start sniffing and statistics updating
def start_program():
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    
    update_thread = threading.Thread(target=update_stats_textbox)
    update_thread.daemon = True
    update_thread.start()

# Function to calculate the total timepoint and data usage
def calculate_totals(rows):
    total_time = timedelta()  # Use timedelta for summing times
    total_data_usage = 0

    for row in rows:
        # Convert timepoint (row[1]) to timedelta and add to total_time
        time_parts = row[1].split(":")
        hours, minutes, seconds = int(time_parts[0]), int(time_parts[1]), float(time_parts[2])
        total_time += timedelta(hours=hours, minutes=minutes, seconds=seconds)


        # Add data usage (row[2]) to total_data_usage
        total_data_usage += int(row[2])

    return total_time, human_readable_bytes(total_data_usage)

# Function to format the timedelta to HH:MM:SS
def format_time(td):
    total_seconds = int(td.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02}:{seconds:02}"


def show_db_data():
    # Connect to the database
    connection = sqlite3.connect(pa)
    cursor = connection.cursor()

    # Query the data from the database
    cursor.execute("SELECT id, timepoint, datausage, comm FROM logs")
    rows = cursor.fetchall()

    # Calculate total timepoint and data usage
    total_time, total_data_usage = calculate_totals(rows)

    # Create a new window to show the data
    data_window = tk.Toplevel(root)
    data_window.title("Database Data")

    # Create a frame at the top for summary labels
    summary_frame = tk.Frame(data_window)
    summary_frame.pack(pady=5)

    # Add labels for total timepoint and total data usage
    total_time_label = tk.Label(summary_frame, text=f"Total Timepoint: {format_time(total_time)}", font=('Arial', 12))
    total_time_label.pack(side="left", padx=10)

    total_data_label = tk.Label(summary_frame, text=f"Total Data Usage: {total_data_usage}", font=('Arial', 12))
    total_data_label.pack(side="left", padx=10)

    # Set up a Treeview widget
    columns = ("id", "timepoint", "datausage", "comm")
    tree = ttk.Treeview(data_window, columns=columns, show="headings")

    # Define the column headings
    tree.heading("id", text="ID", command=lambda: sort_column(tree, "id", False))
    tree.heading("timepoint", text="Timepoint", command=lambda: sort_column(tree, "timepoint", False))
    tree.heading("datausage", text="Data Usage", command=lambda: sort_column(tree, "datausage", False))
    tree.heading("comm", text="Commit Message", command=lambda: sort_column(tree, "comm", False))

    # Define the column widths
    tree.column("id", width=150)
    tree.column("timepoint", width=150)
    tree.column("datausage", width=100)
    tree.column("comm", width=250)

    # Insert data into the Treeview
    for row in rows:
        tree.insert("", tk.END, values=row)

    # Add a scrollbar
    scrollbar = ttk.Scrollbar(data_window, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side="right", fill="y")

    # Pack the treeview widget
    tree.pack(fill="both", expand=True)

    markdown_button = tk.Button(data_window, text="Convert to Markdown", command=lambda: convert_to_markdown(rows))
    markdown_button.pack(pady=5)

# Function to handle sorting by column
def sort_column(tree, col, reverse):
    data_list = [(tree.set(item, col), item) for item in tree.get_children('')]

    # Sort based on the column type
    if col == "timepoint":
        # Sort timepoint as HH:MM:SS
        data_list.sort(key=lambda x: datetime.strptime(x[0], '%H:%M:%S.%f'), reverse=reverse)
    elif col == "datausage":
        # Sort data usage as integers
        data_list.sort(key=lambda x: int(x[0]), reverse=reverse)
    else:
        # Sort text columns (id and comm)
        data_list.sort(reverse=reverse)

    # Rearrange the items in sorted positions
    for index, (val, item) in enumerate(data_list):
        tree.move(item, '', index)

    # Reverse sort next time
    tree.heading(col, command=lambda: sort_column(tree, col, not reverse))



# Function to convert the table data to Markdown format and copy to clipboard
def convert_to_markdown(rows):
    headers = "| ID | Timepoint | Data Usage | Commit Message |\n"
    separator = "| --- | --- | --- | --- |\n"
    markdown_rows = [headers, separator]

    for row in rows:
        row_md = f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} |\n"
        markdown_rows.append(row_md)

    markdown_text = "".join(markdown_rows)
    clipboard.copy(markdown_text)  # Copy Markdown to clipboard

    # Show confirmation message
    messagebox.showinfo("Markdown Copied", "Table has been converted to Markdown and copied to the clipboard.")



# GUI Setup
root = tk.Tk()
root.title("Lacakgrak")
root.geometry("600x400")

# Scrolled Textbox to display statistics
stats_textbox = scrolledtext.ScrolledText(root, width=70, height=20)
stats_textbox.pack(pady=10)

button_frame = tk.Frame(root)
button_frame.pack(pady=5)

# Button to copy stats to clipboard
copy_button = tk.Button(button_frame, text="Stop", command=copy_stats_to_clipboard)
copy_button.pack(side="left", padx=10)

# Button to show database data
db_button = tk.Button(button_frame, text="Show DB", command=show_db_data)
db_button.pack(side="left", padx=10)

# Status Label
status_label = tk.Label(root, text="")
status_label.pack()

# Start the sniffing
start_program()

# Main loop for Tkinter
root.mainloop()
