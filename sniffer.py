from scapy.all import sniff, IP, TCP
from datetime import datetime
from colorama import Fore, init
import tkinter as tk
from tkinter import scrolledtext
import threading

init(autoreset=True)

running = False

# GUI Setup
root = tk.Tk()
root.title("Advanced Packet Sniffer")
root.geometry("700x500")

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
text_area.pack(expand=True, fill='both')

def log(text):
    text_area.insert(tk.END, text + "\n")
    text_area.see(tk.END)

def process_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        time_now = datetime.now().strftime("%H:%M:%S")

        output = f"[{time_now}] {ip.src} → {ip.dst}"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            output += f" | TCP {tcp.sport} → {tcp.dport}"

        log(output)

        with open("packets.log", "a") as f:
            f.write(output + "\n")

def sniff_packets():
    sniff(prn=process_packet, store=False, stop_filter=lambda x: not running)

def start_sniffing():
    global running
    running = True
    thread = threading.Thread(target=sniff_packets)
    thread.daemon = True
    thread.start()
    log(Fore.GREEN + "Sniffing Started...")

def stop_sniffing():
    global running
    running = False
    log(Fore.RED + "Sniffing Stopped!")

# Buttons
start_btn = tk.Button(root, text="Start", bg="green", fg="white", command=start_sniffing)
start_btn.pack(side="left", fill="x", expand=True)

stop_btn = tk.Button(root, text="Stop", bg="red", fg="white", command=stop_sniffing)
stop_btn.pack(side="right", fill="x", expand=True)

root.mainloop()