import psutil
import scapy.all 
from scapy.all import ARP, Ether, srp
import time
import threading


# 
# Functioms for network scanning and monitoring
# 
# Network statistics
def get_network_stats():
    net_io = psutil.net_io_counters()
    return {
        'bytes_sent': net_io.bytes_sent,
        'bytes_recv': net_io.bytes_recv,
        'packets_sent': net_io.packets_sent,
        'packets_recv': net_io.packets_recv,
    }

# ARP scan function

# 

def arp_scan(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

#  Monitor and scanning functions w/ control

def monitor_network(interface, stopEvent):
    while not stopEvent.is_set():
        stats = get_network_stats()
        print(f"Bytes sent: {stats['bytes_sent']}, Bytes received: {stats['bytes_recv']}")
        print(f"Packets sent: {stats['packets_sent']}, Packets received: {stats['packets_recv']}")
        time.sleep(5)

def scan_network(network, stopEvent):
    while not stopEvent.is_set():
        devices = arp_scan(network)
        print("Devices on network:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
        time.sleep(60)


if __name__ == "__main__":
    interface = "eth0"
    network = "192.168.1.0/24"
    
    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_network, args=(interface, stop_event))
    scan_thread = threading.Thread(target=scan_network, args=(network, stop_event))
    
    while True:
        command = input("Enter 'start' to start monitoring and scanning, 'stop' to stop, or 'exit' to exit: ").strip().lower()
        if command == "start":
            if not monitor_thread.is_alive() and not scan_thread.is_alive():
                stop_event.clear()
                monitor_thread = threading.Thread(target=monitor_network, args=(interface, stop_event))
                scan_thread = threading.Thread(target=scan_network, args=(network, stop_event))
                monitor_thread.start()
                scan_thread.start()
                print("Monitoring and scanning started.")
            else:
                print("Monitoring and scanning are already running.")
        elif command == "stop":
            stop_event.set()
            monitor_thread.join()
            scan_thread.join()
            print("Monitoring and scanning stopped.")   
        elif command == "exit":
            stop_event.set()
            monitor_thread.join()
            scan_thread.join()
            print("Exiting program.")
            break
        else:
            print("Invalid command. Please enter 'start', 'stop', or 'exit'.")        

