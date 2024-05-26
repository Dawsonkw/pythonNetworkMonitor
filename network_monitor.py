import sys
from collections import deque
from scapy.all import ARP, Ether, srp, conf
import time
import threading
import signal
import psutil
from tabulate import tabulate

# Global variables for storing network traffic data
baseline = 0  # 1 MB/s

# Functions for network scanning and monitoring


def signal_handler(signal, frame):
    stop_event.set()
    print("\nMonitoring and scanning stopped.")
    sys.exit(0)


def display_alert(message):
    print(f"\033[91m" + message + "\033[0m")


def get_network_stats():
    net_io = psutil.net_io_counters()
    return {
        'bytes_sent': net_io.bytes_sent,
        'bytes_recv': net_io.bytes_recv,
        'packets_sent': net_io.packets_sent,
        'packets_recv': net_io.packets_recv,
    }


def convert_bytes(num):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return f"{num:.2f} {unit}"
        num /= 1024.0


def arp_scan(network):
    conf.L3socket6 = True
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def monitor_network(interface, stop_event):
    global baseline
    traffic_threshold = 500  # 5 times the baseline

    while not stop_event.is_set():
        try:
            stats = get_network_stats()
            table = [
                ["Bytes Sent", convert_bytes(stats['bytes_sent'])],
                ["Bytes Received", convert_bytes(stats['bytes_recv'])],
                ["Packets Sent", stats['packets_sent']],
                ["Packets Received", stats['packets_recv']],
                ["Average Baseline", f"{(baseline * 8) / 1000000:.2f} Mbps"]
            ]
            print(tabulate(table, headers=[
                  "Metric", "Value"], tablefmt="pretty"))

            if baseline > 0 and stats["bytes_recv"] > baseline * traffic_threshold:
                alert_message = f"High network traffic detected on interface {interface}! Traffic Rate: {(stats['bytes_recv'] * 8) / 1000000:.2f} Mbps, Threshold: {(baseline * traffic_threshold * 8) / 1000000:.2f} Mbps"
                display_alert(alert_message)

            time.sleep(5)
        except KeyboardInterrupt:
            stop_event.set()
            print("\nMonitoring and scanning stopped.")
            break


def scan_network(network, stop_event):
    while not stop_event.is_set():
        try:
            devices = arp_scan(network)
            print("Devices on network:")
            for device in devices:
                print(f"IP: {device['ip']}, MAC: {device['mac']}")
            time.sleep(60)
        except KeyboardInterrupt:
            stop_event.set()
            print("\nMonitoring and scanning stopped.")
            break


def monitor_baseline(interface, stop_event):
    global baseline
    traffic_data = deque(maxlen=60)
    while not stop_event.is_set():
        try:
            stats = get_network_stats()
            bytes_recv = stats['bytes_recv']
            traffic_data.append(bytes_recv)
            if len(traffic_data) == traffic_data.maxlen:
                baseline = sum(traffic_data) // len(traffic_data) // 1000000
            time.sleep(1)  # check every second
        except KeyboardInterrupt:
            stop_event.set()
            print("\nMonitoring and scanning stopped.")
            break


if __name__ == "__main__":
    INTERFACE = "eth0"
    NETWORK = "192.168.1.0/24"
    stop_event = threading.Event()

    # Register signal handler for KeyboardInterrupt
    signal.signal(signal.SIGINT, signal_handler)

    # Start monitoring and scanning threads
    monitor_thread = threading.Thread(
        target=monitor_network, args=(INTERFACE, stop_event))
    scan_thread = threading.Thread(
        target=scan_network, args=(NETWORK, stop_event))
    baseline_thread = threading.Thread(
        target=monitor_baseline, args=(INTERFACE, stop_event))

    baseline_thread.start()
    monitor_thread.start()
    scan_thread.start()

    # Loop to control the monitoring and scanning processes
    while True:
        try:
            command = input(
                "Enter 'start' to start monitoring and scanning, 'stop' to stop, or 'exit' to exit: ").strip().lower()
            if command == "start":
                if not any(thread.is_alive() for thread in [monitor_thread, scan_thread]):
                    stop_event.clear()
                    monitor_thread = threading.Thread(
                        target=monitor_network, args=(INTERFACE, stop_event))
                    scan_thread = threading.Thread(
                        target=scan_network, args=(NETWORK, stop_event))
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

        except KeyboardInterrupt:
            stop_event.set()
            baseline_thread.join()
            monitor_thread.join()
            scan_thread.join()
            print("\nExiting program.")
            break
