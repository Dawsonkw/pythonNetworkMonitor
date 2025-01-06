"""
Network Monitor
"""

import sys
import time
import threading
import sqlite3
import statistics
import signal
from collections import deque
import psutil
from tabulate import tabulate
from scapy.all import ARP, Ether, srp

# test test test


class NetworkMonitor:
    """Network Monitor class"""

    def __init__(self, interface="eth0", network="192.168.1.0/24"):
        self.interface = interface
        self.network = network
        self.baseline = 50_000_000_000  # More readable number format
        self.stop_event = threading.Event()
        self.baseline_calculated_event = threading.Event()
        self.traffic_threshold = 10

        # Initialize database
        self.init_database()

        # Register signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

    def init_database(self):
        """Initialize SQLite database with proper connection handling"""
        with sqlite3.connect('network_monitor.db') as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS network_traffic
                        (timestamp TEXT, 
                         bytes_sent INTEGER, 
                         bytes_recv INTEGER, 
                         packets_sent INTEGER, 
                         packets_recv INTEGER, 
                         baseline INTEGER)''')
            conn.commit()

    def signal_handler(self, signum, frame):
        """Properly handle shutdown signal"""
        self.stop_event.set()
        print("\nMonitoring and scanning stopped.")
        sys.exit(0)

    @staticmethod
    def convert_bytes(num):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024.0:
                return f"{num:.2f} {unit}"
            num /= 1024.0
        return f"{num:.2f} PB"

    def get_network_stats(self):
        """Get current network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
            }
        except psutil.Error as e:
            print(f"Error getting network stats: {e}")
            return None

    def arp_scan(self):
        """Perform ARP scan with proper error handling"""
        try:
            arp = ARP(pdst=self.network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=3, verbose=0)[0]
            return [{'ip': recv.psrc, 'mac': recv.hwsrc} for sent, recv in result]
        except psutil.Error as e:
            print(f"Error during ARP scan: {e}")
            return []

    def monitor_network(self):
        """Monitor network traffic with proper connection handling"""
        with sqlite3.connect('network_monitor.db') as conn:
            cursor = conn.cursor()

            while not self.stop_event.is_set():
                try:
                    stats = self.get_network_stats()
                    if not stats:
                        time.sleep(5)
                        continue

                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute(
                        "INSERT INTO network_traffic VALUES (?, ?, ?, ?, ?, ?)",
                        (timestamp, stats['bytes_sent'], stats['bytes_recv'],
                         stats['packets_sent'], stats['packets_recv'], self.baseline)
                    )
                    conn.commit()

                    self.display_network_stats(stats)
                    self.check_high_traffic(stats)
                    time.sleep(5)

                except psutil.Error as e:
                    print(f"Error in monitor_network: {e}")
                    time.sleep(5)

    def display_network_stats(self, stats):
        """Display current network statistics"""
        table = [
            ["Bytes Sent", self.convert_bytes(stats['bytes_sent'])],
            ["Bytes Received", self.convert_bytes(stats['bytes_recv'])],
            ["Packets Sent", stats['packets_sent']],
            ["Packets Received", stats['packets_recv']],
            ["Baseline", f"{(self.baseline * 8) / 1_000_000:.2f} Mbps"]
        ]
        print(tabulate(table, headers=["Metric", "Value"], tablefmt="pretty"))

    def check_high_traffic(self, stats):
        """Check for high traffic conditions"""
        if stats["bytes_recv"] > self.baseline * self.traffic_threshold:
            message = (
                f"\033[91mHigh network traffic detected on {self.interface}! "
                f"Traffic: {(stats['bytes_recv'] * 8) / 1_000_000:.2f} Mbps, "
                f"Threshold: {
                    (self.baseline * self.traffic_threshold * 8) / 1_000_000:.2f} Mbps\033[0m"
            )
            print(message)

    def monitor_baseline(self):
        """Calculate baseline with proper error handling"""
        traffic_data = deque(maxlen=10)

        with sqlite3.connect('network_monitor.db') as conn:
            cursor = conn.cursor()

            while not self.stop_event.is_set():
                try:
                    stats = self.get_network_stats()
                    if not stats:
                        time.sleep(1)
                        continue

                    traffic_data.append(stats['bytes_recv'])

                    if len(traffic_data) == traffic_data.maxlen:
                        self.baseline = statistics.quantiles(
                            traffic_data, n=100)[95]
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        cursor.execute(
                            "INSERT INTO network_traffic (timestamp, baseline) VALUES (?, ?)",
                            (timestamp, self.baseline)
                        )
                        conn.commit()
                        self.baseline_calculated_event.set()

                    time.sleep(1)

                except psutil.Error as e:
                    print(f"Error in monitor_baseline: {e}")
                    time.sleep(1)

    def run(self):
        """Main execution method"""
        try:
            baseline_thread = threading.Thread(target=self.monitor_baseline)
            baseline_thread.start()

            print("Calculating baseline traffic rate...")
            while not self.baseline_calculated_event.is_set():
                print(".", end="", flush=True)
                time.sleep(5)

            print(f"\nBaseline traffic rate: {
                  (self.baseline * 8) / 1_000_000:.2f} Mbps")

            monitor_thread = threading.Thread(target=self.monitor_network)
            monitor_thread.start()

            while True:
                command = input("\nEnter 'stop' or 'exit': ").strip().lower()
                if command in ('stop', 'exit'):
                    self.stop_event.set()
                    baseline_thread.join()
                    monitor_thread.join()
                    print("Program terminated.")
                    break

        except KeyboardInterrupt:
            self.stop_event.set()
            print("\nProgram terminated.")
            sys.exit(0)


if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.run()
