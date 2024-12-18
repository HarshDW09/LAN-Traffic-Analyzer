import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict
import os

class LANTrafficAnalyzer:
    def __init__(self, capture_interface: str = 'eth0'):
        """
        Initialize LAN Traffic Analyzer
        
        :param capture_interface: Network interface to capture traffic from
        """
        self.capture_interface = capture_interface
        self.packets = []
        self.traffic_summary = {}

    def capture_traffic(self, duration: int = 60) -> None:
        """
        Capture network traffic for specified duration
        
        :param duration: Capture duration in seconds
        """
        print(f"Capturing traffic on {self.capture_interface} for {duration} seconds...")
        capture = pyshark.LiveCapture(interface=self.capture_interface)
        self.packets = capture.sniff(timeout=duration)

    def analyze_traffic(self) -> Dict:
        """
        Analyze captured network traffic
        
        :return: Dictionary of traffic analysis insights
        """
        # Protocol distribution
        protocols = {}
        source_ips = {}
        dest_ips = {}
        total_bytes = 0

        for packet in self.packets:
            try:
                # Protocol tracking
                if hasattr(packet, 'transport_layer'):
                    proto = packet.transport_layer
                    protocols[proto] = protocols.get(proto, 0) + 1

                # IP tracking
                if hasattr(packet.ip, 'src'):
                    source_ips[packet.ip.src] = source_ips.get(packet.ip.src, 0) + 1
                
                if hasattr(packet.ip, 'dst'):
                    dest_ips[packet.ip.dst] = dest_ips.get(packet.ip.dst, 0) + 1

                # Byte count
                if hasattr(packet, 'length'):
                    total_bytes += int(packet.length)

            except AttributeError:
                continue

        self.traffic_summary = {
            'total_packets': len(self.packets),
            'protocols': protocols,
            'source_ips': dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'dest_ips': dict(sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'total_bytes': total_bytes
        }
        return self.traffic_summary

    def visualize_traffic(self) -> None:
        """
        Create visualizations of network traffic
        """
        # Protocol Distribution Pie Chart
        plt.figure(figsize=(10, 5))
        plt.subplot(1, 2, 1)
        plt.pie(
            list(self.traffic_summary['protocols'].values()), 
            labels=list(self.traffic_summary['protocols'].keys()),
            autopct='%1.1f%%'
        )
        plt.title('Protocol Distribution')

        # Top Source IPs Bar Chart
        plt.subplot(1, 2, 2)
        plt.bar(
            list(self.traffic_summary['source_ips'].keys()), 
            list(self.traffic_summary['source_ips'].values())
        )
        plt.title('Top 10 Source IPs')
        plt.xticks(rotation=45)

        plt.tight_layout()
        plt.savefig('lan_traffic_analysis.png')
        plt.close()

    def generate_report(self) -> None:
        """
        Generate a comprehensive traffic analysis report
        """
        with open('lan_traffic_report.txt', 'w') as report:
            report.write("LAN Traffic Analysis Report\n")
            report.write("=" * 30 + "\n\n")
            report.write(f"Total Packets Captured: {self.traffic_summary['total_packets']}\n")
            report.write(f"Total Bytes Transferred: {self.traffic_summary['total_bytes']}\n\n")
            
            report.write("Protocol Distribution:\n")
            for proto, count in self.traffic_summary['protocols'].items():
                report.write(f"- {proto}: {count} packets\n")
            
            report.write("\nTop 10 Source IPs:\n")
            for ip, count in self.traffic_summary['source_ips'].items():
                report.write(f"- {ip}: {count} packets\n")

def main():
    analyzer = LANTrafficAnalyzer()
    analyzer.capture_traffic(duration=120)  # Capture for 2 minutes
    analyzer.analyze_traffic()
    analyzer.visualize_traffic()
    analyzer.generate_report()

if __name__ == "__main__":
    main()
