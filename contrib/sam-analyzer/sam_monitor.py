#!/usr/bin/env python3
"""
SAM Analyzer Monitor - User-space tool for Surface Aggregator Module analysis
Author: Jakub Komosa
"""

import os
import sys
import time
import json
import argparse
import struct
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

class SAMAnalyzerMonitor:
    """Real-time monitor for SAM packet analysis"""
    
    DEBUGFS_PATH = "/sys/kernel/debug/sam_analyzer"
    
    # SAM categories from linux-surface documentation
    CATEGORIES = {
        0x01: "Power/Battery",
        0x02: "Thermal",
        0x03: "Platform",
        0x08: "Keyboard",
        0x09: "Touchpad",
        0x0A: "Touch",
        0x0B: "Pen",
        0x11: "Display",
        0x13: "Performance",
        0x15: "HID",
    }
    
    def __init__(self):
        self.stats_history = deque(maxlen=100)
        self.latency_tracker = defaultdict(list)
        self.event_counter = defaultdict(int)
        
    def check_module_loaded(self):
        """Check if the SAM analyzer module is loaded"""
        if not Path(self.DEBUGFS_PATH).exists():
            print("Error: SAM Analyzer module not loaded")
            print("Please run: sudo insmod sam_analyzer.ko")
            return False
        return True
    
    def read_stats(self):
        """Read current statistics from debugfs"""
        stats_file = f"{self.DEBUGFS_PATH}/stats"
        try:
            with open(stats_file, 'r') as f:
                content = f.read()
                
            stats = {}
            for line in content.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    if value.isdigit():
                        stats[key] = int(value)
                    else:
                        stats[key] = value
            return stats
        except (IOError, PermissionError) as e:
            print(f"Error reading stats: {e}")
            return None
    
    def enable_analyzer(self, enable=True):
        """Enable or disable the analyzer"""
        enable_file = f"{self.DEBUGFS_PATH}/enable"
        try:
            with open(enable_file, 'w') as f:
                f.write('1' if enable else '0')
            return True
        except (IOError, PermissionError) as e:
            print(f"Error setting analyzer state: {e}")
            return False
    
    def set_payload_capture(self, enable=True):
        """Enable or disable payload capture"""
        payload_file = f"{self.DEBUGFS_PATH}/capture_payload"
        try:
            with open(payload_file, 'w') as f:
                f.write('1' if enable else '0')
            return True
        except (IOError, PermissionError):
            return False
    
    def monitor_realtime(self, interval=1):
        """Monitor statistics in real-time"""
        print("\033[2J\033[H")  # Clear screen
        print("SAM Analyzer Monitor - Press Ctrl+C to stop")
        print("=" * 60)
        
        last_stats = None
        
        try:
            while True:
                stats = self.read_stats()
                if not stats:
                    time.sleep(interval)
                    continue
                
                # Calculate rates
                rates = {}
                if last_stats:
                    time_diff = interval
                    for key in ['Packets Captured', 'Total Bytes']:
                        if key in stats and key in last_stats:
                            diff = stats[key] - last_stats[key]
                            rates[key] = diff / time_diff
                
                # Display current stats
                print("\033[4;0H")  # Move cursor
                print(f"Status: {stats.get('Status', 'Unknown'):<20} "
                      f"Time: {datetime.now().strftime('%H:%M:%S')}")
                print("-" * 60)
                
                print(f"Packets Captured: {stats.get('Packets Captured', 0):>10} "
                      f"({rates.get('Packets Captured', 0):.1f}/s)")
                print(f"Packets Dropped:  {stats.get('Packets Dropped', 0):>10}")
                print(f"Total Bytes:      {stats.get('Total Bytes', 0):>10} "
                      f"({rates.get('Total Bytes', 0):.1f} B/s)")
                print(f"Command Packets:  {stats.get('Command Packets', 0):>10}")
                print(f"Event Packets:    {stats.get('Event Packets', 0):>10}")
                print(f"Errors:           {stats.get('Errors', 0):>10}")
                
                # Calculate and display packet distribution
                total_pkts = stats.get('Packets Captured', 0)
                if total_pkts > 0:
                    cmd_pct = (stats.get('Command Packets', 0) / total_pkts) * 100
                    evt_pct = (stats.get('Event Packets', 0) / total_pkts) * 100
                    
                    print("\nPacket Distribution:")
                    print(f"  Commands: {cmd_pct:>5.1f}%")
                    print(f"  Events:   {evt_pct:>5.1f}%")
                
                # Store for history
                self.stats_history.append(stats)
                last_stats = stats
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped.")
    
    def dump_trace(self, output_file):
        """Dump packet trace to file"""
        # This would require implementing trace buffer reading
        # from the ring buffer via debugfs or a custom interface
        print(f"Dumping trace to {output_file}...")
        # Implementation would go here
        print("Trace dump complete.")
    
    def analyze_latency(self):
        """Analyze command-response latencies"""
        print("Latency Analysis")
        print("=" * 40)
        
        # This would process the trace buffer to extract latency data
        # For demonstration, showing the structure:
        categories = ["Keyboard", "Touchpad", "Power", "Thermal"]
        
        for category in categories:
            print(f"\n{category}:")
            print(f"  Average: -- ms")
            print(f"  Min:     -- ms")
            print(f"  Max:     -- ms")
            print(f"  P95:     -- ms")
    
    def filter_by_category(self, category):
        """Set filter to specific category"""
        category_id = None
        for cat_id, cat_name in self.CATEGORIES.items():
            if cat_name.lower() == category.lower():
                category_id = cat_id
                break
        
        if category_id is None:
            print(f"Unknown category: {category}")
            return False
        
        filter_file = f"{self.DEBUGFS_PATH}/filter_mask"
        try:
            with open(filter_file, 'w') as f:
                f.write(f"0x{1 << category_id:08x}")
            print(f"Filter set to category: {category}")
            return True
        except (IOError, PermissionError) as e:
            print(f"Error setting filter: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='SAM Analyzer Monitor')
    parser.add_argument('--enable', action='store_true', 
                       help='Enable the analyzer')
    parser.add_argument('--disable', action='store_true',
                       help='Disable the analyzer')
    parser.add_argument('--monitor', action='store_true',
                       help='Start real-time monitoring')
    parser.add_argument('--interval', type=float, default=1.0,
                       help='Monitoring interval in seconds')
    parser.add_argument('--dump', metavar='FILE',
                       help='Dump trace to file')
    parser.add_argument('--latency', action='store_true',
                       help='Analyze latencies')
    parser.add_argument('--filter', metavar='CATEGORY',
                       help='Filter by category (e.g., Keyboard, Touchpad)')
    parser.add_argument('--payload', action='store_true',
                       help='Enable payload capture')
    parser.add_argument('--stats', action='store_true',
                       help='Show current statistics')
    
    args = parser.parse_args()
    
    monitor = SAMAnalyzerMonitor()
    
    # Check if module is loaded
    if not monitor.check_module_loaded():
        return 1
    
    # Handle commands
    if args.enable:
        if monitor.enable_analyzer(True):
            print("Analyzer enabled")
    
    if args.disable:
        if monitor.enable_analyzer(False):
            print("Analyzer disabled")
    
    if args.payload:
        if monitor.set_payload_capture(True):
            print("Payload capture enabled")
    
    if args.filter:
        monitor.filter_by_category(args.filter)
    
    if args.dump:
        monitor.dump_trace(args.dump)
    
    if args.latency:
        monitor.analyze_latency()
    
    if args.stats:
        stats = monitor.read_stats()
        if stats:
            for key, value in stats.items():
                print(f"{key}: {value}")
    
    if args.monitor:
        monitor.monitor_realtime(args.interval)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
