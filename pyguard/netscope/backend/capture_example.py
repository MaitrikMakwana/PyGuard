#!/usr/bin/env python3
# capture_example.py
# PyGuard - Enhanced Packet Capture Example
#
# This script demonstrates how to use the enhanced packet capture module
# for detailed packet capture and export to JSON/CSV formats.

import os
import sys
import time
import json
import argparse
from scapy.all import get_if_list

# Import the enhanced packet capture module
from enhanced_packet_capture import EnhancedPacketCapture

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="PyGuard Enhanced Packet Capture Example",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Interface selection
    parser.add_argument("-i", "--interfaces", nargs="+",
                        help="Network interfaces to capture on (e.g., eth0 wlan0)")
    
    # Capture parameters
    parser.add_argument("-f", "--filter", type=str, default="",
                        help="BPF filter expression (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Maximum number of packets to capture (0 for infinite)")
    parser.add_argument("-d", "--duration", type=int, default=30,
                        help="Maximum duration in seconds (0 for infinite)")
    
    # Output parameters
    parser.add_argument("-o", "--output-dir", type=str, default="captures",
                        help="Directory for output files")
    parser.add_argument("-b", "--output-base", type=str, default="packets",
                        help="Base filename for output files")
    parser.add_argument("--db-path", type=str, default="packets.db",
                        help="Path to SQLite database file")
    
    # Performance parameters
    parser.add_argument("--flush-interval", type=int, default=5,
                        help="Interval in seconds to flush data to disk")
    parser.add_argument("--max-file-size", type=int, default=10,
                        help="Maximum file size in MB before rotation")
    parser.add_argument("--rotation-interval", type=int, default=300,
                        help="Time interval in seconds before file rotation")
    parser.add_argument("--sample-rate", type=int, default=1,
                        help="Packet sampling rate (1 = all packets, 2 = every other packet, etc.)")
    
    # Output format
    parser.add_argument("--formats", nargs="+", choices=["json", "csv"], default=["json", "csv"],
                        help="Output formats")
    
    # Utility options
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available network interfaces and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")
    
    # Load from config file
    parser.add_argument("--config", type=str,
                        help="Load configuration from JSON file")
    
    args = parser.parse_args()
    
    # Handle list interfaces option
    if args.list_interfaces:
        print("Available network interfaces:")
        try:
            interfaces = get_if_list()
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
        except Exception as e:
            print(f"Error listing interfaces: {e}")
        sys.exit(0)
    
    # Load configuration from file if specified
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_data = json.load(f)
                
                # Filter out comments
                if 'comments' in config_data:
                    del config_data['comments']
                
                # Convert to command line args format
                config = {}
                for key, value in config_data.items():
                    # Convert camelCase or snake_case to command line args format
                    cmd_key = key.replace('_', '-')
                    config[cmd_key] = value
                
                # Override with command line args
                for key, value in vars(args).items():
                    if value is not None and key != 'config':
                        config[key.replace('_', '-')] = value
                
                # Convert back to args format
                for key, value in config.items():
                    cmd_key = key.replace('-', '_')
                    setattr(args, cmd_key, value)
                
        except Exception as e:
            print(f"Error loading configuration file: {e}")
            sys.exit(1)
    
    # If no interfaces specified, use the first available interface
    if not args.interfaces:
        try:
            interfaces = get_if_list()
            if interfaces:
                args.interfaces = [interfaces[0]]
                print(f"No interface specified, using {args.interfaces[0]}")
            else:
                print("No network interfaces available")
                sys.exit(1)
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
            sys.exit(1)
    
    return args

def main():
    """Main function"""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)
        
        # Create configuration dictionary
        config = {
            'interfaces': args.interfaces,
            'bpf_filter': args.filter,
            'max_packets': args.count,
            'duration': args.duration,
            'output_dir': args.output_dir,
            'output_base': args.output_base,
            'db_path': args.db_path,
            'flush_interval': args.flush_interval,
            'max_file_size': args.max_file_size,
            'rotation_interval': args.rotation_interval,
            'sample_rate': args.sample_rate,
            'formats': args.formats
        }
        
        # Print configuration
        print("=== PyGuard Enhanced Packet Capture ===")
        print(f"Interfaces: {', '.join(config['interfaces'])}")
        print(f"Filter: {config['bpf_filter'] or 'None'}")
        print(f"Duration: {config['duration']} seconds")
        print(f"Output directory: {config['output_dir']}")
        print(f"Output formats: {', '.join(config['formats'])}")
        print(f"Database: {config['db_path']}")
        print()
        
        # Create and start packet capture
        capture = EnhancedPacketCapture(config)
        capture.start()
        
        # Wait for specified duration or until user interrupts
        try:
            if config['duration'] > 0:
                print(f"Capturing packets for {config['duration']} seconds...")
                time.sleep(config['duration'])
            else:
                print("Capturing packets indefinitely. Press Ctrl+C to stop.")
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\nCapture interrupted by user.")
        
        # Stop capture and print statistics
        capture.stop()
        
        print("\nCapture completed successfully.")
        print(f"Output files are in: {os.path.abspath(config['output_dir'])}")
        print(f"Database file: {os.path.abspath(config['db_path'])}")
        
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'capture' in locals():
            capture.stop()

if __name__ == "__main__":
    main()