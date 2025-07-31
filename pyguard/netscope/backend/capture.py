import threading
import time
import os
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw, get_if_list
import sqlite3

# Import the enhanced packet capture module
from .enhanced_packet_capture import EnhancedPacketCapture, PacketProcessor

class CaptureManager:
    def __init__(self, db_path='packets.db'):
        self.db_path = db_path
        self._connection_pool = []
        self._max_pool_size = 3  # Maximum number of connections in the pool
        
        # Get initial connection and create tables
        self.conn = self._get_connection()
        self.cursor = self.conn.cursor()
        self._ensure_table()
        
        self.thread = None
        self.running = False
        self.interface = None
        self.bpf_filter = None
        self.packet_callback = None  # Optional: function to call with each packet (for UI updates)
        
    def _get_connection(self):
        """Get a database connection from the pool or create a new one"""
        if self._connection_pool:
            return self._connection_pool.pop()
        
        # Create a new connection with optimized settings
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute('PRAGMA journal_mode = WAL')  # Use Write-Ahead Logging
        conn.execute('PRAGMA synchronous = NORMAL')  # Reduce synchronous writes
        conn.execute('PRAGMA cache_size = -10000')  # ~10MB cache
        return conn
    
    def _return_connection(self, conn):
        """Return a connection to the pool"""
        if len(self._connection_pool) < self._max_pool_size:
            self._connection_pool.append(conn)
        else:
            conn.close()
    
    def __init__(self, db_path='packets.db'):
        self.db_path = db_path
        self._connection_pool = []
        self._max_pool_size = 3  # Maximum number of connections in the pool
        
        # Get initial connection and create tables
        self.conn = self._get_connection()
        self.cursor = self.conn.cursor()
        self._ensure_table()
        
        self.thread = None
        self.running = False
        self.interface = None
        self.bpf_filter = None
        self.packet_callback = None  # Optional: function to call with each packet (for UI updates)
        
        # Enhanced capture support
        self.enhanced_mode = False
        self.enhanced_capture = None
        self.packet_processor = PacketProcessor()
        self.export_formats = ['json', 'csv']
        self.export_dir = 'captures'
        self.export_base = 'packets'

    def _ensure_table(self):
        # Create improved table schema with indexes (consistent with packet_sniffer.py)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                size INTEGER NOT NULL,
                details TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better query performance
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets(dst_ip)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_port ON packets(src_port)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_port ON packets(dst_port)')
        
        # Create enhanced table schema with additional fields for TCP flags and payload length
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS enhanced_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                packet_length INTEGER NOT NULL,
                payload_length INTEGER,
                tcp_flags_syn INTEGER,
                tcp_flags_ack INTEGER,
                tcp_flags_fin INTEGER,
                tcp_flags_rst INTEGER,
                tcp_flags_psh INTEGER,
                tcp_flags_urg INTEGER,
                details TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for enhanced table
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_enh_timestamp ON enhanced_packets(timestamp)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_enh_src_ip ON enhanced_packets(src_ip)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_enh_dst_ip ON enhanced_packets(dst_ip)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_enh_protocol ON enhanced_packets(protocol)')
        
        self.conn.commit()

    def start(self, interface=None, bpf_filter=None, packet_callback=None, enhanced_mode=False, 
              export_formats=None, export_dir=None, export_base=None):
        """
        Start packet capture with enhanced options
        
        Args:
            interface: Network interface to capture on
            bpf_filter: BPF filter expression
            packet_callback: Callback function for UI updates
            enhanced_mode: Whether to use enhanced capture mode
            export_formats: List of export formats (json, csv)
            export_dir: Directory for export files
            export_base: Base filename for export files
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_callback = packet_callback
        self.enhanced_mode = enhanced_mode
        
        if export_formats:
            self.export_formats = export_formats
        if export_dir:
            self.export_dir = export_dir
        if export_base:
            self.export_base = export_base
        
        # Create export directory if it doesn't exist
        if self.enhanced_mode and self.export_dir:
            os.makedirs(self.export_dir, exist_ok=True)
        
        self.running = True
        
        if self.enhanced_mode:
            # Use enhanced capture mode
            config = {
                'interfaces': [self.interface] if self.interface else get_if_list(),
                'bpf_filter': self.bpf_filter,
                'output_dir': self.export_dir,
                'output_base': self.export_base,
                'db_path': self.db_path,
                'formats': self.export_formats
            }
            
            self.enhanced_capture = EnhancedPacketCapture(config)
            self.enhanced_capture.start()
        else:
            # Use legacy capture mode
            self.thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.thread.start()

    def stop(self):
        """Stop packet capture"""
        self.running = False
        
        if self.enhanced_mode and self.enhanced_capture:
            # Stop enhanced capture
            self.enhanced_capture.stop()
            self.enhanced_capture = None
        elif self.thread:
            # Stop legacy capture
            self.thread.join(timeout=2)
            self.thread = None

    def _capture_loop(self):
        """Legacy capture loop with improved error handling"""
        max_retries = 3
        retry_count = 0
        backoff_time = 1  # Start with 1 second backoff
        
        while self.running and retry_count < max_retries:
            try:
                # Log capture start
                print(f"Starting packet capture on interface {self.interface} with filter: {self.bpf_filter}")
                
                # Set a packet count limit to prevent memory issues
                packet_count = 0
                max_packets_per_session = 1000  # Increased limit for better performance
                
                # Use sampling for high-traffic networks
                sample_rate = 1  # Process every packet by default
                
                def packet_handler(pkt):
                    nonlocal packet_count, sample_rate
                    packet_count += 1
                    
                    # If we've captured too many packets, restart the capture
                    if packet_count >= max_packets_per_session:
                        print(f"Reached packet limit ({max_packets_per_session}), restarting capture")
                        return True  # Stop the current capture
                    
                    # Implement adaptive sampling based on traffic volume
                    if packet_count % 100 == 0:
                        # Check if we're getting too many packets too quickly
                        if packet_count > 200 and (time.time() - capture_start_time) < 5:
                            # High traffic detected, increase sampling rate
                            sample_rate = min(sample_rate * 2, 10)  # Max sample every 10th packet
                            print(f"High traffic detected, sampling every {sample_rate}th packet")
                    
                    # Process the packet (with sampling)
                    if packet_count % sample_rate == 0:
                        self._handle_packet(pkt)
                    
                    # Check if we should stop
                    return not self.running
                
                # Record start time for adaptive sampling
                capture_start_time = time.time()
                
                # Start capture with improved handling
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=packet_handler,
                    store=False,
                    stop_filter=lambda x: packet_count >= max_packets_per_session or not self.running
                )
                
                # If we get here and we're still running, it means we hit the packet limit
                # So we'll loop and start a new capture session
                if self.running and packet_count >= max_packets_per_session:
                    print("Restarting capture session")
                    continue
                
                # If we get here and we're not running, it means stop() was called
                break
                
            except MemoryError:
                # Handle memory errors specifically
                print(f"Memory error during capture. Retrying in {backoff_time} seconds...")
                retry_count += 1
                
                # Force garbage collection
                import gc
                gc.collect()
                
                # Wait before retry with exponential backoff
                time.sleep(backoff_time)
                backoff_time *= 2
                
            except Exception as e:
                print(f"Capture error: {e}. Retrying in {backoff_time} seconds...")
                retry_count += 1
                
                # Wait before retry with exponential backoff
                time.sleep(backoff_time)
                backoff_time *= 2
        
        if retry_count >= max_retries:
            print("Max retries reached. Capture stopped.")

    def _handle_packet(self, packet):
        """Legacy packet handler"""
        details = {}
        proto_name = "OTHER"
        src = dst = src_port = dst_port = "-"
        # Ethernet
        if packet.haslayer(Ether):
            details['eth_src'] = packet[Ether].src
            details['eth_dst'] = packet[Ether].dst
            details['eth_type'] = packet[Ether].type
        # IP
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            details['ip_version'] = packet[IP].version
            details['ip_ihl'] = packet[IP].ihl
            details['ip_tos'] = packet[IP].tos
            details['ip_len'] = packet[IP].len
            details['ip_id'] = packet[IP].id
            details['ip_flags'] = int(packet[IP].flags)
            details['ip_frag'] = packet[IP].frag
            details['ip_ttl'] = packet[IP].ttl
            details['ip_proto'] = packet[IP].proto
            details['ip_chksum'] = packet[IP].chksum
            details['ip_options'] = str(packet[IP].options)
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(packet[IP].proto, str(packet[IP].proto))
        # TCP
        if packet.haslayer(TCP):
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
            details['tcp_seq'] = packet[TCP].seq
            details['tcp_ack'] = packet[TCP].ack
            details['tcp_dataofs'] = packet[TCP].dataofs
            details['tcp_reserved'] = packet[TCP].reserved
            details['tcp_flags'] = str(packet[TCP].flags)
            details['tcp_window'] = packet[TCP].window
            details['tcp_chksum'] = packet[TCP].chksum
            details['tcp_urgptr'] = packet[TCP].urgptr
            details['tcp_options'] = str(packet[TCP].options)
            if packet.haslayer(Raw):
                try:
                    raw_load = packet[Raw].load.decode(errors='replace')
                    if raw_load.startswith('GET') or raw_load.startswith('POST'):
                        proto_name = "HTTP"
                        details['http_data'] = raw_load[:200]
                except Exception:
                    pass
        # UDP
        if packet.haslayer(UDP):
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
            details['udp_len'] = packet[UDP].len
            details['udp_chksum'] = packet[UDP].chksum
            if packet.haslayer(DNS):
                proto_name = "DNS"
                details['dns_id'] = packet[DNS].id
                details['dns_qr'] = packet[DNS].qr
                details['dns_opcode'] = packet[DNS].opcode
                details['dns_aa'] = packet[DNS].aa
                details['dns_tc'] = packet[DNS].tc
                details['dns_rd'] = packet[DNS].rd
                details['dns_ra'] = packet[DNS].ra
                details['dns_z'] = packet[DNS].z
                details['dns_rcode'] = packet[DNS].rcode
                details['dns_qdcount'] = packet[DNS].qdcount
                details['dns_ancount'] = packet[DNS].ancount
                details['dns_nscount'] = packet[DNS].nscount
                details['dns_arcount'] = packet[DNS].arcount
                details['dns_qd'] = str(packet[DNS].qd.qname) if packet[DNS].qd else ""
                details['dns_an'] = str(packet[DNS].an.rdata) if packet[DNS].an else ""
        # ICMP
        if packet.haslayer(ICMP):
            proto_name = "ICMP"
            details['icmp_type'] = packet[ICMP].type
            details['icmp_code'] = packet[ICMP].code
            details['icmp_chksum'] = packet[ICMP].chksum
            details['icmp_id'] = getattr(packet[ICMP], 'id', None)
            details['icmp_seq'] = getattr(packet[ICMP], 'seq', None)
        # ARP
        if packet.haslayer(ARP):
            proto_name = "ARP"
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            details['arp_hwtype'] = packet[ARP].hwtype
            details['arp_ptype'] = packet[ARP].ptype
            details['arp_hwlen'] = packet[ARP].hwlen
            details['arp_plen'] = packet[ARP].plen
            details['arp_op'] = packet[ARP].op
            details['arp_hwsrc'] = packet[ARP].hwsrc
            details['arp_psrc'] = packet[ARP].psrc
            details['arp_hwdst'] = packet[ARP].hwdst
            details['arp_pdst'] = packet[ARP].pdst
        # Raw payload
        if packet.haslayer(Raw):
            try:
                details['raw'] = packet[Raw].load[:100].hex()
            except Exception:
                pass
        size = len(packet)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        
        # Convert ports to integers, handle None values
        src_port_int = int(src_port) if src_port and src_port.isdigit() else None
        dst_port_int = int(dst_port) if dst_port and dst_port.isdigit() else None
        
        self.cursor.execute(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, src, dst, proto_name, src_port_int, dst_port_int, size, json.dumps(details))
        )
        self.conn.commit()
        if self.packet_callback:
            self.packet_callback({
                'timestamp': timestamp,
                'src_ip': src,
                'dst_ip': dst,
                'protocol': proto_name,
                'src_port': src_port,
                'dst_port': dst_port,
                'size': size,
                'details': details
            })
    
    def export_packets(self, query=None, format='csv', filename=None):
        """
        Export packets to CSV or JSON
        
        Args:
            query: SQL query to filter packets (None for all)
            format: Export format ('csv' or 'json')
            filename: Output filename (None for auto-generated)
            
        Returns:
            Path to the exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.export_base}_{timestamp}.{format}"
            
        filepath = os.path.join(self.export_dir, filename)
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Default query to get all packets
        if not query:
            query = "SELECT * FROM packets ORDER BY timestamp"
        
        try:
            # Execute query
            self.cursor.execute(query)
            rows = self.cursor.fetchall()
            
            # Get column names
            columns = [description[0] for description in self.cursor.description]
            
            if format.lower() == 'csv':
                with open(filepath, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write header
                    writer.writerow(columns)
                    # Write data
                    writer.writerows(rows)
            
            elif format.lower() == 'json':
                # Convert to list of dictionaries
                result = []
                for row in rows:
                    row_dict = {}
                    for i, col in enumerate(columns):
                        # Parse details JSON if present
                        if col == 'details' and row[i]:
                            try:
                                row_dict[col] = json.loads(row[i])
                            except:
                                row_dict[col] = row[i]
                        else:
                            row_dict[col] = row[i]
                    result.append(row_dict)
                
                # Write JSON file
                with open(filepath, 'w') as jsonfile:
                    json.dump(result, jsonfile, indent=2)
            
            return filepath
            
        except Exception as e:
            print(f"Export error: {e}")
            return None
    
    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        try:
            return get_if_list()
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []