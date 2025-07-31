#!/usr/bin/env python3
# enhanced_packet_capture.py
# PyGuard - Enhanced Packet Capture Module
# 
# A Scapy-based packet capture module that listens on specified network interfaces,
# extracts key packet fields in real-time and stores them in structured JSON or CSV
# output for downstream analysis.

import os
import sys
import time
import json
import csv
import logging
import threading
import argparse
import sqlite3
import queue
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Callable

from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw, get_if_list

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)

logger = logging.getLogger("EnhancedCapture")

class OutputRotator:
    """Handles file rotation based on size or time interval"""
    
    def __init__(self, 
                 base_path: str, 
                 max_size_mb: int = 100, 
                 time_interval_sec: int = 3600,
                 formats: List[str] = None):
        """
        Initialize the output rotator
        
        Args:
            base_path: Base path for output files
            max_size_mb: Maximum file size in MB before rotation
            time_interval_sec: Time interval in seconds before rotation
            formats: List of output formats ('json', 'csv')
        """
        self.base_path = Path(base_path)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.time_interval_sec = time_interval_sec
        self.formats = formats or ['json', 'csv']
        
        # Create output directory if it doesn't exist
        self.base_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Current file handles
        self.current_files = {}
        self.csv_writers = {}
        self.last_rotation_time = time.time()
        self.current_file_sizes = {}
        
        # Initialize files
        self._rotate_files()
    
    def _get_timestamp_str(self) -> str:
        """Get current timestamp string for filenames"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _rotate_files(self) -> None:
        """Rotate output files"""
        # Close existing files
        for fmt, file_handle in self.current_files.items():
            if file_handle:
                file_handle.close()
        
        # Reset file handles and sizes
        self.current_files = {}
        self.csv_writers = {}
        self.current_file_sizes = {}
        
        # Create new files with timestamp
        timestamp = self._get_timestamp_str()
        
        for fmt in self.formats:
            filename = f"{self.base_path}_{timestamp}.{fmt}"
            
            if fmt == 'json':
                self.current_files[fmt] = open(filename, 'w', encoding='utf-8')
                # Initialize JSON array
                self.current_files[fmt].write('[\n')
                self.current_file_sizes[fmt] = 2  # Account for the opening bracket
            
            elif fmt == 'csv':
                self.current_files[fmt] = open(filename, 'w', newline='', encoding='utf-8')
                self.csv_writers[fmt] = csv.writer(self.current_files[fmt])
                # Write comprehensive CSV header with detailed protocol fields
                header = [
                    # Basic packet information
                    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                    'protocol', 'packet_length', 'payload_length',
                    
                    # TCP flags
                    'tcp_flags_syn', 'tcp_flags_ack', 'tcp_flags_fin',
                    'tcp_flags_rst', 'tcp_flags_psh', 'tcp_flags_urg',
                    
                    # Ethernet header fields
                    'eth_src', 'eth_dst', 'eth_type',
                    
                    # IP header fields
                    'ip_version', 'ip_ihl', 'ip_tos', 'ip_id', 
                    'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto',
                    
                    # TCP header fields
                    'tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_window',
                    
                    # UDP header fields
                    'udp_len', 'udp_chksum',
                    
                    # ICMP header fields
                    'icmp_type', 'icmp_code',
                    
                    # DNS fields
                    'dns_id', 'dns_qr', 'dns_opcode', 'dns_qname',
                    
                    # ARP fields
                    'arp_op', 'arp_hwsrc', 'arp_hwdst',
                    
                    # HTTP detection
                    'http_detected'
                ]
                self.csv_writers[fmt].writerow(header)
                self.current_file_sizes[fmt] = len(','.join(header)) + 2  # Rough estimate
        
        self.last_rotation_time = time.time()
        logger.info(f"Rotated output files with timestamp {timestamp}")
    
    def _check_rotation(self) -> bool:
        """Check if files need to be rotated"""
        # Check time-based rotation
        current_time = time.time()
        if current_time - self.last_rotation_time >= self.time_interval_sec:
            logger.debug("Rotating files based on time interval")
            return True
        
        # Check size-based rotation
        for fmt, size in self.current_file_sizes.items():
            if size >= self.max_size_bytes:
                logger.debug(f"Rotating files based on size limit ({fmt})")
                return True
        
        return False
    
    def write_record(self, record: Dict[str, Any]) -> None:
        """
        Write a record to output files
        
        Args:
            record: Dictionary containing packet data
        """
        # Check if rotation is needed
        if self._check_rotation():
            self._rotate_files()
        
        # Write to each format
        for fmt in self.formats:
            if fmt == 'json':
                # Check if we need a comma (not the first record)
                if self.current_file_sizes[fmt] > 2:
                    self.current_files[fmt].write(',\n')
                
                # Write the JSON record
                json_str = json.dumps(record)
                self.current_files[fmt].write(json_str)
                self.current_file_sizes[fmt] += len(json_str) + 2  # +2 for comma and newline
            
            elif fmt == 'csv':
                # Extract fields in the same order as the header with all detailed protocol fields
                tcp_flags = record.get('tcp_flags', {})
                
                row = [
                    # Basic packet information
                    record.get('timestamp', ''),
                    record.get('src_ip', ''),
                    record.get('dst_ip', ''),
                    record.get('src_port', ''),
                    record.get('dst_port', ''),
                    record.get('protocol', ''),
                    record.get('packet_length', 0),
                    record.get('payload_length', 0),
                    
                    # TCP flags
                    tcp_flags.get('SYN', 0),
                    tcp_flags.get('ACK', 0),
                    tcp_flags.get('FIN', 0),
                    tcp_flags.get('RST', 0),
                    tcp_flags.get('PSH', 0),
                    tcp_flags.get('URG', 0),
                    
                    # Ethernet header fields
                    record.get('eth_src', ''),
                    record.get('eth_dst', ''),
                    record.get('eth_type', ''),
                    
                    # IP header fields
                    record.get('ip_version', ''),
                    record.get('ip_ihl', ''),
                    record.get('ip_tos', ''),
                    record.get('ip_id', ''),
                    record.get('ip_flags', ''),
                    record.get('ip_frag', ''),
                    record.get('ip_ttl', ''),
                    record.get('ip_proto', ''),
                    
                    # TCP header fields
                    record.get('tcp_seq', ''),
                    record.get('tcp_ack', ''),
                    record.get('tcp_dataofs', ''),
                    record.get('tcp_window', ''),
                    
                    # UDP header fields
                    record.get('udp_len', ''),
                    record.get('udp_chksum', ''),
                    
                    # ICMP header fields
                    record.get('icmp_type', ''),
                    record.get('icmp_code', ''),
                    
                    # DNS fields
                    record.get('dns_id', ''),
                    record.get('dns_qr', ''),
                    record.get('dns_opcode', ''),
                    record.get('dns_qname', ''),
                    
                    # ARP fields
                    record.get('arp_op', ''),
                    record.get('arp_hwsrc', ''),
                    record.get('arp_hwdst', ''),
                    
                    # HTTP detection
                    1 if record.get('protocol') == 'HTTP' else 0
                ]
                self.csv_writers[fmt].writerow(row)
                
                # Rough estimate of CSV row size
                self.current_file_sizes[fmt] += sum(len(str(field)) for field in row) + len(row)
        
        # Flush to ensure data is written
        for file_handle in self.current_files.values():
            file_handle.flush()
    
    def close(self) -> None:
        """Close all file handles"""
        for fmt, file_handle in self.current_files.items():
            if fmt == 'json':
                # Close the JSON array
                file_handle.write('\n]')
            file_handle.close()
        
        self.current_files = {}
        self.csv_writers = {}


class PacketProcessor:
    """Processes captured packets and extracts relevant fields"""
    
    def __init__(self):
        """Initialize the packet processor"""
        pass
    
    def process_packet(self, packet) -> Dict[str, Any]:
        """
        Process a packet and extract relevant fields
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing extracted packet fields
        """
        # Initialize packet data
        packet_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'src_ip': '',
            'dst_ip': '',
            'src_port': '',
            'dst_port': '',
            'protocol': 'UNKNOWN',
            'packet_length': len(packet),
            'payload_length': 0,
            'tcp_flags': {
                'SYN': 0, 'ACK': 0, 'FIN': 0, 
                'RST': 0, 'PSH': 0, 'URG': 0
            }
        }
        
        # Extract Ethernet layer information with all header fields
        if packet.haslayer(Ether):
            packet_data['eth_src'] = packet[Ether].src
            packet_data['eth_dst'] = packet[Ether].dst
            packet_data['eth_type'] = packet[Ether].type
        
        # Extract IP layer information with all header fields
        if packet.haslayer(IP):
            packet_data['src_ip'] = packet[IP].src
            packet_data['dst_ip'] = packet[IP].dst
            packet_data['ip_version'] = packet[IP].version
            packet_data['ip_ihl'] = packet[IP].ihl
            packet_data['ip_tos'] = packet[IP].tos
            packet_data['ip_len'] = packet[IP].len
            packet_data['ip_id'] = packet[IP].id
            packet_data['ip_flags'] = int(packet[IP].flags)
            packet_data['ip_frag'] = packet[IP].frag
            packet_data['ip_ttl'] = packet[IP].ttl
            packet_data['ip_proto'] = packet[IP].proto
            packet_data['ip_chksum'] = packet[IP].chksum
            packet_data['ip_options'] = str(packet[IP].options)
            packet_data['protocol'] = {
                6: 'TCP', 17: 'UDP', 1: 'ICMP'
            }.get(packet[IP].proto, str(packet[IP].proto))
        
        # Extract TCP layer information with all header fields
        if packet.haslayer(TCP):
            packet_data['src_port'] = packet[TCP].sport
            packet_data['dst_port'] = packet[TCP].dport
            
            # Extract detailed TCP header fields
            packet_data['tcp_seq'] = packet[TCP].seq
            packet_data['tcp_ack'] = packet[TCP].ack
            packet_data['tcp_dataofs'] = packet[TCP].dataofs
            packet_data['tcp_reserved'] = packet[TCP].reserved
            packet_data['tcp_flags_raw'] = str(packet[TCP].flags)
            packet_data['tcp_window'] = packet[TCP].window
            packet_data['tcp_chksum'] = packet[TCP].chksum
            packet_data['tcp_urgptr'] = packet[TCP].urgptr
            packet_data['tcp_options'] = str(packet[TCP].options)
            
            # Extract TCP flags
            flags = packet[TCP].flags
            packet_data['tcp_flags']['SYN'] = 1 if 'S' in flags else 0
            packet_data['tcp_flags']['ACK'] = 1 if 'A' in flags else 0
            packet_data['tcp_flags']['FIN'] = 1 if 'F' in flags else 0
            packet_data['tcp_flags']['RST'] = 1 if 'R' in flags else 0
            packet_data['tcp_flags']['PSH'] = 1 if 'P' in flags else 0
            packet_data['tcp_flags']['URG'] = 1 if 'U' in flags else 0
            
            # Check for payload
            if packet.haslayer(Raw):
                packet_data['payload_length'] = len(packet[Raw].load)
                packet_data['payload_hex'] = packet[Raw].load[:100].hex()
                
                # Try to detect HTTP
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if any(method in payload for method in ['GET ', 'POST ', 'HTTP/']):
                        packet_data['protocol'] = 'HTTP'
                        packet_data['http_data'] = payload[:200]
                        
                        # Try to extract HTTP headers
                        if '\r\n' in payload:
                            headers = payload.split('\r\n\r\n')[0].split('\r\n')
                            packet_data['http_headers'] = headers
                            
                            # Extract HTTP method, URI, version
                            if len(headers) > 0 and ' ' in headers[0]:
                                request_parts = headers[0].split(' ')
                                if len(request_parts) >= 3:
                                    packet_data['http_method'] = request_parts[0]
                                    packet_data['http_uri'] = request_parts[1]
                                    packet_data['http_version'] = request_parts[2]
                except:
                    pass
        
        # Extract UDP layer information with all header fields
        elif packet.haslayer(UDP):
            packet_data['src_port'] = packet[UDP].sport
            packet_data['dst_port'] = packet[UDP].dport
            packet_data['udp_len'] = packet[UDP].len
            packet_data['udp_chksum'] = packet[UDP].chksum
            
            # Check for DNS
            if packet.haslayer(DNS):
                packet_data['protocol'] = 'DNS'
                
                # Extract detailed DNS header fields
                packet_data['dns_id'] = packet[DNS].id
                packet_data['dns_qr'] = packet[DNS].qr
                packet_data['dns_opcode'] = packet[DNS].opcode
                packet_data['dns_aa'] = packet[DNS].aa
                packet_data['dns_tc'] = packet[DNS].tc
                packet_data['dns_rd'] = packet[DNS].rd
                packet_data['dns_ra'] = packet[DNS].ra
                packet_data['dns_z'] = packet[DNS].z
                packet_data['dns_rcode'] = packet[DNS].rcode
                packet_data['dns_qdcount'] = packet[DNS].qdcount
                packet_data['dns_ancount'] = packet[DNS].ancount
                packet_data['dns_nscount'] = packet[DNS].nscount
                packet_data['dns_arcount'] = packet[DNS].arcount
                
                # Extract DNS query/response info
                if packet[DNS].qr == 0:  # Query
                    packet_data['dns_type'] = 'query'
                else:  # Response
                    packet_data['dns_type'] = 'response'
                
                # Extract DNS query name if available
                if packet[DNS].qd:
                    try:
                        packet_data['dns_qname'] = packet[DNS].qd.qname.decode('utf-8')
                        packet_data['dns_qtype'] = packet[DNS].qd.qtype
                        packet_data['dns_qclass'] = packet[DNS].qd.qclass
                    except:
                        packet_data['dns_qname'] = str(packet[DNS].qd.qname)
                
                # Extract DNS answer if available
                if packet[DNS].an:
                    try:
                        packet_data['dns_an_name'] = str(packet[DNS].an.rrname)
                        packet_data['dns_an_type'] = packet[DNS].an.type
                        packet_data['dns_an_rdata'] = str(packet[DNS].an.rdata)
                        packet_data['dns_an_ttl'] = packet[DNS].an.ttl
                    except:
                        packet_data['dns_an_rdata'] = str(packet[DNS].an)
            
            # Check for payload
            if packet.haslayer(Raw):
                packet_data['payload_length'] = len(packet[Raw].load)
                packet_data['payload_hex'] = packet[Raw].load[:100].hex()
        
        # Extract ICMP information with all header fields
        elif packet.haslayer(ICMP):
            packet_data['icmp_type'] = packet[ICMP].type
            packet_data['icmp_code'] = packet[ICMP].code
            packet_data['icmp_chksum'] = packet[ICMP].chksum
            packet_data['icmp_id'] = getattr(packet[ICMP], 'id', None)
            packet_data['icmp_seq'] = getattr(packet[ICMP], 'seq', None)
            
            # Map ICMP type/code to human-readable format
            icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded"
            }
            packet_data['icmp_type_name'] = icmp_types.get(packet_data['icmp_type'], f"Type {packet_data['icmp_type']}")
            
            # Check for payload
            if packet.haslayer(Raw):
                packet_data['payload_length'] = len(packet[Raw].load)
                packet_data['payload_hex'] = packet[Raw].load[:100].hex()
        
        # Extract ARP information with all header fields
        elif packet.haslayer(ARP):
            packet_data['protocol'] = 'ARP'
            packet_data['src_ip'] = packet[ARP].psrc
            packet_data['dst_ip'] = packet[ARP].pdst
            packet_data['arp_hwtype'] = packet[ARP].hwtype
            packet_data['arp_ptype'] = packet[ARP].ptype
            packet_data['arp_hwlen'] = packet[ARP].hwlen
            packet_data['arp_plen'] = packet[ARP].plen
            packet_data['arp_op'] = packet[ARP].op
            packet_data['arp_op_name'] = 'request' if packet[ARP].op == 1 else 'reply'
            packet_data['arp_hwsrc'] = packet[ARP].hwsrc
            packet_data['arp_hwdst'] = packet[ARP].hwdst
        
        return packet_data


class DatabaseManager:
    """Manages database operations for packet storage"""
    
    def __init__(self, db_path: str = 'packets.db'):
        """
        Initialize the database manager
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.batch_size = 50  # Reduced from 100 to 50 for better memory management
        self.packet_batch = []
        self.memory_check_counter = 0
        self.memory_check_interval = 100  # Check memory every 100 packets
        
        # Initialize database
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize database with schema and indexes"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            
            # Enable WAL mode for better concurrency and performance
            self.conn.execute('PRAGMA journal_mode = WAL')
            
            # Reduce synchronous writes for better performance
            # NORMAL provides a good balance between safety and performance
            self.conn.execute('PRAGMA synchronous = NORMAL')
            
            # Increase cache size for better performance
            self.conn.execute('PRAGMA cache_size = -10000')  # ~10MB cache
            
            self.cursor = self.conn.cursor()
            
            # Create enhanced table schema with additional fields
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
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
            
            # Create indexes for better query performance
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets(dst_ip)')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_port ON packets(src_port)')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_port ON packets(dst_port)')
            
            self.conn.commit()
            logger.info(f"Database initialized successfully at {self.db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise
    
    def _optimize_json_details(self, packet_data: Dict[str, Any]) -> str:
        """
        Optimize JSON serialization by limiting stored fields
        
        Args:
            packet_data: Dictionary containing packet data
            
        Returns:
            str: JSON string with optimized fields
        """
        # Create a subset of the packet data with only essential fields
        essential_fields = {
            'timestamp': packet_data.get('timestamp'),
            'src_ip': packet_data.get('src_ip'),
            'dst_ip': packet_data.get('dst_ip'),
            'protocol': packet_data.get('protocol'),
            'src_port': packet_data.get('src_port'),
            'dst_port': packet_data.get('dst_port'),
            'packet_length': packet_data.get('packet_length'),
            'payload_length': packet_data.get('payload_length'),
            'tcp_flags': packet_data.get('tcp_flags', {}),
        }
        
        # Include protocol-specific fields based on protocol
        protocol = packet_data.get('protocol', '').upper()
        
        if protocol == 'TCP':
            essential_fields.update({
                'tcp_seq': packet_data.get('tcp_seq'),
                'tcp_ack': packet_data.get('tcp_ack'),
                'tcp_window': packet_data.get('tcp_window'),
            })
        elif protocol == 'UDP':
            essential_fields.update({
                'udp_len': packet_data.get('udp_len'),
                'udp_chksum': packet_data.get('udp_chksum'),
            })
        elif protocol == 'ICMP':
            essential_fields.update({
                'icmp_type': packet_data.get('icmp_type'),
                'icmp_code': packet_data.get('icmp_code'),
            })
        elif protocol == 'DNS':
            essential_fields.update({
                'dns_id': packet_data.get('dns_id'),
                'dns_qr': packet_data.get('dns_qr'),
                'dns_qname': packet_data.get('dns_qname'),
            })
        elif protocol == 'HTTP':
            # Include minimal HTTP fields
            if 'http_method' in packet_data:
                essential_fields['http_method'] = packet_data['http_method']
            if 'http_path' in packet_data:
                essential_fields['http_path'] = packet_data['http_path']
            if 'http_version' in packet_data:
                essential_fields['http_version'] = packet_data['http_version']
        
        # Serialize to JSON with minimal overhead
        return json.dumps(essential_fields)
    
    def _check_memory_usage(self) -> bool:
        """
        Monitor memory usage and take action if it exceeds threshold
        
        Returns:
            bool: True if memory usage is high, False otherwise
        """
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            
            # If memory usage is above 70%, consider it high
            if memory_percent > 70:
                # Force flush the batch to free up memory
                self.flush_batch()
                
                # Force garbage collection
                import gc
                gc.collect()
                
                return True
            return False
        except ImportError:
            # If psutil is not available, use a simpler approach
            if len(self.packet_batch) > self.batch_size * 2:
                self.flush_batch()
                return True
            return False
        except Exception as e:
            logger.error(f"Memory check error: {e}")
            return False
    
    def add_packet(self, packet_data: Dict[str, Any]) -> None:
        """
        Add a packet to the batch for later insertion
        
        Args:
            packet_data: Dictionary containing packet data
        """
        # Periodically check memory usage
        self.memory_check_counter += 1
        if self.memory_check_counter >= self.memory_check_interval:
            self.memory_check_counter = 0
            self._check_memory_usage()
        # Extract fields for database insertion
        packet_record = (
            packet_data.get('timestamp'),
            packet_data.get('src_ip'),
            packet_data.get('dst_ip'),
            packet_data.get('protocol'),
            packet_data.get('src_port'),
            packet_data.get('dst_port'),
            packet_data.get('packet_length'),
            packet_data.get('payload_length'),
            packet_data.get('tcp_flags', {}).get('SYN', 0),
            packet_data.get('tcp_flags', {}).get('ACK', 0),
            packet_data.get('tcp_flags', {}).get('FIN', 0),
            packet_data.get('tcp_flags', {}).get('RST', 0),
            packet_data.get('tcp_flags', {}).get('PSH', 0),
            packet_data.get('tcp_flags', {}).get('URG', 0),
            self._optimize_json_details(packet_data)
        )
        
        self.packet_batch.append(packet_record)
        
        # Batch insert when we reach batch_size
        if len(self.packet_batch) >= self.batch_size:
            self.flush_batch()
    
    def flush_batch(self) -> None:
        """Insert all packets in the batch to database"""
        if not self.packet_batch:
            return
        
        try:
            self.cursor.executemany(
                """INSERT INTO packets 
                   (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, 
                    packet_length, payload_length, 
                    tcp_flags_syn, tcp_flags_ack, tcp_flags_fin, 
                    tcp_flags_rst, tcp_flags_psh, tcp_flags_urg, 
                    details) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                self.packet_batch
            )
            self.conn.commit()
            logger.debug(f"Inserted {len(self.packet_batch)} packets to database")
            self.packet_batch.clear()
                
        except sqlite3.Error as e:
            logger.error(f"Database insert error: {e}")
            self.packet_batch.clear()  # Clear batch to prevent memory buildup
    
    def close(self) -> None:
        """Flush remaining packets and close database"""
        self.flush_batch()
        if self.conn:
            self.conn.close()
        logger.info("Database operations completed")


class EnhancedPacketCapture:
    """Main class for enhanced packet capture functionality"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the enhanced packet capture
        
        Args:
            config: Configuration dictionary with the following keys:
                - interfaces: List of network interfaces to capture on
                - bpf_filter: BPF filter expression
                - max_packets: Maximum number of packets to capture (0 for infinite)
                - duration: Maximum duration in seconds (0 for infinite)
                - output_dir: Directory for output files
                - output_base: Base filename for output files
                - db_path: Path to SQLite database file
                - flush_interval: Interval in seconds to flush data to disk
                - max_file_size: Maximum file size in MB before rotation
                - rotation_interval: Time interval in seconds before file rotation
                - sample_rate: Packet sampling rate (1 = all packets, 2 = every other packet, etc.)
                - formats: List of output formats ('json', 'csv')
        """
        # Set default configuration
        self.config = {
            'interfaces': [],
            'bpf_filter': None,
            'max_packets': 0,
            'duration': 0,
            'adaptive_sampling': True,  # Enable adaptive sampling by default
            'output_dir': 'captures',
            'output_base': 'packets',
            'db_path': 'packets.db',
            'flush_interval': 10,
            'max_file_size': 100,
            'rotation_interval': 3600,
            'sample_rate': 1,
            'formats': ['json', 'csv']
        }
        
        # Update with provided configuration
        if config:
            self.config.update(config)
        
        # Initialize components
        self.packet_processor = PacketProcessor()
        self.db_manager = DatabaseManager(self.config['db_path'])
        
        # Setup output path
        output_path = os.path.join(self.config['output_dir'], self.config['output_base'])
        self.output_rotator = OutputRotator(
            base_path=output_path,
            max_size_mb=self.config['max_file_size'],
            time_interval_sec=self.config['rotation_interval'],
            formats=self.config['formats']
        )
        
        # Runtime variables
        self.running = False
        self.start_time = None
        self.packet_count = 0
        self.sample_counter = 0
        self.threads = []
        self.packet_queue = queue.Queue(maxsize=10000)  # Buffer for async processing
        
        # Error tracking
        self.error_count = 0
        self.dropped_packets = 0
        
        # Setup error log
        logging.basicConfig(
            filename=os.path.join(self.config['output_dir'], 'capture_errors.log'),
            level=logging.ERROR,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def _packet_handler(self, packet) -> None:
        """
        Handle a captured packet with adaptive sampling
        
        Args:
            packet: Scapy packet object
        """
        # Implement adaptive packet sampling based on packet count
        self.sample_counter += 1
        
        # Determine sampling rate based on current packet count
        if self.config.get('adaptive_sampling', False):
            if self.packet_count > 700:  # High load threshold
                adaptive_rate = 5  # Sample every 5th packet
            elif self.packet_count > 500:  # Medium load threshold
                adaptive_rate = 3  # Sample every 3rd packet
            elif self.packet_count > 300:  # Low load threshold
                adaptive_rate = 2  # Sample every 2nd packet
            else:
                adaptive_rate = 1  # Process every packet
                
            # Use the adaptive rate instead of the configured rate
            effective_rate = adaptive_rate
        else:
            # Use the configured sample rate
            effective_rate = self.config['sample_rate']
        
        # Skip packets based on sampling rate
        if effective_rate > 1 and self.sample_counter % effective_rate != 0:
            return
        
        # Check if we've reached the maximum packet count
        if self.config['max_packets'] > 0 and self.packet_count >= self.config['max_packets']:
            self.stop()
            return
        
        # Check if we've exceeded the maximum duration
        if self.config['duration'] > 0 and time.time() - self.start_time >= self.config['duration']:
            self.stop()
            return
        
        try:
            # Check queue fill level to implement throttling
            queue_fill_percent = self.packet_queue.qsize() / self.packet_queue.maxsize * 100
            
            # Implement throttling based on queue fill level
            if queue_fill_percent > 80:
                # High load - very aggressive throttling
                if self.packet_count % 10 != 0:  # Process only 1 in 10 packets
                    return
            elif queue_fill_percent > 60:
                # Medium load - aggressive throttling
                if self.packet_count % 5 != 0:  # Process only 1 in 5 packets
                    return
            elif queue_fill_percent > 40:
                # Moderate load - moderate throttling
                if self.packet_count % 3 != 0:  # Process only 1 in 3 packets
                    return
            
            # Put packet in queue for asynchronous processing with timeout
            try:
                # Use a short timeout to prevent blocking
                self.packet_queue.put(packet, block=True, timeout=0.01)
            except queue.Full:
                self.dropped_packets += 1
                logger.warning(f"Packet queue full, dropped packet (total dropped: {self.dropped_packets})")
        
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error handling packet: {e}")
    
    def _process_packet_queue(self) -> None:
        """Process packets from the queue"""
        while self.running or not self.packet_queue.empty():
            try:
                # Get packet from queue with timeout
                try:
                    packet = self.packet_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Process the packet
                packet_data = self.packet_processor.process_packet(packet)
                
                # Store in database
                self.db_manager.add_packet(packet_data)
                
                # Write to output files
                self.output_rotator.write_record(packet_data)
                
                # Increment packet count
                self.packet_count += 1
                
                # Mark task as done
                self.packet_queue.task_done()
                
            except Exception as e:
                self.error_count += 1
                logger.error(f"Error processing packet from queue: {e}")
    
    def _flush_data_periodically(self) -> None:
        """Periodically flush data to disk"""
        while self.running:
            try:
                # Sleep for the flush interval
                time.sleep(self.config['flush_interval'])
                
                # Flush database batch
                self.db_manager.flush_batch()
                
                logger.debug(f"Periodic flush: {self.packet_count} packets processed, "
                           f"{self.dropped_packets} dropped, {self.error_count} errors")
                
            except Exception as e:
                logger.error(f"Error in periodic flush: {e}")
    
    def start(self) -> None:
        """Start packet capture"""
        if self.running:
            logger.warning("Packet capture already running")
            return
        
        self.running = True
        self.start_time = time.time()
        self.packet_count = 0
        self.sample_counter = 0
        self.error_count = 0
        self.dropped_packets = 0
        
        # Start packet processing thread
        processor_thread = threading.Thread(
            target=self._process_packet_queue,
            daemon=True,
            name="PacketProcessor"
        )
        processor_thread.start()
        self.threads.append(processor_thread)
        
        # Start flush thread
        flush_thread = threading.Thread(
            target=self._flush_data_periodically,
            daemon=True,
            name="DataFlusher"
        )
        flush_thread.start()
        self.threads.append(flush_thread)
        
        # Start capture on each interface
        for interface in self.config['interfaces']:
            try:
                # Start in a separate thread to handle multiple interfaces
                capture_thread = threading.Thread(
                    target=self._capture_on_interface,
                    args=(interface,),
                    daemon=True,
                    name=f"Capture-{interface}"
                )
                capture_thread.start()
                self.threads.append(capture_thread)
                logger.info(f"Started capture on interface {interface}")
                
            except Exception as e:
                logger.error(f"Error starting capture on interface {interface}: {e}")
        
        logger.info(f"Packet capture started on interfaces: {', '.join(self.config['interfaces'])}")
    
    def _capture_on_interface(self, interface: str) -> None:
        """
        Capture packets on a specific interface
        
        Args:
            interface: Network interface name
        """
        try:
            sniff(
                iface=interface,
                filter=self.config['bpf_filter'],
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error in capture thread for interface {interface}: {e}")
    
    def stop(self) -> None:
        """Stop packet capture"""
        if not self.running:
            logger.warning("Packet capture not running")
            return
        
        logger.info("Stopping packet capture...")
        self.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=5.0)
        
        # Flush remaining data
        self.db_manager.flush_batch()
        
        # Close output files
        self.output_rotator.close()
        
        # Close database connection
        self.db_manager.close()
        
        # Calculate statistics
        duration = time.time() - self.start_time
        packets_per_second = self.packet_count / duration if duration > 0 else 0
        
        logger.info(f"Packet capture stopped. Statistics:")
        logger.info(f"  Duration: {duration:.2f} seconds")
        logger.info(f"  Packets captured: {self.packet_count}")
        logger.info(f"  Packets/second: {packets_per_second:.2f}")
        logger.info(f"  Dropped packets: {self.dropped_packets}")
        logger.info(f"  Errors: {self.error_count}")
        
        self.threads = []


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Enhanced Packet Capture Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Interface selection
    parser.add_argument("-i", "--interfaces", nargs="+", required=True,
                        help="Network interfaces to capture on (e.g., eth0 wlan0)")
    
    # Capture parameters
    parser.add_argument("-f", "--filter", type=str, default="",
                        help="BPF filter expression (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Maximum number of packets to capture (0 for infinite)")
    parser.add_argument("-d", "--duration", type=int, default=0,
                        help="Maximum duration in seconds (0 for infinite)")
    
    # Output parameters
    parser.add_argument("-o", "--output-dir", type=str, default="captures",
                        help="Directory for output files")
    parser.add_argument("-b", "--output-base", type=str, default="packets",
                        help="Base filename for output files")
    parser.add_argument("--db-path", type=str, default="packets.db",
                        help="Path to SQLite database file")
    
    # Performance parameters
    parser.add_argument("--flush-interval", type=int, default=10,
                        help="Interval in seconds to flush data to disk")
    parser.add_argument("--max-file-size", type=int, default=100,
                        help="Maximum file size in MB before rotation")
    parser.add_argument("--rotation-interval", type=int, default=3600,
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
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Convert arguments to config dictionary
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
    
    return config


def main():
    """Main function"""
    try:
        # Parse command line arguments
        config = parse_arguments()
        
        # Create and start packet capture
        capture = EnhancedPacketCapture(config)
        capture.start()
        
        # Wait for user to stop capture
        print("Packet capture running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
    except Exception as e:
        logger.error(f"Error in main: {e}")
    finally:
        if 'capture' in locals():
            capture.stop()


if __name__ == "__main__":
    main()