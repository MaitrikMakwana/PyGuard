# packet_sniffer.py
# PyGuard Pro - Week 1 Milestone: Enhanced Packet Sniffer
# Requirements: pip install scapy
# Usage: python packet_sniffer.py -c 10 -f "tcp port 80" -i eth0
#
# Sample Output:
# Source IP: 192.168.1.2 -> Destination IP: 8.8.8.8 | Protocol: ICMP
# Source IP: 10.0.0.5 -> Destination IP: 192.168.1.1 | Protocol: TCP | Src Port: 443 -> Dst Port: 52344
# ...

from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw, get_if_list
import argparse
import sqlite3
import time
import json
import logging
import os
import sys
from contextlib import contextmanager
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketDatabase:
    def __init__(self, db_path='packets.db'):
        self.db_path = db_path
        self.batch_size = 100
        self.packet_batch = []
        self._init_database()
    
    def _init_database(self):
        """Initialize database with improved schema and indexes"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Create improved table schema
                cursor.execute('''
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
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets(dst_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_port ON packets(src_port)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_port ON packets(dst_port)')
                
                conn.commit()
                logger.info(f"Database initialized successfully at {self.db_path}")
                
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            sys.exit(1)
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute('PRAGMA journal_mode=WAL')  # Enable WAL mode for better concurrency
            conn.execute('PRAGMA synchronous=NORMAL')  # Balance between safety and performance
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def add_packet(self, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details):
        """Add a packet to the batch for later insertion"""
        # Convert ports to integers, handle None values
        src_port_int = int(src_port) if src_port and src_port.isdigit() else None
        dst_port_int = int(dst_port) if dst_port and dst_port.isdigit() else None
        
        packet_data = (
            timestamp, src_ip, dst_ip, protocol, 
            src_port_int, dst_port_int, size, json.dumps(details)
        )
        
        self.packet_batch.append(packet_data)
        
        # Batch insert when we reach batch_size
        if len(self.packet_batch) >= self.batch_size:
            self.flush_batch()
    
    def flush_batch(self):
        """Insert all packets in the batch to database"""
        if not self.packet_batch:
            return
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany(
                    """INSERT INTO packets 
                       (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    self.packet_batch
                )
                conn.commit()
                logger.debug(f"Inserted {len(self.packet_batch)} packets to database")
                self.packet_batch.clear()
                
        except sqlite3.Error as e:
            logger.error(f"Database insert error: {e}")
            self.packet_batch.clear()  # Clear batch to prevent memory buildup
    
    def close(self):
        """Flush remaining packets and close database"""
        self.flush_batch()
        logger.info("Database operations completed")

# Global database instance (will be initialized in main)
db = None

def validate_filter(filter_str):
    """Enhanced BPF filter validation with Wireshark-like capabilities"""
    if not filter_str:
        return True, ""
    
    try:
        # Test the filter by attempting to compile it with scapy
        from scapy.all import conf
        # This will raise an exception if the filter is invalid
        # We can't directly test BPF compilation, but we can check basic syntax
        
        # Enhanced validation - check for common BPF keywords and operators
        valid_keywords = [
            # Protocol keywords
            'tcp', 'udp', 'icmp', 'arp', 'ip', 'ip6', 'ether', 'rarp', 'atalk', 'aarp', 
            'decnet', 'lat', 'sca', 'moprc', 'mopdl', 'iso', 'stp', 'ipx', 'netbeui',
            
            # Direction keywords
            'src', 'dst', 'host', 'net', 'port', 'portrange', 'gateway',
            
            # Logical operators
            'and', 'or', 'not', '&&', '||', '!',
            
            # Comparison operators
            'greater', 'less', 'len', 'proto', 'protochain',
            
            # Address keywords
            'broadcast', 'multicast',
            
            # VLAN keywords
            'vlan', 'mpls',
            
            # Common protocols by number
            'icmp6', 'esp', 'ah',
            
            # TCP flag keywords
            'tcpflags', 'tcp-syn', 'tcp-rst', 'tcp-ack', 'tcp-fin', 'tcp-push', 'tcp-urg'
        ]
        
        # Check for dangerous characters that could cause command injection
        dangerous_chars = [';', '$', '`', '\n', '\r', '\t']
        for char in dangerous_chars:
            if char in filter_str:
                return False, f"Dangerous character '{char}' detected in filter"
        
        # Check for shell operators that could be dangerous (but allow BPF operators)
        # Look for shell-style && or || (not BPF 'and'/'or')
        if '&&' in filter_str or '||' in filter_str:
            return False, "Shell operators (&& or ||) detected - use 'and'/'or' instead"
        
        # Check for standalone & or | that might be shell operators 
        # (but allow them in BPF expressions like tcp[flags] & tcp-syn)
        import re
        # More specific check: look for & or | that are clearly shell operators
        # Allow BPF bitwise operations but block potential shell injection
        shell_patterns = [
            r'\s+&\s+(?!tcp-|udp-|\d|\w+!=|\w+=)',  # & not followed by BPF constructs
            r'\s+\|\s+(?!tcp-|udp-|\d)',            # | not followed by BPF constructs
            r';\s*[&|]',                           # semicolon followed by operator
            r'[&|]\s*;',                           # operator followed by semicolon
            r'\s&\s[a-z]+\s',                      # & with suspicious commands
            r'\|\s*(rm|cat|ls|echo|curl|wget)',    # pipe to dangerous commands
        ]
        
        for pattern in shell_patterns:
            if re.search(pattern, filter_str):
                return False, "Potential shell injection detected in filter"
        
        # Basic syntax validation
        filter_lower = filter_str.lower()
        
        # Check for balanced parentheses
        if filter_str.count('(') != filter_str.count(')'):
            return False, "Unbalanced parentheses in filter expression"
            
        # Check for balanced brackets
        if filter_str.count('[') != filter_str.count(']'):
            return False, "Unbalanced brackets in filter expression"
        
        # Check for empty expressions in parentheses
        if '()' in filter_str:
            return False, "Empty parentheses found in filter expression"
            
        # Validate common filter patterns
        import re
        
        # Pattern validation for common expressions
        patterns = [
            r'host\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # host IP
            r'net\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?',  # network
            r'port\s+\d{1,5}',  # port number
            r'portrange\s+\d{1,5}-\d{1,5}',  # port range
            r'(tcp|udp|icmp|arp|ip6?)\s+(port\s+\d{1,5}|host\s+[\w\d\.\:]+)',  # protocol with port/host
            r'len\s*[><]=?\s*\d+',  # length comparisons
            r'proto\s+\d{1,3}',  # protocol number
        ]
        
        # Check if filter contains valid patterns or keywords
        has_valid_content = False
        words = re.findall(r'\b\w+\b', filter_lower)
        
        # Must have at least one valid keyword (not just numbers or random words)
        keyword_found = False
        for word in words:
            if word in valid_keywords:
                keyword_found = True
                break
        
        # Check for valid patterns even if no keywords found
        pattern_found = False
        for pattern in patterns:
            if re.search(pattern, filter_lower):
                pattern_found = True
                break
        
        has_valid_content = keyword_found or pattern_found
                
        if not has_valid_content and filter_str.strip():
            return False, "Filter contains no recognized BPF keywords or patterns"
            
        return True, "Filter syntax appears valid"
        
    except Exception as e:
        return False, f"Filter validation error: {str(e)}"

def get_filter_help():
    """Get comprehensive filter help similar to Wireshark"""
    help_text = """
=== BPF (Berkeley Packet Filter) Syntax Help ===

BASIC SYNTAX:
  Primitives can be combined with logical operators: and, or, not (or &&, ||, !)

PROTOCOL FILTERS:
  tcp                    - TCP packets only
  udp                    - UDP packets only  
  icmp                   - ICMP packets only
  arp                    - ARP packets only
  ip                     - IPv4 packets only
  ip6                    - IPv6 packets only

HOST AND NETWORK FILTERS:
  host 192.168.1.1       - Traffic to/from specific host
  src host 192.168.1.1   - Traffic from specific host
  dst host 192.168.1.1   - Traffic to specific host
  net 192.168.1.0/24     - Traffic to/from network
  src net 192.168.0.0/16 - Traffic from network
  dst net 10.0.0.0/8     - Traffic to network

PORT FILTERS:
  port 80                - Traffic on port 80 (any direction)
  src port 80            - Traffic from port 80
  dst port 80            - Traffic to port 80
  portrange 1000-2000    - Traffic on ports 1000-2000

SIZE FILTERS:
  len > 100              - Packets larger than 100 bytes
  len < 60               - Packets smaller than 60 bytes
  len >= 1500            - Packets 1500 bytes or larger

PROTOCOL NUMBER:
  proto 6                - Same as tcp (protocol number 6)
  proto 17               - Same as udp (protocol number 17)
  proto 1                - Same as icmp (protocol number 1)

COMBINATION EXAMPLES:
  tcp and port 80                           - HTTP traffic
  udp and port 53                           - DNS traffic  
  host 8.8.8.8 and (tcp or udp)           - TCP/UDP to Google DNS
  tcp and (port 80 or port 443)           - HTTP/HTTPS traffic
  not arp and not icmp                     - Exclude ARP and ICMP
  src host 192.168.1.100 and dst port 22  - SSH from specific host
  tcp and len > 1000                       - Large TCP packets
  (tcp and port 80) or (udp and port 53)  - HTTP or DNS

COMMON PRESETS:
  Web Traffic: tcp and (port 80 or port 443 or port 8080)
  Email: tcp and (port 25 or port 110 or port 143 or port 993 or port 995)
  DNS: udp and port 53
  SSH: tcp and port 22
  FTP: tcp and (port 20 or port 21)
  Telnet: tcp and port 23
  DHCP: udp and (port 67 or port 68)
  SNMP: udp and (port 161 or port 162)
"""
    return help_text

def get_common_filters():
    """Get dictionary of common filter presets"""
    return {
        "web_traffic": "tcp and (port 80 or port 443 or port 8080)",
        "dns_traffic": "udp and port 53",
        "email_traffic": "tcp and (port 25 or port 110 or port 143 or port 993 or port 995)",
        "ssh_traffic": "tcp and port 22",
        "ftp_traffic": "tcp and (port 20 or port 21)",
        "dhcp_traffic": "udp and (port 67 or port 68)",
        "icmp_traffic": "icmp",
        "arp_traffic": "arp",
        "large_packets": "len > 1000",
        "small_packets": "len < 64",
        "tcp_syn": "tcp and tcp[tcpflags] & tcp-syn != 0",
        "tcp_rst": "tcp and tcp[tcpflags] & tcp-rst != 0",
        "broadcast": "ether broadcast or arp",
        "multicast": "ether multicast",
        "non_standard_ports": "tcp and not (port 80 or port 443 or port 22 or port 25 or port 53)",
    }

def validate_interface(interface):
    """Validate if the network interface exists"""
    if not interface:
        return True
    
    try:
        available_interfaces = get_if_list()
        return interface in available_interfaces
    except Exception as e:
        logger.warning(f"Could not validate interface {interface}: {e}")
        return True  # Allow it to proceed, let scapy handle the error

def print_packet(packet):
    """Print packet summary and store in database"""
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
    # Print as a table row
    print(f"{src:<16} {dst:<16} {proto_name:<8} {src_port:<10} {dst_port:<10} {size:<8} {json.dumps(details)[:40]:<40}")
    
    # Store in database using improved batch system
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        db.add_packet(timestamp, src, dst, proto_name, src_port, dst_port, size, details)
    except Exception as e:
        logger.error(f"Error storing packet in database: {e}")

def main():
    """Main function with improved argument parsing and error handling"""
    parser = argparse.ArgumentParser(
        description="Enhanced Packet Sniffer with customizable filters",
        epilog="""
Examples:
  python packet_sniffer.py -c 50 -f "tcp port 80"           # Capture 50 HTTP packets
  python packet_sniffer.py -f "udp port 53" -i eth0         # Capture DNS packets on eth0
  python packet_sniffer.py -f "host 8.8.8.8"                # Capture packets to/from Google DNS
  python packet_sniffer.py -f "tcp and port 443"            # Capture HTTPS traffic
  python packet_sniffer.py -f "icmp"                        # Capture only ICMP packets
  python packet_sniffer.py --list-interfaces                # List available interfaces
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-c", "--count", type=int, default=10, 
                       help="Number of packets to capture (default: 10, 0 for infinite)")
    parser.add_argument("-i", "--iface", type=str, 
                       help="Network interface to sniff on (optional)")
    parser.add_argument("-f", "--filter", type=str, default="ip", 
                       help="BPF filter expression (default: 'ip')")
    parser.add_argument("--list-interfaces", action="store_true",
                       help="List available network interfaces and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose logging")
    parser.add_argument("--db-path", type=str, default="packets.db",
                       help="Path to SQLite database file (default: packets.db)")
    parser.add_argument("--filter-help", action="store_true",
                       help="Show comprehensive BPF filter syntax help and exit")
    parser.add_argument("--common-filters", action="store_true",
                       help="Show common filter presets and exit")
    parser.add_argument("--preset", type=str,
                       help="Use a preset filter (use --common-filters to see available presets)")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Show filter help and exit if requested
    if args.filter_help:
        print(get_filter_help())
        return
        
    # Show common filters and exit if requested
    if args.common_filters:
        print("=== Common Filter Presets ===\n")
        common_filters = get_common_filters()
        for name, filter_expr in common_filters.items():
            print(f"{name.replace('_', ' ').title():<20}: {filter_expr}")
        print("\nUsage: --preset <preset_name>")
        print("Example: --preset web_traffic")
        return
    
    # Handle preset filters
    if args.preset:
        common_filters = get_common_filters()
        if args.preset in common_filters:
            args.filter = common_filters[args.preset]
            print(f"Using preset filter '{args.preset}': {args.filter}")
        else:
            print(f"Error: Unknown preset '{args.preset}'")
            print("Available presets:")
            for name in common_filters.keys():
                print(f"  - {name}")
            return
    
    # List interfaces and exit if requested
    if args.list_interfaces:
        print("Available network interfaces:")
        try:
            interfaces = get_if_list()
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
        except Exception as e:
            print(f"Error listing interfaces: {e}")
        return
    
    # Validate filter
    is_valid, error_msg = validate_filter(args.filter)
    if not is_valid:
        print(f"Error: Invalid filter expression '{args.filter}'")
        print(f"Reason: {error_msg}")
        print("\nUse --filter-help for detailed syntax information")
        print("Examples: 'tcp port 80', 'udp port 53', 'host 192.168.1.1'")
        return
    
    # Validate interface
    if args.iface and not validate_interface(args.iface):
        print(f"Warning: Interface '{args.iface}' not found in available interfaces.")
        print("Available interfaces:")
        try:
            interfaces = get_if_list()
            for iface in interfaces:
                print(f"  - {iface}")
        except Exception:
            pass
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            return
    
    # Initialize database with custom path
    global db
    if db is None:
        db = PacketDatabase(args.db_path)
    
    # Display configuration
    count_str = str(args.count) if args.count > 0 else "infinite"
    interface_str = f" on interface '{args.iface}'" if args.iface else ""
    
    print(f"=== PyGuard Pro Packet Sniffer ===")
    print(f"Capturing {count_str} packets{interface_str}")
    print(f"Filter: {args.filter}")
    print(f"Database: {args.db_path}")
    print()
    
    # Print table header
    print(f"{'Source IP':<16} {'Destination IP':<16} {'Protocol':<8} {'Src Port':<10} {'Dst Port':<10} {'Size':<8} {'Details':<40}")
    print("-" * 110)
    
    try:
        # Use count=0 for infinite capture
        count = args.count if args.count > 0 else 0
        
        sniff(
            filter=args.filter, 
            prn=print_packet, 
            count=count, 
            iface=args.iface,
            store=False  # Don't store packets in memory to save RAM
        )
        
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except PermissionError:
        print("Error: You need to run this script as administrator/root.")
        print("On Windows: Run Command Prompt/PowerShell as Administrator")
        print("On Linux/Mac: Use 'sudo python packet_sniffer.py ...'")
    except Exception as e:
        logger.error(f"An error occurred during packet capture: {e}")
        print(f"Error: {e}")
    
    finally:
        print("\nFlushing remaining packets to database...")
        db.close()
        print("Done.")

if __name__ == "__main__":
    main()