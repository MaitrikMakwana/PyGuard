#!/usr/bin/env python3
"""
Advanced Packet Viewer with Wireshark-style Display Filters
Enhanced filtering capabilities for viewing captured packets
"""

import sqlite3
import json
import re
import argparse
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Any, Callable, Optional, Tuple
import sys
import os

class DisplayFilter:
    """Advanced display filter parser and evaluator similar to Wireshark"""
    
    def __init__(self):
        self.operators = {
            '==': lambda a, b: self._safe_compare(a, b, lambda x, y: x == y),
            '!=': lambda a, b: self._safe_compare(a, b, lambda x, y: x != y),
            '>': lambda a, b: self._safe_compare(a, b, lambda x, y: x > y),
            '<': lambda a, b: self._safe_compare(a, b, lambda x, y: x < y),
            '>=': lambda a, b: self._safe_compare(a, b, lambda x, y: x >= y),
            '<=': lambda a, b: self._safe_compare(a, b, lambda x, y: x <= y),
            'contains': lambda a, b: str(b).lower() in str(a).lower() if a and b else False,
            'matches': lambda a, b: bool(re.search(str(b), str(a), re.IGNORECASE)) if a and b else False,
        }
        
    def _safe_compare(self, a, b, op):
        """Safely compare values with type conversion"""
        try:
            # Handle special port field case
            if isinstance(a, dict) and '_port_field' in a:
                # For port fields, check if any of the port values match
                port_values = a['_port_field']
                for port_val in port_values:
                    if port_val is not None and port_val != "-":
                        try:
                            if op(port_val, b) or op(int(port_val) if str(port_val).isdigit() else port_val, b):
                                return True
                        except (ValueError, TypeError):
                            if op(str(port_val), str(b)):
                                return True
                return False
            
            # Try numeric comparison first
            if isinstance(a, str) and isinstance(b, str):
                # Check if both are numeric
                try:
                    return op(float(a), float(b))
                except ValueError:
                    pass
            # Try direct comparison
            return op(a, b)
        except (TypeError, ValueError):
            # Fall back to string comparison
            return op(str(a), str(b))
            
    def _get_field_value(self, packet: Dict[str, Any], field_path: str) -> Any:
        """Extract field value from packet using dot notation"""
        try:
            # Handle special field mappings (Wireshark-style)
            field_mappings = {
                'ip.src': 'src_ip',
                'ip.dst': 'dst_ip',
                'tcp.port': ['src_port', 'dst_port'],
                'udp.port': ['src_port', 'dst_port'],
                'tcp.srcport': 'src_port',
                'tcp.dstport': 'dst_port',
                'udp.srcport': 'src_port',
                'udp.dstport': 'dst_port',
                'frame.len': 'size',
                'frame.time': 'timestamp',
                'ip.proto': 'protocol',
                'tcp.flags': 'tcp_flags',
                'tcp.seq': 'tcp_seq',
                'tcp.ack': 'tcp_ack',
                'tcp.window': 'tcp_window',
                'icmp.type': 'icmp_type',
                'icmp.code': 'icmp_code',
                'dns.qry.name': 'dns_qd',
                'eth.src': 'eth_src',
                'eth.dst': 'eth_dst',
            }
            
            # Check for field mapping
            if field_path in field_mappings:
                mapped_field = field_mappings[field_path]
                if isinstance(mapped_field, list):
                    # For port fields, we need special handling in the operator
                    # Return a special marker that indicates this is a port field
                    return {'_port_field': [packet.get(field) for field in mapped_field]}
                else:
                    return packet.get(mapped_field)
            
            # Handle nested field access with dots
            parts = field_path.split('.')
            value = packet
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return None
                if value is None:
                    break
            return value
            
        except Exception:
            return None
    
    def _parse_value(self, value_str: str) -> Any:
        """Parse string value to appropriate type"""
        value_str = value_str.strip()
        
        # Remove quotes if present
        if (value_str.startswith('"') and value_str.endswith('"')) or \
           (value_str.startswith("'") and value_str.endswith("'")):
            return value_str[1:-1]
        
        # Try to parse as number
        try:
            if '.' in value_str:
                return float(value_str)
            else:
                return int(value_str)
        except ValueError:
            pass
        
        # Check for boolean values
        if value_str.lower() in ('true', 'yes', 'on'):
            return True
        elif value_str.lower() in ('false', 'no', 'off'):
            return False
            
        # Return as string
        return value_str
    
    def _parse_expression(self, expr: str) -> Callable[[Dict[str, Any]], bool]:
        """Parse a single filter expression"""
        expr = expr.strip()
        
        # Find operator
        op_pattern = r'(==|!=|>=|<=|>|<|contains|matches)'
        match = re.search(op_pattern, expr)
        
        if not match:
            # Simple field existence check
            return lambda packet: self._get_field_value(packet, expr) is not None
        
        operator = match.group(1)
        field_path = expr[:match.start()].strip()
        value_str = expr[match.end():].strip()
        
        parsed_value = self._parse_value(value_str)
        op_func = self.operators[operator]
        
        def evaluator(packet):
            field_value = self._get_field_value(packet, field_path)
            return op_func(field_value, parsed_value)
        
        return evaluator
    
    def parse_filter(self, filter_str: str) -> Callable[[Dict[str, Any]], bool]:
        """Parse complete filter string with AND/OR logic"""
        if not filter_str.strip():
            return lambda packet: True
        
        # Split by OR first (lower precedence)
        or_clauses = self._split_by_operator(filter_str, 'or')
        or_evaluators = []
        
        for or_clause in or_clauses:
            # Split by AND (higher precedence)
            and_clauses = self._split_by_operator(or_clause, 'and')
            and_evaluators = [self._parse_expression(clause) for clause in and_clauses]
            
            # Create AND evaluator
            def and_eval(packet, evaluators=and_evaluators):
                return all(evaluator(packet) for evaluator in evaluators)
            
            or_evaluators.append(and_eval)
        
        # Create final OR evaluator
        def final_evaluator(packet):
            return any(evaluator(packet) for evaluator in or_evaluators)
        
        return final_evaluator
    
    def _split_by_operator(self, text: str, operator: str) -> List[str]:
        """Split text by operator while respecting parentheses and quotes"""
        parts = []
        current = ""
        paren_count = 0
        in_quotes = False
        quote_char = None
        i = 0
        
        op_pattern = f"\\b{operator}\\b"
        
        while i < len(text):
            char = text[i]
            
            # Handle quotes
            if char in ('"', "'") and (i == 0 or text[i-1] != '\\'):
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
            
            # Handle parentheses (only when not in quotes)
            elif not in_quotes:
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                # Check for operator when not in parentheses
                elif paren_count == 0:
                    remaining = text[i:]
                    if re.match(op_pattern, remaining, re.IGNORECASE):
                        # Found operator at current level
                        if current.strip():
                            parts.append(current.strip())
                        current = ""
                        i += len(operator)
                        continue
            
            current += char
            i += 1
        
        if current.strip():
            parts.append(current.strip())
        
        return parts if parts else [text]

class AdvancedPacketViewer:
    """Advanced packet viewer with filtering, sorting, and analysis"""
    
    def __init__(self, db_path: str = 'packets.db'):
        self.db_path = db_path
        self.display_filter = DisplayFilter()
        self.conn = None
        
    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()
    
    def get_packets(self, limit: Optional[int] = None, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve packets from database"""
        cursor = self.conn.cursor()
        
        query = """
        SELECT id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details 
        FROM packets 
        ORDER BY id DESC
        """
        
        if limit:
            query += f" LIMIT {limit} OFFSET {offset}"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        packets = []
        for row in rows:
            packet = {
                'id': row[0],
                'timestamp': row[1],
                'src_ip': row[2],
                'dst_ip': row[3],
                'protocol': row[4],
                'src_port': row[5],
                'dst_port': row[6],
                'size': row[7],
                'details': row[8]
            }
            
            # Parse JSON details
            if row[8]:
                try:
                    details = json.loads(row[8])
                    packet.update(details)
                except json.JSONDecodeError:
                    pass
            
            packets.append(packet)
        
        return packets
    
    def filter_packets(self, packets: List[Dict[str, Any]], filter_str: str) -> List[Dict[str, Any]]:
        """Apply display filter to packets"""
        if not filter_str.strip():
            return packets
        
        try:
            filter_func = self.display_filter.parse_filter(filter_str)
            return [packet for packet in packets if filter_func(packet)]
        except Exception as e:
            print(f"Error applying filter: {e}")
            return packets
    
    def sort_packets(self, packets: List[Dict[str, Any]], sort_field: str, reverse: bool = False) -> List[Dict[str, Any]]:
        """Sort packets by specified field"""
        def sort_key(packet):
            value = packet.get(sort_field, '')
            # Try to convert to number for better sorting
            try:
                if isinstance(value, str) and value.replace('.', '', 1).isdigit():
                    return float(value)
            except:
                pass
            return str(value) if value is not None else ''
        
        return sorted(packets, key=sort_key, reverse=reverse)
    
    def print_packets(self, packets: List[Dict[str, Any]], detailed: bool = False, max_width: int = 150):
        """Print packets in a formatted table"""
        if not packets:
            print("No packets found.")
            return
        
        if detailed:
            self._print_detailed_packets(packets)
        else:
            self._print_summary_table(packets, max_width)
    
    def _print_summary_table(self, packets: List[Dict[str, Any]], max_width: int):
        """Print packets in summary table format"""
        headers = ['#', 'Timestamp', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
        col_widths = [5, 19, 16, 16, 8, 8, max_width - 72]
        
        # Print header
        header_line = ""
        for i, (header, width) in enumerate(zip(headers, col_widths)):
            header_line += f"{header:<{width}}"
            if i < len(headers) - 1:
                header_line += " "
        print(header_line)
        print("-" * len(header_line))
        
        # Print packets
        for i, packet in enumerate(packets):
            info = self._get_packet_info(packet)
            
            row = f"{i+1:<{col_widths[0]}} "
            row += f"{packet.get('timestamp', ''):<{col_widths[1]}} "
            row += f"{packet.get('src_ip', ''):<{col_widths[2]}} "
            row += f"{packet.get('dst_ip', ''):<{col_widths[3]}} "
            row += f"{packet.get('protocol', ''):<{col_widths[4]}} "
            row += f"{packet.get('size', ''):<{col_widths[5]}} "
            row += f"{info:<{col_widths[6]}}"
            
            print(row)
    
    def _print_detailed_packets(self, packets: List[Dict[str, Any]]):
        """Print packets with detailed information"""
        for i, packet in enumerate(packets):
            print(f"\n=== Packet {i+1} ===")
            print(f"ID: {packet.get('id', 'N/A')}")
            print(f"Timestamp: {packet.get('timestamp', 'N/A')}")
            print(f"Source IP: {packet.get('src_ip', 'N/A')}")
            print(f"Destination IP: {packet.get('dst_ip', 'N/A')}")
            print(f"Protocol: {packet.get('protocol', 'N/A')}")
            print(f"Source Port: {packet.get('src_port', 'N/A')}")
            print(f"Destination Port: {packet.get('dst_port', 'N/A')}")
            print(f"Size: {packet.get('size', 'N/A')} bytes")
            
            # Print protocol-specific details
            protocol = packet.get('protocol', '').upper()
            if protocol == 'TCP':
                self._print_tcp_details(packet)
            elif protocol == 'UDP':
                self._print_udp_details(packet)
            elif protocol == 'ICMP':
                self._print_icmp_details(packet)
            elif protocol == 'DNS':
                self._print_dns_details(packet)
            elif protocol == 'ARP':
                self._print_arp_details(packet)
    
    def _get_packet_info(self, packet: Dict[str, Any]) -> str:
        """Generate info string for packet"""
        protocol = packet.get('protocol', '').upper()
        
        if protocol == 'TCP':
            flags = packet.get('tcp_flags', '')
            src_port = packet.get('src_port', '')
            dst_port = packet.get('dst_port', '')
            if 'http_data' in packet:
                return f"HTTP {src_port} → {dst_port} [{flags}]"
            return f"{src_port} → {dst_port} [{flags}] Seq={packet.get('tcp_seq', 0)} Ack={packet.get('tcp_ack', 0)}"
            
        elif protocol == 'UDP':
            src_port = packet.get('src_port', '')
            dst_port = packet.get('dst_port', '')
            return f"{src_port} → {dst_port} Len={packet.get('size', 0)}"
            
        elif protocol == 'ICMP':
            icmp_type = packet.get('icmp_type', '')
            icmp_code = packet.get('icmp_code', '')
            return f"Type={icmp_type} Code={icmp_code}"
            
        elif protocol == 'DNS':
            query = packet.get('dns_qd', '')
            return f"Query {query}" if query else "DNS"
            
        elif protocol == 'ARP':
            op = packet.get('arp_op', '')
            op_name = {1: 'Request', 2: 'Reply'}.get(op, f'Op={op}')
            return f"{op_name} {packet.get('arp_psrc', '')} → {packet.get('arp_pdst', '')}"
        
        return ""
    
    def _print_tcp_details(self, packet: Dict[str, Any]):
        """Print TCP-specific details"""
        print("TCP Details:")
        for field in ['tcp_seq', 'tcp_ack', 'tcp_window', 'tcp_flags', 'tcp_chksum']:
            value = packet.get(field)
            if value is not None:
                print(f"  {field.replace('tcp_', '').title()}: {value}")
        
        if 'http_data' in packet:
            print("HTTP Data (first 200 chars):")
            print(f"  {packet['http_data']}")
    
    def _print_udp_details(self, packet: Dict[str, Any]):
        """Print UDP-specific details"""
        print("UDP Details:")
        for field in ['udp_len', 'udp_chksum']:
            value = packet.get(field)
            if value is not None:
                print(f"  {field.replace('udp_', '').title()}: {value}")
    
    def _print_icmp_details(self, packet: Dict[str, Any]):
        """Print ICMP-specific details"""
        print("ICMP Details:")
        for field in ['icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq']:
            value = packet.get(field)
            if value is not None:
                print(f"  {field.replace('icmp_', '').title()}: {value}")
    
    def _print_dns_details(self, packet: Dict[str, Any]):
        """Print DNS-specific details"""
        print("DNS Details:")
        dns_fields = {
            'dns_id': 'Transaction ID',
            'dns_qr': 'Query/Response',
            'dns_opcode': 'Opcode',
            'dns_aa': 'Authoritative Answer',
            'dns_tc': 'Truncated',
            'dns_rd': 'Recursion Desired',
            'dns_ra': 'Recursion Available',
            'dns_rcode': 'Response Code',
            'dns_qd': 'Query',
            'dns_an': 'Answer'
        }
        
        for field, description in dns_fields.items():
            value = packet.get(field)
            if value is not None and value != "":
                print(f"  {description}: {value}")
    
    def _print_arp_details(self, packet: Dict[str, Any]):
        """Print ARP-specific details"""
        print("ARP Details:")
        arp_fields = {
            'arp_hwtype': 'Hardware Type',
            'arp_ptype': 'Protocol Type',
            'arp_op': 'Operation',
            'arp_hwsrc': 'Sender MAC',
            'arp_psrc': 'Sender IP',
            'arp_hwdst': 'Target MAC',
            'arp_pdst': 'Target IP'
        }
        
        for field, description in arp_fields.items():
            value = packet.get(field)
            if value is not None:
                print(f"  {description}: {value}")

def get_display_filter_help():
    """Get help for display filter syntax"""
    return """
=== Display Filter Syntax Help (Wireshark-style) ===

BASIC SYNTAX:
  field operator value
  Expressions can be combined with 'and', 'or' operators

COMPARISON OPERATORS:
  ==                     - Equal
  !=                     - Not equal
  >                      - Greater than
  <                      - Less than
  >=                     - Greater than or equal
  <=                     - Less than or equal
  contains               - Contains substring
  matches                - Matches regular expression

FIELD NAMES (Wireshark-style):
  ip.src                 - Source IP address
  ip.dst                 - Destination IP address
  tcp.port               - TCP port (source or destination)
  udp.port               - UDP port (source or destination)
  tcp.srcport            - TCP source port
  tcp.dstport            - TCP destination port
  udp.srcport            - UDP source port
  udp.dstport            - UDP destination port
  frame.len              - Packet length
  frame.time             - Timestamp
  tcp.flags              - TCP flags
  tcp.seq                - TCP sequence number
  tcp.ack                - TCP acknowledgment number
  icmp.type              - ICMP type
  icmp.code              - ICMP code
  dns.qry.name           - DNS query name
  eth.src                - Ethernet source MAC
  eth.dst                - Ethernet destination MAC
  protocol               - Protocol name

EXAMPLES:
  ip.src == 192.168.1.1                    - Packets from specific IP
  tcp.port == 80                           - HTTP traffic (any direction)
  protocol == TCP and tcp.dstport == 443   - HTTPS traffic to port 443
  frame.len > 1000                         - Large packets
  ip.src == 10.0.0.1 or ip.dst == 10.0.0.1 - Traffic involving specific IP
  dns.qry.name contains google             - DNS queries containing 'google'
  tcp.flags matches ".*A.*"                - TCP packets with ACK flag
  icmp.type == 8                           - ICMP ping requests
  frame.len >= 64 and frame.len <= 1518   - Standard Ethernet frame sizes

LOGICAL COMBINATIONS:
  Expression1 and Expression2              - Both must be true
  Expression1 or Expression2               - Either can be true
  (Expression1 or Expression2) and Expression3 - Use parentheses for grouping
"""

def main():
    """Main function for advanced packet viewer"""
    parser = argparse.ArgumentParser(
        description="Advanced Packet Viewer with Wireshark-style Display Filters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_packet_viewer.py                                    # View all packets
  python advanced_packet_viewer.py -f "ip.src == 192.168.1.1"       # Filter by source IP
  python advanced_packet_viewer.py -f "tcp.port == 80" -s frame.len  # HTTP traffic sorted by size
  python advanced_packet_viewer.py -f "protocol == DNS" -d           # DNS packets with details
  python advanced_packet_viewer.py --filter-help                     # Show filter syntax help
        """
    )
    
    parser.add_argument("--db-path", type=str, default="packets.db",
                       help="Path to SQLite database file (default: packets.db)")
    parser.add_argument("-f", "--filter", type=str, default="",
                       help="Display filter expression (Wireshark-style)")
    parser.add_argument("-s", "--sort", type=str, default="timestamp",
                       help="Sort by field (default: timestamp)")
    parser.add_argument("-r", "--reverse", action="store_true",
                       help="Reverse sort order")
    parser.add_argument("-l", "--limit", type=int,
                       help="Limit number of packets to display")
    parser.add_argument("-d", "--detailed", action="store_true",
                       help="Show detailed packet information")
    parser.add_argument("--filter-help", action="store_true",
                       help="Show display filter syntax help and exit")
    parser.add_argument("-w", "--width", type=int, default=150,
                       help="Maximum display width (default: 150)")
    
    args = parser.parse_args()
    
    # Show filter help if requested
    if args.filter_help:
        print(get_display_filter_help())
        return
    
    # Check if database exists
    if not os.path.exists(args.db_path):
        print(f"Error: Database file '{args.db_path}' not found.")
        print("Run the packet sniffer first to capture some packets.")
        return
    
    try:
        with AdvancedPacketViewer(args.db_path) as viewer:
            print(f"Loading packets from {args.db_path}...")
            
            # Get packets from database
            packets = viewer.get_packets(limit=args.limit)
            print(f"Loaded {len(packets)} packets from database.")
            
            # Apply filter if specified
            if args.filter:
                print(f"Applying filter: {args.filter}")
                filtered_packets = viewer.filter_packets(packets, args.filter)
                print(f"Filter matched {len(filtered_packets)} packets.")
                packets = filtered_packets
            
            # Sort packets
            if packets:
                packets = viewer.sort_packets(packets, args.sort, args.reverse)
                
                # Display packets
                print(f"\nDisplaying packets (sorted by {args.sort}):")
                print("=" * args.width)
                viewer.print_packets(packets, detailed=args.detailed, max_width=args.width)
                print("=" * args.width)
                print(f"Total: {len(packets)} packets")
            else:
                print("No packets to display.")
    
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()