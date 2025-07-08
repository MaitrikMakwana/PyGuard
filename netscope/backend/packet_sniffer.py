# packet_sniffer.py
# PyGuard Pro - Week 1 Milestone: Basic Packet Sniffer
# Requirements: pip install scapy
# Usage: python packet_sniffer.py -c 10
#
# Sample Output:
# Source IP: 192.168.1.2 -> Destination IP: 8.8.8.8 | Protocol: ICMP
# Source IP: 10.0.0.5 -> Destination IP: 192.168.1.1 | Protocol: TCP | Src Port: 443 -> Dst Port: 52344
# ...

from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw
import argparse
import sqlite3
import time
import json

# Set up SQLite database
conn = sqlite3.connect('packets.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        src_port TEXT,
        dst_port TEXT,
        size INTEGER,
        details TEXT
    )
''')
conn.commit()

# Print packet summary: source/destination IP, protocol, and ports if available
# Also store packet info in the database
def print_packet(packet):
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
    # Store in database
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    cursor.execute(
        "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, src, dst, proto_name, src_port, dst_port, size, json.dumps(details))
    )
    conn.commit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of packets to capture")
    parser.add_argument("-i", "--iface", type=str, help="Network interface to sniff on (optional)")
    args = parser.parse_args()

    print(f"Sniffing {args.count} packets{' on ' + args.iface if args.iface else ''}...")
    # Print table header
    print(f"{'Source IP':<16} {'Destination IP':<16} {'Protocol':<8} {'Src Port':<10} {'Dst Port':<10} {'Size':<8} {'Details':<40}")
    print("-" * 110)
    try:
        sniff(filter="ip", prn=print_packet, count=args.count, iface=args.iface)
    except PermissionError:
        print("Error: You need to run this script as administrator/root.")
    except Exception as e:
        print(f"An error occurred: {e}")
    print("Done.")
    conn.close()