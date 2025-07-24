from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw
import sqlite3
import time
import json

# Connect to SQLite database (or create it)
conn = sqlite3.connect('packets.db')
cursor = conn.cursor()

# Create improved table schema with indexes (consistent with packet_sniffer.py)
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

def store_packet(packet):
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
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    size = len(packet)
    
    # Convert ports to integers, handle None values
    src_port_int = int(src_port) if src_port and src_port.isdigit() else None
    dst_port_int = int(dst_port) if dst_port and dst_port.isdigit() else None
    
    cursor.execute(
        "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, src, dst, proto_name, src_port_int, dst_port_int, size, json.dumps(details))
    )
    conn.commit()

if __name__ == "__main__":
    print("Sniffing packets and storing them in packets.db...")
    try:
        sniff(filter="ip", prn=store_packet, count=20)  # Change count as needed
    except PermissionError:
        print("Error: You need to run this script as administrator/root.")
    except Exception as e:
        print(f"An error occurred: {e}")
    print("Done.")
    conn.close()
