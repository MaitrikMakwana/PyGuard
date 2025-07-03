import sqlite3
import json
import re

# Connect to the database
conn = sqlite3.connect('packets.db')
cursor = conn.cursor()

print("Enter advanced filter (e.g. ip.src==192.168.1.1 || ip.dst==8.8.8.8 || tcp.port==80 || protocol==TCP):")
filter_str = input("Filter: ").strip()

# Prompt for sorting
sort_fields = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'size']
print(f"Sort by field {tuple(sort_fields)}:")
sort_field = input("Sort field: ").strip()
if sort_field not in sort_fields:
    sort_field = 'timestamp'
order = input("Order (asc/desc): ").strip().lower()
reverse = (order == 'desc')

# Fetch all packets
cursor.execute("SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details FROM packets")
rows = cursor.fetchall()

# Parse filter string
def parse_filter(filter_str):
    # Supports: ip.src==, ip.dst==, tcp.port==, udp.port==, protocol==
    if not filter_str:
        return lambda pkt: True
    or_clauses = [c.strip() for c in filter_str.split('||')]
    conditions = []
    for clause in or_clauses:
        m_ip_src = re.match(r'ip\.src==([\d\.]+)', clause)
        m_ip_dst = re.match(r'ip\.dst==([\d\.]+)', clause)
        m_tcp_port = re.match(r'tcp\.port==([\d]+)', clause)
        m_udp_port = re.match(r'udp\.port==([\d]+)', clause)
        m_proto = re.match(r'protocol==([A-Za-z0-9]+)', clause)
        if m_ip_src:
            value = m_ip_src.group(1)
            conditions.append(lambda pkt, value=value: pkt.get('src_ip') == value)
        elif m_ip_dst:
            value = m_ip_dst.group(1)
            conditions.append(lambda pkt, value=value: pkt.get('dst_ip') == value)
        elif m_tcp_port:
            value = m_tcp_port.group(1)
            conditions.append(lambda pkt, value=value: pkt.get('src_port') == value or pkt.get('dst_port') == value)
        elif m_udp_port:
            value = m_udp_port.group(1)
            conditions.append(lambda pkt, value=value: pkt.get('src_port') == value or pkt.get('dst_port') == value)
        elif m_proto:
            value = m_proto.group(1).upper()
            conditions.append(lambda pkt, value=value: pkt.get('protocol', '').upper() == value)
    def filter_func(pkt):
        return any(cond(pkt) for cond in conditions) if conditions else True
    return filter_func

filter_func = parse_filter(filter_str)

# Filter and build packet dicts
filtered_packets = []
for idx, row in enumerate(rows):
    pkt = {
        'timestamp': row[0],
        'src_ip': row[1],
        'dst_ip': row[2],
        'protocol': row[3],
        'src_port': row[4],
        'dst_port': row[5],
        'size': row[6],
        'details': row[7]
    }
    # Merge details JSON if present
    if row[7]:
        try:
            pkt.update(json.loads(row[7]))
        except Exception:
            pass
    if filter_func(pkt):
        filtered_packets.append(pkt)

# Sort packets
try:
    filtered_packets.sort(key=lambda pkt: pkt.get(sort_field, ''), reverse=reverse)
except Exception:
    pass

# Print results as a table
print(f"{'#':<3} {'Timestamp':<20} {'Source IP':<16} {'Destination IP':<16} {'Proto':<6} {'Src Port':<8} {'Dst Port':<8} {'Size':<8} {'Details':<40}")
print("-" * 132)
for idx, pkt in enumerate(filtered_packets):
    print(f"{idx:<3} {pkt['timestamp']:<20} {pkt['src_ip']:<16} {pkt['dst_ip']:<16} {pkt['protocol']:<6} {pkt['src_port']:<8} {pkt['dst_port']:<8} {pkt['size']:<8} {str(pkt['details'])[:40]:<40}")

# Optionally, allow user to inspect full details for a specific packet
if filtered_packets:
    try:
        idx = input("\nEnter row number to see full details (or blank to skip): ").strip()
        if idx:
            idx = int(idx)
            if 0 <= idx < len(filtered_packets):
                print(json.dumps(json.loads(filtered_packets[idx]['details']), indent=2))
    except Exception:
        pass
print(f"\nTotal packets found: {len(filtered_packets)}")

conn.close()