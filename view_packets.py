import sqlite3
import json

# Connect to the database
conn = sqlite3.connect('packets.db')
cursor = conn.cursor()

print("Packet Filter Options (leave blank to ignore a filter):")
source_ip = input("Source IP: ").strip()
dest_ip = input("Destination IP: ").strip()
port = input("Port (source or destination): ").strip()
protocol = input("Protocol (TCP/UDP/ICMP): ").strip().upper()

# Build query dynamically
query = "SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details FROM packets WHERE 1=1"
params = []
if source_ip:
    query += " AND src_ip = ?"
    params.append(source_ip)
if dest_ip:
    query += " AND dst_ip = ?"
    params.append(dest_ip)
if port:
    query += " AND (src_port = ? OR dst_port = ?)"
    params.extend([port, port])
if protocol:
    query += " AND protocol = ?"
    params.append(protocol)

cursor.execute(query, params)
rows = cursor.fetchall()

# Print results as a table
print(f"{'Timestamp':<20} {'Source IP':<16} {'Destination IP':<16} {'Proto':<6} {'Src Port':<8} {'Dst Port':<8} {'Size':<8} {'Details':<40}")
print("-" * 128)
for row in rows:
    print(f"{row[0]:<20} {row[1]:<16} {row[2]:<16} {row[3]:<6} {row[4]:<8} {row[5]:<8} {row[6]:<8} {row[7][:40]:<40}")

# Optionally, allow user to inspect full details for a specific packet
if rows:
    try:
        idx = int(input("\nEnter row number to see full details (or blank to skip): "))
        if 0 <= idx < len(rows):
            print(json.dumps(json.loads(rows[idx][7]), indent=2))
    except Exception:
        pass
print(f"\nTotal packets found: {len(rows)}")
conn.close()