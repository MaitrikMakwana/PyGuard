# PyGuard Pro Documentation

## Project Scope
PyGuard Pro is a real-time, rule-based Intrusion Detection System (IDS) and advanced network packet analyzer. It captures packets, extracts all protocol details (Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP, etc.), stores them as JSON in a database, and provides both summary and detailed inspection features, similar to Wireshark.

## Team Member Roles
- **A**: Packet Capture & DB Integration (Backend)
- **B**: Detection Engine & Data Analysis
- **C**: Web Dashboard & UI/UX (Frontend & DevOps)

## Feature Plan
- Real-time packet capture
- Deep protocol inspection (Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP, etc.)
- Store all protocol fields as JSON in the database
- Packet summary and detailed inspection (Wireshark-like)
- Rule/statistics-based intrusion detection
- Database logging
- Live web dashboard

## Sample Packet Output
```
Source IP: 192.168.1.2 -> Destination IP: 8.8.8.8 | Protocol: ICMP | Size: 98 | Details: {"icmp_type": 8, "icmp_code": 0, ...}
Source IP: 10.0.0.5 -> Destination IP: 192.168.1.1 | Protocol: TCP | Src Port: 443 -> Dst Port: 52344 | Size: 74 | Details: {"tcp_flags": "S", "tcp_seq": 123456, ...}
```

## Tool List
- Python (Scapy, pyshark, SQLAlchemy, Flask, Flask-RESTX, Flask-SocketIO)
- React
- Docker
- GitHub Actions

## Milestones
- Week 1: Basic packet sniffer
- Week 2: Git workflow, docs, README, team plan
- Week 3: DB schema, store packets
- Week 4: CLI/Notebook data viz
