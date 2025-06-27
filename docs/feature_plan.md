# PyGuard Pro Feature Plan

## Milestones
- **Week 1:** Basic packet sniffer (done)
- **Week 2:** Git workflow, docs, README, team plan (this week)
- **Week 3:** DB schema, store packets
- **Week 4:** CLI/Notebook data viz

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

## Branching Strategy
- `main`: Stable, production-ready code
- `dev`: Integration branch for new features
- `feature/<feature-name>`: Feature-specific branches

## Documentation
- All plans, outputs, and diagrams go in the `docs/` folder.
- Update documentation as features are added or changed.
