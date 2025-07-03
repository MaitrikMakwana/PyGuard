# PyGuard Pro Feature Plan

## Milestones
- **Week 1:** Basic packet sniffer (done)
- **Week 2:** Git workflow, docs, README, team plan (this week)
- **Week 3:** DB schema, store packets
- **Week 4:** CLI/Notebook data viz
- **Week 5:** **ML-based intrusion detection:**
    - Feature engineering for network traffic
    - Collect and label data
    - Train and evaluate ML models (Random Forest, SVM, Isolation Forest, etc.)
    - Integrate model into packet processing pipeline
- **Week 6:** Model tuning, continuous learning, and documentation

## Sample Packet Output
```
Source IP: 192.168.1.2 -> Destination IP: 8.8.8.8 | Protocol: ICMP | Size: 98 | Details: {"icmp_type": 8, "icmp_code": 0, ...}
Source IP: 10.0.0.5 -> Destination IP: 192.168.1.1 | Protocol: TCP | Src Port: 443 -> Dst Port: 52344 | Size: 74 | Details: {"tcp_flags": "S", "tcp_seq": 123456, ...}
```

## Tool List
- Python (Scapy, pyshark, SQLAlchemy, Flask, Flask-RESTX, Flask-SocketIO, **scikit-learn, pandas, numpy**)
- React
- Docker
- GitHub Actions

## ML Intrusion Detection Plan
- **Feature Engineering:** Extract features from packets/flows (e.g., protocol, size, flags, timing).
- **Data Collection:** Use real or public datasets (e.g., KDD Cup, UNSW-NB15) or capture your own.
- **Model Training:** Train supervised or anomaly detection models.
- **Integration:** Load model in packet_sniffer.py and classify packets in real time.
- **Continuous Learning:** Periodically retrain with new data.

## Branching Strategy
- `main`: Stable, production-ready code
- `dev`: Integration branch for new features
- `feature/<feature-name>`: Feature-specific branches

## Documentation
- All plans, outputs, and diagrams go in the `docs/` folder.
- Update documentation as features are added or changed.
