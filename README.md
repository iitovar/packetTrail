# PacketTrail (Foundation Milestone)

This project is the capstone foundation check-in for PacketTrail, a lightweight network intrusion detection and forensics logger.

## Current Capabilities
- Capture TCP/UDP packets using Scapy
- Log packet metadata to SQLite (timestamp, IPs, ports, protocol, length)
- Detect simple anomalies: suspected port scans and high burst traffic
- Record alerts to a database and display them in the console
- Export data to CSV for sharing or analysis

## How to Run
See `README_PacketTrail_Checkin.txt` for detailed instructions and example commands.

## Files
- `packettrail.py` — main sniffer and logger
- `requirements.txt` — dependencies
- `schema.sql` — database schema
- `export_csv.py` — export SQLite tables to CSV
- `make_demo_rows.py` — populate the DB with demo rows
- `README_PacketTrail_Checkin.txt` — quick run guide for this milestone

## Next Steps
- Expand detection rules (e.g., beaconing, unusual packet sizes)
- Build a Flask-based dashboard to visualize events
- Create incident timelines for forensic analysis

