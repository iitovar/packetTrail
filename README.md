# PacketTrail

PacketTrail is a lightweight network intrusion detection and forensics tool developed as my cybersecurity capstone project. It combines live packet capture, anomaly detection, structured logging, and a web dashboard to make network activity and alerts easy to analyze for investigators.

## Features

- **Packet Capture:** Uses Scapy to capture TCP/UDP packets on a chosen interface.  
- **Database Logging:** Stores metadata (timestamp, source/destination IPs, ports, protocol, packet length) in SQLite.  
- **Anomaly Detection:**  
  - **Port Scans** – detects excessive unique ports probed by a host.  
  - **Burst Traffic** – flags unusually high packet volumes in a short time window.  
  - **Beaconing** – identifies highly regular traffic intervals that may indicate malware callbacks.  
- **Flask Dashboard:** Web interface with tables of recent alerts and captured packets.  
- **CSV Export:** Utility to export packets and alerts to CSV for offline analysis.  

## Installation

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/iitovar/packetTrail.git
cd packetTrail
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

# Usage

Start PacketTrail Sniffer
Run with thresholds low enough to trigger alerts in a demo:

sudo python3 packettrail.py --iface en0 --window 10 --port-threshold 5 --rate-threshold 30 --beacon-count 5 --beacon-jitter 0.35

# Run the Dashboard

Start the Flask app to view alerts and packets:

python3 app.py --db packettrail.db

Then open http://127.0.0.1:5000 in your browser.
/alerts shows logged anomalies
/packets shows captured packet metadata

# Exporting CSVs

python3 export_csv.py --db packettrail.db --out export

This will produce export/packets.csv and export/alerts.csv

# Roadmap

Add filtering and search features to the dashboard
Implement charts/visualizations of packet volume and alert frequency
Expand anomaly detection with more rule types

# License

This project is licensed under the MIT License. See LICENSE for details.

