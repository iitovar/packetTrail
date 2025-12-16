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

Clone the repository and set up a virtual environment.

Visit runInstructions.txt for a step-by-step.

