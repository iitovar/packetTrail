PacketTrail — Foundation Milestone (Check-In)

What this does
- Captures TCP/UDP packets using Scapy
- Logs packet metadata (timestamp, IPs, ports, protocol, length) to SQLite
- Detects simple anomalies: suspected port scans and burst packet rates
- Writes alerts to an `alerts` table and prints them in the console

Quick start
1) Install deps:
   pip install -r requirements.txt

2) Option A — Quick demo without live sniffing:
   python3 make_demo_rows.py --db packettrail.db
   sqlite3 packettrail.db "SELECT * FROM packets LIMIT 5;"
   sqlite3 packettrail.db "SELECT * FROM alerts LIMIT 5;"
   python3 export_csv.py --db packettrail.db --out export

3) Option B — Live capture (admin/sudo usually required):
   sudo python3 packettrail.py --iface <iface>                 # e.g., eth0, en0, wlan0
   sqlite3 packettrail.db "SELECT * FROM alerts ORDER BY epoch DESC LIMIT 10;"
   python3 export_csv.py --db packettrail.db --out export

Key files
- packettrail.py        : sniffer + SQLite logger + basic alerts
- schema.sql            : DB schema (packets, alerts + indexes)
- export_csv.py         : exports tables to CSV for attachments/poster
- make_demo_rows.py     : inserts demo rows if you can’t sniff
- requirements.txt      : dependencies

Typical commands for screenshots
- Console alert view:
  sqlite3 packettrail.db "SELECT ts_iso, src_ip, alert_type, details FROM alerts ORDER BY epoch DESC LIMIT 10;"
- Packet count range:
  sqlite3 packettrail.db "SELECT COUNT(*), MIN(ts_iso), MAX(ts_iso) FROM packets;"

Tuning (optional)
- Window seconds:        --window 10
- Port-scan threshold:   --port-threshold 20
- Burst-rate threshold:  --rate-threshold 200
- BPF capture filter:    --bpf "tcp or udp"   (e.g., "tcp and port 80")

Notes
- Live sniffing typically needs admin privileges.
- If you see no packets, try a more active interface or generate traffic (visit a website, ping, etc.).
- On macOS, you may need to allow terminal capture permissions (System Settings → Privacy & Security → Full Disk Access/Network).

Next steps (after this milestone)
- Add beaconing detection
- Start minimal Flask view to query recent alerts

