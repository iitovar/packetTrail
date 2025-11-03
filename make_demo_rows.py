#!/usr/bin/env python3
"""
make_demo_rows.py
Populate packettrail.db with a few demo rows for screenshots if you can't sniff live.

Usage:
  python3 make_demo_rows.py --db packettrail.db

After running:
  sqlite3 packettrail.db "SELECT * FROM packets;"
  sqlite3 packettrail.db "SELECT * FROM alerts;"
"""

import argparse
import sqlite3
import time

def ensure_schema(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_iso TEXT NOT NULL,
        epoch REAL NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        proto TEXT,
        sport INTEGER,
        dport INTEGER,
        length INTEGER
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_iso TEXT NOT NULL,
        epoch REAL NOT NULL,
        src_ip TEXT,
        alert_type TEXT NOT NULL,
        details TEXT
    );
    """)
    conn.commit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="packettrail.db", help="Path to SQLite database file")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    ensure_schema(conn)

    now = time.time()
    packets = [
        ("2025-09-18T19:20:00Z", now-60, "192.168.1.50", "142.250.72.14", "TCP", 54500, 80, 900),
        ("2025-09-18T19:20:02Z", now-58, "192.168.1.77", "142.250.72.14", "TCP", 54510, 443, 860),
        ("2025-09-18T19:20:04Z", now-56, "192.168.1.50", "8.8.8.8", "UDP", 5353, 53, 120),
        ("2025-09-18T19:20:06Z", now-54, "192.168.1.50", "142.250.72.14", "TCP", 54511, 81, 700)
    ]
    alerts = [
        ("2025-09-18T19:20:10Z", now-50, "192.168.1.50", "PORT_SCAN",
         "Port scan suspected: 25 unique dports within 10s"),
        ("2025-09-18T19:20:14Z", now-46, "192.168.1.77", "BURST_RATE",
         "High packet rate: 230 packets within 10s")
    ]

    conn.executemany(
        "INSERT INTO packets (ts_iso, epoch, src_ip, dst_ip, proto, sport, dport, length) "
        "VALUES (?,?,?,?,?,?,?,?)",
        packets
    )
    conn.executemany(
        "INSERT INTO alerts (ts_iso, epoch, src_ip, alert_type, details) VALUES (?,?,?,?,?)",
        alerts
    )
    conn.commit()
    conn.close()

    print(f"Inserted {len(packets)} packets and {len(alerts)} alerts into {args.db}")

if __name__ == "__main__":
    main()

