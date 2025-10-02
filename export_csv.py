#!/usr/bin/env python3
"""
Export PacketTrail SQLite tables to CSV.

Usage:
  python3 export_csv.py --db packettrail.db --out export_dir

Example:
  python3 export_csv.py --db packettrail.db --out sample_export
"""

import argparse
import sqlite3
import csv
import os

def export_table(conn, table, outdir):
    cur = conn.execute(f"SELECT * FROM {table}")
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()

    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{table}.csv")

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        writer.writerows(rows)

    return path, len(rows)

def main():
    parser = argparse.ArgumentParser(description="Export PacketTrail SQLite tables to CSV")
    parser.add_argument("--db", default="packettrail.db", help="Path to SQLite database")
    parser.add_argument("--out", default="export", help="Directory to write CSV files")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    try:
        for table in ("packets", "alerts"):
            try:
                path, n = export_table(conn, table, args.out)
                print(f"Exported {table} -> {path} ({n} rows)")
            except Exception as e:
                print(f"[warn] Could not export {table}: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()

