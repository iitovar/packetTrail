#!/usr/bin/env python3
import sqlite3, sys, socket, time
from typing import Optional

DB = sys.argv[1] if len(sys.argv) > 1 else "packettrail.db"
TIMEOUT = 2.0

def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dns_cache (
          ip TEXT PRIMARY KEY,
          hostname TEXT,
          ts_iso TEXT NOT NULL
        )
    """)
    # convenience index 
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_hostname ON dns_cache(hostname)")

def resolve(ip: str) -> Optional[str]:
    try:
        socket.setdefaulttimeout(TIMEOUT)
        host, _aliases, _ips = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None

def main() -> None:
    conn = sqlite3.connect(DB)
    ensure_schema(conn)
    cur = conn.cursor()

    # Pull distinct dst IPs 
    rows = cur.execute("""
        SELECT DISTINCT p.dst_ip
        FROM packets p
        LEFT JOIN dns_cache d ON d.ip = p.dst_ip
        WHERE p.dst_ip IS NOT NULL AND d.ip IS NULL
        LIMIT 500
    """).fetchall()

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    added = 0
    for (ip,) in rows:
        host = resolve(ip)
        cur.execute(
            "INSERT OR REPLACE INTO dns_cache(ip, hostname, ts_iso) VALUES (?,?,?)",
            (ip, host, now_iso)
        )
        added += 1

    conn.commit()
    conn.close()
    print(f"[dns] cached {added} hostnames")

if __name__ == "__main__":
    main()

