#!/usr/bin/env python3
import sqlite3, sys, time, urllib.request, urllib.error

FEEDS = [
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "firehol_level1"),
    # This one sometimes goes 404; we'll try and skip on failure:
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malwaredomainlist.ipset", "malwaredomainlist"),
    ("https://www.spamhaus.org/drop/drop.txt", "spamhaus_drop"),
    ("https://www.spamhaus.org/drop/edrop.txt", "spamhaus_edrop"),
    ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "emergingthreats_compromised"),
]

def fetch_lines(url: str):
    with urllib.request.urlopen(url, timeout=45) as r:
        for raw in r.read().decode("utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            token = line.split()[0]  # handle "IP ; comment"
            yield token

def main(db_path: str):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
          ip TEXT PRIMARY KEY,
          source TEXT NOT NULL,
          added_ts TEXT NOT NULL
        )
    """)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    total = 0

    for url, src in FEEDS:
        try:
            ips = set()
            for token in fetch_lines(url):
                # skip IPv6 for now (simple MVP)
                if ":" in token:
                    continue
                # keep CIDR/networks as-is so you can still see the item
                ips.add(token)
            if not ips:
                print(f"[threats] {src}: 0 items (empty)")
                continue
            rows = [(ip, src, now_iso) for ip in ips]
            cur.executemany(
                "INSERT OR REPLACE INTO threat_intel(ip, source, added_ts) VALUES (?,?,?)",
                rows
            )
            conn.commit()
            print(f"[threats] {src}: {len(rows)} items")
            total += len(rows)
        except urllib.error.HTTPError as e:
            print(f"[threats] {src}: HTTP {e.code} ({url}) — skipped")
        except Exception as e:
            print(f"[threats] {src}: error {e} — skipped")

    conn.close()
    print(f"[threats] total stored: {total}")

if __name__ == "__main__":
    db = sys.argv[1] if len(sys.argv) > 1 else "packettrail.db"
    main(db)

