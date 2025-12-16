-- PacketTrail DB schema
CREATE TABLE IF NOT EXISTS packets (
  id INTEGER PRIMARY KEY,
  epoch REAL NOT NULL,
  ts_iso TEXT NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  proto TEXT,
  sport INTEGER,
  dport INTEGER,
  length INTEGER
);

-- alerts (existing + used by new THREAT_MATCH alerts)
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY,
  epoch REAL NOT NULL,
  ts_iso TEXT NOT NULL,
  src_ip TEXT,
  alert_type TEXT,
  details TEXT
);

-- NEW: threat intel IPs from open feeds (one row per IP)
CREATE TABLE IF NOT EXISTS threat_intel (
  ip TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  added_ts TEXT NOT NULL
);

-- NEW: passive DNS cache for packet IPs (resolved hostnames)
CREATE TABLE IF NOT EXISTS dns_cache (
  ip TEXT PRIMARY KEY,
  hostname TEXT,
  last_resolved_ts TEXT
);

