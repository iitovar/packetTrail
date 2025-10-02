-- PacketTrail DB schema

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

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_iso TEXT NOT NULL,
    epoch REAL NOT NULL,
    src_ip TEXT,
    alert_type TEXT NOT NULL,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(epoch);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(epoch);

