#!/usr/bin/env python3
"""
PacketTrail: capture + SQLite logging + basic detections (port-scan, burst-rate, beaconing).
Run (macOS/Linux usually needs sudo):
  sudo python3 packettrail.py --iface <iface>
"""
import argparse, sqlite3, time
from datetime import datetime
from collections import deque, defaultdict
from typing import Optional
from scapy.all import sniff, IP, TCP, UDP

def init_db(db_path: str):
    conn = sqlite3.connect(db_path, check_same_thread=False)
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
        );""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_iso TEXT NOT NULL,
            epoch REAL NOT NULL,
            src_ip TEXT,
            alert_type TEXT NOT NULL,
            details TEXT
        );""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(epoch);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(epoch);")
    conn.commit()
    return conn

def insert_packet(conn, ts_iso, epoch, src_ip, dst_ip, proto, sport, dport, length):
    conn.execute(
        "INSERT INTO packets (ts_iso, epoch, src_ip, dst_ip, proto, sport, dport, length) VALUES (?,?,?,?,?,?,?,?)",
        (ts_iso, epoch, src_ip, dst_ip, proto, sport, dport, length)
    )

def insert_alert(conn, ts_iso, epoch, src_ip, alert_type, details):
    conn.execute(
        "INSERT INTO alerts (ts_iso, epoch, src_ip, alert_type, details) VALUES (?,?,?,?,?)",
        (ts_iso, epoch, src_ip, alert_type, details)
    )

class Detector:
    """
    Sliding-window detector with 3 rules:
      - PORT_SCAN: many unique dports from same src within window
      - BURST_RATE: many packets from same src within window
      - BEACONING: regular interval connections from src->dst (low jitter)
    """
    def __init__(self, window_seconds=10, port_threshold=20, rate_threshold=200,
                 beacon_count=6, beacon_jitter=0.30, cooldown_seconds=60):
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        self.rate_threshold = rate_threshold
        self.beacon_count = beacon_count           # min packets in window for beacon test
        self.beacon_jitter = beacon_jitter         # allowable std/mean of inter-arrival times
        self.cooldown_seconds = cooldown_seconds

        self.activity = defaultdict(deque)         # src -> deque[(epoch, dport, dst_ip)]
        self.last_alert = defaultdict(lambda: 0.0) # (type, key) -> last_epoch

    def observe(self, now_epoch: float, src: str, dport: Optional[int], dst_ip: Optional[str]):
        dq = self.activity[src]
        dq.append((now_epoch, dport, dst_ip))
        while dq and now_epoch - dq[0][0] > self.window_seconds:
            dq.popleft()

    def _cooldown_ok(self, key):
        now = key[-1] if isinstance(key, tuple) and isinstance(key[-1], (int, float)) else None
        return True

    def _should_alert(self, now_epoch: float, atype: str, key: str):
        k = (atype, key)
        if now_epoch - self.last_alert[k] >= self.cooldown_seconds:
            self.last_alert[k] = now_epoch
            return True
        return False

    def check_portscan(self, now_epoch: float, src: str):
        dq = self.activity[src]
        unique_ports = {p for (_, p, _) in dq if p is not None}
        if len(unique_ports) >= self.port_threshold and self._should_alert(now_epoch, "PORT_SCAN", src):
            return True, len(unique_ports)
        return False, len(unique_ports)

    def check_burst(self, now_epoch: float, src: str):
        dq = self.activity[src]
        count = len(dq)
        if count >= self.rate_threshold and self._should_alert(now_epoch, "BURST_RATE", src):
            return True, count
        return False, count

    def check_beaconing(self, now_epoch: float, src: str):
        """
        Heuristic: for each dst seen from this src in window, compute inter-arrival
        deltas; if we have >= beacon_count and stdev/mean <= beacon_jitter, alert.
        """
        from math import sqrt
        dq = self.activity[src]
        # group by dst
        times_by_dst = defaultdict(list)
        for t, _, dst in dq:
            if dst:
                times_by_dst[dst].append(t)
        for dst, times in times_by_dst.items():
            if len(times) < self.beacon_count:
                continue
            times.sort()
            deltas = [times[i+1]-times[i] for i in range(len(times)-1)]
            if not deltas:
                continue
            mean = sum(deltas)/len(deltas)
            if mean == 0:
                continue
            var = sum((d-mean)**2 for d in deltas)/len(deltas)
            stdev = sqrt(var)
            jitter = stdev/mean
            if jitter <= self.beacon_jitter:
                key = f"{src}->{dst}"
                if self._should_alert(now_epoch, "BEACONING", key):
                    return True, dst, len(times), round(jitter, 3), round(mean, 2)
        return False, None, 0, 0.0, 0.0

def main():
    p = argparse.ArgumentParser(description="PacketTrail - capture, log, and detect anomalies.")
    p.add_argument("--iface", help="Interface (e.g., en0, eth0, wlan0)")
    p.add_argument("--db", default="packettrail.db")
    p.add_argument("--window", type=int, default=10)
    p.add_argument("--port-threshold", type=int, default=20)
    p.add_argument("--rate-threshold", type=int, default=200)
    p.add_argument("--beacon-count", type=int, default=6)
    p.add_argument("--beacon-jitter", type=float, default=0.30)
    p.add_argument("--bpf", default="tcp or udp")
    args = p.parse_args()

    conn = init_db(args.db)
    detector = Detector(window_seconds=args.window,
                        port_threshold=args.port_threshold,
                        rate_threshold=args.rate_threshold,
                        beacon_count=args.beacon_count,
                        beacon_jitter=args.beacon_jitter)

    print("[PacketTrail] DB ->", args.db)
    print("[PacketTrail] Starting sniff... (Ctrl+C to stop)")

    def handle(pkt):
        now = time.time()
        ts_iso = datetime.utcfromtimestamp(now).isoformat(timespec="seconds") + "Z"
        src_ip = pkt[IP].src if IP in pkt else None
        dst_ip = pkt[IP].dst if IP in pkt else None
        proto  = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else None)
        sport  = int(pkt[TCP].sport) if TCP in pkt else (int(pkt[UDP].sport) if UDP in pkt else None)
        dport  = int(pkt[TCP].dport) if TCP in pkt else (int(pkt[UDP].dport) if UDP in pkt else None)

        if src_ip and dst_ip and proto:
            length = len(bytes(pkt))
            insert_packet(conn, ts_iso, now, src_ip, dst_ip, proto, sport, dport, length)
            detector.observe(now, src_ip, dport, dst_ip)

            ps_flag, uniq_ports = detector.check_portscan(now, src_ip)
            if ps_flag:
                insert_alert(conn, ts_iso, now, src_ip, "PORT_SCAN",
                             f"{uniq_ports} unique dports in {detector.window_seconds}s")
                print(f"[ALERT] {ts_iso} {src_ip} -> PORT_SCAN ({uniq_ports} ports)")

            burst_flag, count = detector.check_burst(now, src_ip)
            if burst_flag:
                insert_alert(conn, ts_iso, now, src_ip, "BURST_RATE",
                             f"{count} packets in {detector.window_seconds}s")
                print(f"[ALERT] {ts_iso} {src_ip} -> BURST_RATE ({count})")

            b_flag, dst, n, jit, mean = detector.check_beaconing(now, src_ip)
            if b_flag:
                insert_alert(conn, ts_iso, now, src_ip, "BEACONING",
                             f"to {dst} ~{n} hits; jitter={jit}, mean_interval={mean}s")
                print(f"[ALERT] {ts_iso} {src_ip} -> BEACONING to {dst} (n={n}, jitter={jit})")

            conn.commit()

    try:
        kwargs = dict(store=False, prn=handle, filter=args.bpf)
        if args.iface: kwargs["iface"] = args.iface
        sniff(**kwargs)
    except KeyboardInterrupt:
        print("\n[PacketTrail] Stopping.")
    finally:
        conn.commit(); conn.close()
        print("[PacketTrail] DB closed.")

if __name__ == "__main__":
    main()

