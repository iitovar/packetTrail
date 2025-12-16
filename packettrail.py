#!/usr/bin/env python3
from __future__ import annotations
import argparse, os, sqlite3, time
from datetime import datetime, timezone, timedelta
from scapy.all import sniff, IP, TCP, UDP

UTC = timezone.utc

def iso_now(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), UTC).isoformat().replace("+00:00","Z")

def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

class Detector:
    def __init__(self, db: sqlite3.Connection, window: int, port_threshold: int, rate_threshold: int, beacon_count: int, beacon_jitter: float):
        self.db = db
        self.window = window
        self.port_threshold = port_threshold
        self.rate_threshold = rate_threshold
        self.beacon_count = beacon_count
        self.beacon_jitter = beacon_jitter
        self._ports: dict[str,set[int]] = {}
        self._times: dict[str,list[float]] = {}

    def _insert_alert(self, src: str | None, a_type: str, details: str, ts: float | None = None):
        ep = ts or time.time()
        self.db.execute(
            "INSERT INTO alerts(epoch, ts_iso, src_ip, alert_type, details) VALUES (?,?,?,?,?)",
            (ep, iso_now(ep), src, a_type, details)
        )
        self.db.commit()

    def _portscan(self, now: float, src: str, dport: int | None):
        if dport is None: 
            return
        s = self._ports.setdefault(src, set())
        s.add(dport)
        # drop old state window
        for k in list(self._ports.keys()):
            # (simple windowing by size; adequate for MVP)
            if len(self._ports[k]) > self.port_threshold:
                self._insert_alert(src, "PORT_SCAN", f"Port scan suspected: {len(self._ports[k])} unique dports within {self.window}s", now)
                self._ports[k].clear()

    def _burst(self, now: float, src: str):
        tlist = self._times.setdefault(src, [])
        tlist.append(now)
        # keep only recent timestamps
        cutoff = now - self.window
        while tlist and tlist[0] < cutoff:
            tlist.pop(0)
        if len(tlist) >= self.rate_threshold:
            self._insert_alert(src, "BURST_RATE", f"High packet rate: {len(tlist)} packets within {self.window}s", now)
            tlist.clear()

    def _beacon(self, now: float, src: str):
        # simple fixed-interval check (demo-level)
        tlist = self._times.setdefault(f"b:{src}", [])
        tlist.append(now)
        if len(tlist) < self.beacon_count:
            return
        intervals = [tlist[i+1]-tlist[i] for i in range(len(tlist)-1)]
        avg = sum(intervals)/len(intervals)
        if all(abs(iv-avg) <= self.beacon_jitter*avg for iv in intervals):
            self._insert_alert(src, "BEACONING", f"Regular callback interval ~{avg:.2f}s", now)
            tlist.clear()

    def _threat_match(self, src: str | None, dst: str | None, ts: float):
        # check if either IP is in threat_intel
        if not (src or dst): 
            return
        cur = self.db.cursor()
        for ip in (src, dst):
            if not ip: 
                continue
            row = cur.execute("SELECT source FROM threat_intel WHERE ip = ?", (ip,)).fetchone()
            if row:
                self._insert_alert(src, "THREAT_MATCH", f"Matched blocklist ({row['source']}) for IP {ip}", ts)
                break

    def observe(self, now_epoch: float, src: str | None, dport: int | None, dst: str | None):
        if src:
            self._portscan(now_epoch, src, dport)
            self._burst(now_epoch, src)
            self._beacon(now_epoch, src)
        self._threat_match(src, dst, now_epoch)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--db", default="packettrail.db")
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--port-threshold", type=int, default=25)
    ap.add_argument("--rate-threshold", type=int, default=200)
    ap.add_argument("--beacon-count", type=int, default=6)
    ap.add_argument("--beacon-jitter", type=float, default=0.30)
    ap.add_argument("--bpf", default="tcp or udp")
    args = ap.parse_args()

    db = open_db(args.db)
    print(f"[PacketTrail] DB -> {args.db}")

    def on_pkt(pkt):
        now = time.time()
        if IP not in pkt:
            return
        ip = pkt[IP]
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "IP")
        sport = int(pkt[TCP].sport) if TCP in pkt else (int(pkt[UDP].sport) if UDP in pkt else None)
        dport = int(pkt[TCP].dport) if TCP in pkt else (int(pkt[UDP].dport) if UDP in pkt else None)

        db.execute(
            "INSERT INTO packets(epoch, ts_iso, src_ip, dst_ip, proto, sport, dport, length) VALUES (?,?,?,?,?,?,?,?)",
            (now, iso_now(now), ip.src, ip.dst, proto, sport, dport, len(pkt))
        )
        db.commit()

        det.observe(now, ip.src, dport, ip.dst)

    det = Detector(db, args.window, args.port_threshold, args.rate_threshold, args.beacon_count, args.beacon_jitter)
    print("[PacketTrail] Starting sniff... (Ctrl+C to stop)")
    try:
        sniff(iface=args.iface, prn=on_pkt, store=False, filter=args.bpf)
    finally:
        print("[PacketTrail] DB closed.")
        db.close()

if __name__ == "__main__":
    main()

