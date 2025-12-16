#!/usr/bin/env python3
from __future__ import annotations
import os, sqlite3, re
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Tuple, Optional
from flask import Flask, g, render_template, request, jsonify

UTC = timezone.utc
DB_ROW_FACTORY = sqlite3.Row

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")  # matches HTML datetime-local (no seconds)

def get_db(db_path: str) -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(db_path)
        conn.row_factory = DB_ROW_FACTORY
        g.db = conn
    return g.db  # type: ignore[return-value]

def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def parse_dt_local(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    if not DATE_RE.match(s):
        return None
    # interpret as UTC 
    return datetime.strptime(s, "%Y-%m-%dT%H:%M").replace(tzinfo=UTC)

def parse_iso_z(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"): s = s[:-1]
        return datetime.fromisoformat(s).replace(tzinfo=UTC)
    except Exception:
        return None

def default_window(hours: int = 1) -> Tuple[datetime, datetime]:
    end = datetime.now(tz=UTC).replace(second=0, microsecond=0)
    start = end - timedelta(hours=hours)
    return start, end

def epoch(dt: datetime) -> float:
    return dt.timestamp()

def create_app(db_path: str) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path
    app.teardown_appcontext(close_db)

    def overview_counts(start_dt: datetime, end_dt: datetime) -> Dict[str, Any]:
        se, ee = epoch(start_dt), epoch(end_dt)
        db = get_db(db_path)

        pkt_rows = db.execute("""
            SELECT epoch, proto, src_ip, dst_ip
            FROM packets WHERE epoch BETWEEN ? AND ? ORDER BY epoch ASC
        """, (se, ee)).fetchall()
        alert_rows = db.execute("""
            SELECT epoch, ts_iso, src_ip, alert_type, details
            FROM alerts WHERE epoch BETWEEN ? AND ? ORDER BY epoch DESC
        """, (se, ee)).fetchall()

        from collections import defaultdict
        per_min = defaultdict(int)
        cur = start_dt.replace(second=0, microsecond=0)
        while cur <= end_dt:
            per_min[cur.isoformat().replace("+00:00","Z")] = 0
            cur += timedelta(minutes=1)

        proto_counts = defaultdict(int)
        alerted_srcs = set()
        alert_by_type = defaultdict(int)

        for r in pkt_rows:
            t = datetime.fromtimestamp(r["epoch"], UTC).replace(second=0, microsecond=0)
            key = t.isoformat().replace("+00:00","Z")
            if key in per_min: per_min[key] += 1
            p = (r["proto"] or "").upper()
            proto_counts[p if p in ("TCP","UDP") else "OTHER"] += 1

        for r in alert_rows:
            alert_by_type[r["alert_type"]] += 1
            if r["src_ip"]: alerted_srcs.add(r["src_ip"])

        threat_hits = db.execute("""
            SELECT COUNT(*) AS c FROM packets p
            WHERE p.epoch BETWEEN ? AND ?
              AND (p.src_ip IN (SELECT ip FROM threat_intel) OR p.dst_ip IN (SELECT ip FROM threat_intel))
        """, (se, ee)).fetchone()["c"]

        top_src = db.execute("""
            SELECT src_ip, COUNT(*) AS c
            FROM packets
            WHERE epoch BETWEEN ? AND ? AND src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY c DESC
            LIMIT 5
        """, (se, ee)).fetchall()

        packet_labels = sorted(per_min.keys())
        packet_counts = [per_min[k] for k in packet_labels]
        alert_types = sorted(alert_by_type.keys()) or ["PORT_SCAN","BURST_RATE","BEACONING","THREAT_MATCH"]
        alert_values = [alert_by_type[t] for t in alert_types]

        # recent alerts for the dashboard (top 5, newest first)
        recent_alerts = [
            {"ts_iso": r["ts_iso"], "src_ip": r["src_ip"], "alert_type": r["alert_type"], "details": r["details"]}
            for r in alert_rows[:5]
        ]

        proto_labels = ["TCP","UDP","OTHER"]
        proto_values = [proto_counts.get("TCP",0), proto_counts.get("UDP",0), proto_counts.get("OTHER",0)]

        total_packets = len(pkt_rows)
        total_alerts = len(alert_rows)
        hosts_flagged = len(alerted_srcs)
        good_packets = total_packets - threat_hits

        return {
            "start_iso": start_dt.isoformat().replace("+00:00","Z"),
            "end_iso": end_dt.isoformat().replace("+00:00","Z"),
            "total_packets": total_packets,
            "good_packets": good_packets,
            "total_alerts": total_alerts,
            "hosts_flagged": hosts_flagged,
            "packet_labels": packet_labels,
            "packet_counts": packet_counts,
            "alert_types": alert_types,
            "alert_values": alert_values,
            "proto_labels": proto_labels,
            "proto_values": proto_values,
            "threat_hits": threat_hits,
            "top_src": [dict(row) for row in top_src],
            "recent_alerts": recent_alerts,
        }

    @app.route("/")
    def home():
        start_q = parse_iso_z(request.args.get("start")) or parse_dt_local(request.args.get("start_local"))
        end_q   = parse_iso_z(request.args.get("end"))   or parse_dt_local(request.args.get("end_local"))
        if not start_q or not end_q:
            start_q, end_q = default_window(1)
        data = overview_counts(start_q, end_q)
        return render_template("home.html", **data)

    @app.route("/api/overview")
    def api_overview():
        start_q = parse_iso_z(request.args.get("start")) or parse_dt_local(request.args.get("start_local"))
        end_q   = parse_iso_z(request.args.get("end"))   or parse_dt_local(request.args.get("end_local"))
        if not start_q or not end_q:
            start_q, end_q = default_window(1)
        return jsonify(overview_counts(start_q, end_q))

    @app.route("/alerts")
    def alerts_view():
        db = get_db(db_path)
        # Inputs
        start_q = parse_dt_local(request.args.get("start"))
        end_q   = parse_dt_local(request.args.get("end"))
        if not start_q or not end_q:
            start_q, end_q = default_window(4)
        sort = request.args.get("sort", "desc").lower()
        order = "DESC" if sort == "desc" else "ASC"

        se, ee = epoch(start_q), epoch(end_q)
        rows = db.execute(f"""
            SELECT ts_iso, src_ip, alert_type, details, epoch
            FROM alerts
            WHERE epoch BETWEEN ? AND ?
            ORDER BY epoch {order}
            LIMIT 2000
        """, (se, ee)).fetchall()

        return render_template("alerts.html", rows=rows, start_val=start_q, end_val=end_q, sort=sort)

    @app.route("/packets")
    def packets_view():
        db = get_db(db_path)
        start_q = parse_dt_local(request.args.get("start"))
        end_q   = parse_dt_local(request.args.get("end"))
        if not start_q or not end_q:
            start_q, end_q = default_window(1)
        sort = request.args.get("sort", "desc").lower()
        order = "DESC" if sort == "desc" else "ASC"

        se, ee = epoch(start_q), epoch(end_q)
        rows = db.execute(f"""
            WITH freq AS (
              SELECT src_ip, dst_ip, COUNT(*) AS cnt
              FROM packets
              WHERE epoch BETWEEN ? AND ?
              GROUP BY src_ip, dst_ip
            )
            SELECT p.ts_iso, p.src_ip, p.dst_ip,
                   dc_dst.hostname AS dst_host,
                   p.proto, p.sport, p.dport, p.length, p.epoch,
                   COALESCE(f.cnt,1) AS freq_last_hour,
                   CASE
                     WHEN (p.src_ip IN (SELECT ip FROM threat_intel) OR p.dst_ip IN (SELECT ip FROM threat_intel))
                     THEN 1 ELSE 0
                   END AS is_threat
            FROM packets p
            LEFT JOIN freq f ON f.src_ip = p.src_ip AND f.dst_ip = p.dst_ip
            LEFT JOIN dns_cache dc_dst ON dc_dst.ip = p.dst_ip
            WHERE p.epoch BETWEEN ? AND ?
            ORDER BY p.epoch {order}
            LIMIT 2000
        """, (se, ee, se, ee)).fetchall()

        return render_template("packets.html", rows=rows, start_val=start_q, end_val=end_q, sort=sort)

    return app

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="PacketTrail Dashboard")
    p.add_argument("--db", default=os.environ.get("PACKETTRAIL_DB", "packettrail.db"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=5000, type=int)
    args = p.parse_args()

    app = create_app(args.db)
    app.run(host=args.host, port=args.port, debug=True)

