#!/usr/bin/env python3
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional, Dict, Any

from flask import Flask, g, render_template, request, abort

UTC = timezone.utc
DB_ROW_FACTORY = sqlite3.Row


# -------------------------
# Helpers / DB
# -------------------------
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


def parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        # Accept "YYYY-MM-DDTHH:MM:SSZ" or isoformat
        if s.endswith("Z"):
            s = s[:-1]
        return datetime.fromisoformat(s).replace(tzinfo=UTC)
    except Exception:
        return None


def default_window(hours: int = 1) -> Tuple[datetime, datetime]:
    end = datetime.now(tz=UTC)
    start = end - timedelta(hours=hours)
    return start, end


def epoch(dt: datetime) -> float:
    return dt.timestamp()


# -------------------------
# App factory
# -------------------------
def create_app(db_path: str) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path
    app.teardown_appcontext(close_db)

    # ---- Shared queries ----
    def overview_counts(start_iso: str, end_iso: str) -> Dict[str, Any]:
        start_q = parse_dt(start_iso) or default_window(1)[0]
        end_q = parse_dt(end_iso) or default_window(1)[1]
        se, ee = epoch(start_q), epoch(end_q)
        db = get_db(db_path)

        # Packets in window
        pkt_rows = db.execute(
            "SELECT epoch, proto, src_ip FROM packets WHERE epoch BETWEEN ? AND ? ORDER BY epoch ASC",
            (se, ee)
        ).fetchall()

        # Alerts in window
        alert_rows = db.execute(
            "SELECT epoch, alert_type, src_ip FROM alerts WHERE epoch BETWEEN ? AND ?",
            (se, ee)
        ).fetchall()

        from collections import defaultdict

        # per-minute buckets
        per_min = defaultdict(int)
        cur = start_q.replace(second=0, microsecond=0)
        while cur <= end_q:
            per_min[cur.isoformat().replace("+00:00", "Z")] = 0
            cur += timedelta(minutes=1)

        proto_counts = defaultdict(int)
        alerted_srcs = set()
        alert_by_type = defaultdict(int)

        for r in pkt_rows:
            t = datetime.fromtimestamp(r["epoch"], UTC).replace(second=0, microsecond=0)
            key = t.isoformat().replace("+00:00", "Z")
            if key in per_min:
                per_min[key] += 1
            p = (r["proto"] or "").upper()
            if p in ("TCP", "UDP"):
                proto_counts[p] += 1
            else:
                proto_counts["OTHER"] += 1

        for r in alert_rows:
            alert_by_type[r["alert_type"]] += 1
            if r["src_ip"]:
                alerted_srcs.add(r["src_ip"])

        packet_labels = sorted(per_min.keys())
        packet_counts = [per_min[k] for k in packet_labels]

        alert_types = sorted(alert_by_type.keys()) or ["PORT_SCAN", "BURST_RATE", "BEACONING"]
        alert_values = [alert_by_type[t] for t in alert_types]

        total_packets = len(pkt_rows)
        total_alerts = len(alert_rows)
        hosts_flagged = len(alerted_srcs)
        good_packets = sum(1 for r in pkt_rows if r["src_ip"] not in alerted_srcs)

        proto_labels = ["TCP", "UDP", "OTHER"]
        proto_values = [
            proto_counts.get("TCP", 0),
            proto_counts.get("UDP", 0),
            proto_counts.get("OTHER", 0),
        ]

        return {
            "start_iso": start_q.isoformat().replace("+00:00", "Z"),
            "end_iso": end_q.isoformat().replace("+00:00", "Z"),
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
        }

    # ---- Routes ----
    @app.route("/")
    def home():
        start_q = parse_dt(request.args.get("start"))
        end_q = parse_dt(request.args.get("end"))
        if not start_q or not end_q:
            start_q, end_q = default_window(1)
        data = overview_counts(start_q.isoformat(), end_q.isoformat())
        return render_template(
            "home.html",
            **data
        )

    @app.route("/api/overview")
    def api_overview():
        start_q = parse_dt(request.args.get("start"))
        end_q = parse_dt(request.args.get("end"))
        if not start_q or not end_q:
            start_q, end_q = default_window(1)
        return overview_counts(start_q.isoformat(), end_q.isoformat())

    @app.route("/alerts")
    def alerts_view():
        db = get_db(db_path)
        rows = db.execute(
            "SELECT ts_iso, src_ip, alert_type, details FROM alerts ORDER BY epoch DESC LIMIT 500"
        ).fetchall()
        return render_template("alerts.html", rows=rows)

    @app.route("/packets")
    def packets_view():
        db = get_db(db_path)
        rows = db.execute(
            "SELECT ts_iso, src_ip, dst_ip, proto, sport, dport, length FROM packets ORDER BY epoch DESC LIMIT 1000"
        ).fetchall()
        return render_template("packets.html", rows=rows)

    return app


# -------------------------
# Entrypoint
# -------------------------
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="PacketTrail Dashboard")
    p.add_argument("--db", default=os.environ.get("PACKETTRAIL_DB", "packettrail.db"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=5000, type=int)
    args = p.parse_args()

    app = create_app(args.db)
    app.run(host=args.host, port=args.port, debug=True)

