#!/usr/bin/env python3
"""
PacketTrail Dashboard (MVP): red/blue theme, headline metrics, filters, and charts.
Run:
  python3 app.py --db packettrail.db --host 127.0.0.1 --port 5000
"""
import argparse, sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, g, request

UTC = timezone.utc

def get_db(db_path):
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
    return db

def parse_dt(s):
    if not s: return None
    try:
        if len(s) == 10:  # YYYY-MM-DD
            return datetime.fromisoformat(s).replace(tzinfo=UTC)
        return datetime.fromisoformat(s.replace("Z","")).replace(tzinfo=UTC)
    except Exception:
        return None

def default_window(hours=1):
    now = datetime.now(UTC)
    return now - timedelta(hours=hours), now

def epoch(dt): return dt.timestamp()

def create_app(db_path):
    app = Flask(__name__, static_url_path="/static", static_folder="static")

    @app.teardown_appcontext
    def close_db(_exc):
        db = getattr(g, "_db", None)
        if db is not None:
            db.close()

    @app.route("/")
    def home():
        # time window
        start_q = parse_dt(request.args.get("start"))
        end_q   = parse_dt(request.args.get("end"))
        if not start_q or not end_q:
            start_q, end_q = default_window(1)  # last hour

        db = get_db(db_path)
        se, ee = epoch(start_q), epoch(end_q)

        # packets in window
        pkt_rows = db.execute(
            "SELECT epoch, proto, src_ip FROM packets WHERE epoch BETWEEN ? AND ? ORDER BY epoch ASC",
            (se, ee)
        ).fetchall()

        # per-minute traffic
        per_min = defaultdict(int)
        cur = start_q.replace(second=0, microsecond=0)
        while cur <= end_q:
            per_min[cur.isoformat().replace("+00:00","Z")] = 0
            cur += timedelta(minutes=1)
        proto_counts = defaultdict(int)
        for r in pkt_rows:
            t = datetime.fromtimestamp(r["epoch"], UTC).replace(second=0, microsecond=0)
            key = t.isoformat().replace("+00:00","Z")
            if key in per_min:
                per_min[key] += 1
            proto = (r["proto"] or "").upper()
            if proto in ("TCP","UDP"):
                proto_counts[proto] += 1
            else:
                proto_counts["OTHER"] += 1

        packet_labels = sorted(per_min.keys())
        packet_counts = [per_min[k] for k in packet_labels]

        # alerts in window
        alert_rows = db.execute(
            "SELECT epoch, alert_type, src_ip FROM alerts WHERE epoch BETWEEN ? AND ?",
            (se, ee)
        ).fetchall()
        alert_by_type = defaultdict(int)
        alerted_srcs = set()
        for r in alert_rows:
            alert_by_type[r["alert_type"]] += 1
            if r["src_ip"]:
                alerted_srcs.add(r["src_ip"])

        alert_types = sorted(alert_by_type.keys()) or ["PORT_SCAN","BURST_RATE","BEACONING"]
        alert_values = [alert_by_type[t] for t in alert_types]

        # headline metrics
        total_packets = len(pkt_rows)
        total_alerts  = len(alert_rows)
        hosts_flagged = len(alerted_srcs)
        # "Good traffic" = packets whose source NOT in alerted sources (simple, explain in UI)
        good_packets  = sum(1 for r in pkt_rows if r["src_ip"] not in alerted_srcs)

        # protocol breakdown
        proto_labels = ["TCP","UDP","OTHER"]
        proto_values = [proto_counts.get("TCP",0), proto_counts.get("UDP",0), proto_counts.get("OTHER",0)]

        return render_template(
            "home.html",
            start_iso=start_q.isoformat().replace("+00:00","Z"),
            end_iso=end_q.isoformat().replace("+00:00","Z"),
            total_packets=total_packets,
            good_packets=good_packets,
            total_alerts=total_alerts,
            hosts_flagged=hosts_flagged,
            packet_labels=packet_labels,
            packet_counts=packet_counts,
            alert_types=alert_types,
            alert_values=alert_values,
            proto_labels=proto_labels,
            proto_values=proto_values
        )

    @app.route("/alerts")
    def alerts():
        page = max(int(request.args.get("page", 1)), 1)
        size = min(max(int(request.args.get("size", 25)), 1), 200)
        offset = (page - 1) * size
        q = request.args.get("q", "").strip()
        start_q = parse_dt(request.args.get("start"))
        end_q   = parse_dt(request.args.get("end"))
        if not start_q or not end_q:
            start_q, end_q = default_window(24)
        se, ee = epoch(start_q), epoch(end_q)

        where = ["epoch BETWEEN ? AND ?"]
        params = [se, ee]
        if q:
            where.append("(src_ip LIKE ? OR alert_type LIKE ? OR details LIKE ?)")
            like = f"%{q}%"; params += [like, like, like]

        sql = f"""
            SELECT ts_iso, src_ip, alert_type, details
            FROM alerts
            WHERE {' AND '.join(where)}
            ORDER BY epoch DESC
            LIMIT ? OFFSET ?"""
        params_list = params + [size, offset]

        db = get_db(db_path)
        rows = db.execute(sql, params_list).fetchall()
        count = db.execute(f"SELECT COUNT(*) FROM alerts WHERE {' AND '.join(where)}", params).fetchone()[0]

        return render_template("alerts.html", rows=rows, page=page, size=size, count=count,
                               q=q, start_val=start_q.date().isoformat(), end_val=end_q.date().isoformat())

    @app.route("/packets")
    def packets():
        page = max(int(request.args.get("page", 1)), 1)
        size = min(max(int(request.args.get("size", 25)), 1), 200)
        offset = (page - 1) * size
        qsrc  = request.args.get("qsrc", "").strip()
        qdst  = request.args.get("qdst", "").strip()
        proto = request.args.get("proto", "").strip().upper()
        start_q = parse_dt(request.args.get("start"))
        end_q   = parse_dt(request.args.get("end"))
        if not start_q or not end_q:
            start_q, end_q = default_window(24)
        se, ee = epoch(start_q), epoch(end_q)

        where = ["epoch BETWEEN ? AND ?"]
        params = [se, ee]
        if qsrc:
            where.append("src_ip LIKE ?"); params.append(f"%{qsrc}%")
        if qdst:
            where.append("dst_ip LIKE ?"); params.append(f"%{qdst}%")
        if proto in ("TCP","UDP"):
            where.append("proto = ?"); params.append(proto)

        sql = f"""
            SELECT ts_iso, src_ip, dst_ip, proto, sport, dport, length
            FROM packets
            WHERE {' AND '.join(where)}
            ORDER BY epoch DESC
            LIMIT ? OFFSET ?"""
        params2 = params + [size, offset]

        db = get_db(db_path)
        rows = db.execute(sql, params2).fetchall()
        count = db.execute(f"SELECT COUNT(*) FROM packets WHERE {' AND '.join(where)}", params).fetchone()[0]

        return render_template("packets.html", rows=rows, page=page, size=size, count=count,
                               qsrc=qsrc, qdst=qdst, proto=proto,
                               start_val=start_q.date().isoformat(), end_val=end_q.date().isoformat())

    return app

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="packettrail.db")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    app = create_app(args.db)
    app.run(host=args.host, port=args.port, debug=True)

