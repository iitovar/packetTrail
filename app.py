#!/usr/bin/env python3
"""
Flask dashboard for PacketTrail.
Run:
  python3 app.py --db packettrail.db --host 127.0.0.1 --port 5000
"""
import argparse, sqlite3
from flask import Flask, render_template, g, request

def get_db(db_path):
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
    return db

def create_app(db_path):
    app = Flask(__name__)

    @app.teardown_appcontext
    def close_db(_exc):
        db = getattr(g, "_db", None)
        if db is not None:
            db.close()

    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/alerts")
    def alerts():
        page = max(int(request.args.get("page", 1)), 1)
        size = min(max(int(request.args.get("size", 25)), 1), 200)
        offset = (page - 1) * size
        db = get_db(db_path)
        rows = db.execute(
            "SELECT ts_iso, src_ip, alert_type, details FROM alerts ORDER BY epoch DESC LIMIT ? OFFSET ?",
            (size, offset)
        ).fetchall()
        count = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return render_template("alerts.html", rows=rows, page=page, size=size, count=count)

    @app.route("/packets")
    def packets():
        page = max(int(request.args.get("page", 1)), 1)
        size = min(max(int(request.args.get("size", 25)), 1), 200)
        offset = (page - 1) * size
        db = get_db(db_path)
        rows = db.execute(
            """SELECT ts_iso, src_ip, dst_ip, proto, sport, dport, length
               FROM packets ORDER BY epoch DESC LIMIT ? OFFSET ?""",
            (size, offset)
        ).fetchall()
        count = db.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        return render_template("packets.html", rows=rows, page=page, size=size, count=count)

    return app

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="packettrail.db")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    app = create_app(args.db)
    app.run(host=args.host, port=args.port, debug=True)

