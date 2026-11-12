#!/usr/bin/env python3
"""
ShopSecure — "Pre-Launch Penetration Test for an E-Commerce Site"
Case study demo unit: Implementing Security Defenses.
CLASSROOM / LOCAL DEMO ONLY — fake data, toy SQLite database.

Run:
    pip install flask
    python app.py
"""

from __future__ import annotations

import html
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "shopsecure.db"

app = Flask(__name__)

# --------------------------------------------------------------------------- #
#  Shared demo state (single presenter, single browser — deliberately simple)  #
# --------------------------------------------------------------------------- #
LOCK = threading.Lock()
MODE = {"value": "vulnerable"}          # "vulnerable" | "secured"
LOG: list[dict] = []                    # live attack log entries
SEQ = {"id": 0}                         # monotonic log id (never reset)
FAILED: dict[str, int] = {}             # username -> failed attempts
LOCKED: dict[str, float] = {}           # username -> lock expiry (epoch)
LAST_USER = {"name": ""}

MAX_ATTEMPTS = 5
LOCK_SECONDS = 60

# --------------------------------------------------------------------------- #
#  Toy data                                                                     #
# --------------------------------------------------------------------------- #
USERS = [
    ("admin", "admin123", "administrator"),
    ("maya", "neonlife", "customer"),
    ("guest", "guest", "customer"),
]

PRODUCTS = [
    ("Neon Flux Hoodie", "Apparel", 59.99, "Reflective-strike hoodie with thermal lining and taped seams.", 4.6),
    ("Cyber Runner Sneakers", "Footwear", 89.0, "Lightweight runners with reactive gel heel and glow trim.", 4.4),
    ("Holo Visor Sunglasses", "Accessories", 24.5, "Polarized wrap-around visor with mirror finish.", 4.1),
    ("Quantum Mechanical Keyboard", "Electronics", 119.0, "Hot-swappable switches, per-key RGB, aluminium deck.", 4.8),
    ("Pulse Wireless Mouse", "Electronics", 39.99, "26K DPI sensor, 70h battery, silent clicks.", 4.5),
    ("Grid Runner Backpack", "Accessories", 74.0, "22L commuter pack with laptop sleeve and rain cover.", 4.7),
    ("Plasma Desk Lamp", "Home", 45.0, "Stepless dimming, USB-C power, colour temperature memory.", 4.2),
    ("Static Denim Jacket", "Apparel", 95.0, "Washed denim with embroidered glitch motif on the back.", 4.3),
    ("Echo Noise-Cancel Headphones", "Electronics", 149.0, "Hybrid ANC, 40h battery, multipoint Bluetooth.", 4.9),
    ("Vector Water Bottle", "Home", 19.99, "750ml insulated steel bottle, keeps cold 24h.", 4.0),
    ("Glitch Print T-Shirt", "Apparel", 29.0, "Heavyweight cotton with discharge-printed glitch art.", 4.5),
    ("Hexagon Leather Wallet", "Accessories", 34.0, "Slim bifold with RFID-blocking lining.", 4.2),
]

REVIEWS = [
    (1, "Maya", "Fits great and the reflective strips actually work at night. 5/5.", "2026-11-01 18:22:10", 0),
    (9, "Dmitri", "Battery lasts forever and the ANC kills the train noise completely.", "2026-11-02 09:14:55", 0),
    (2, "Sam", "True to size, comfy for city walking. Order half size up if wide feet.", "2026-11-03 21:47:31", 0),
]

# --------------------------------------------------------------------------- #
#  Detection helpers (used by Secured Mode validation layer)                    #
# --------------------------------------------------------------------------- #
SQLI_PATTERN = re.compile(
    r"('|\"|;|--|/\*|union[\s/]+select|select[\s/]+from|drop\s+table|delete\s+from|"
    r"insert\s+into|update\s+\w+\s+set|alter\s+table|exec(ute)?\s|sleep\s*\(|benchmark\s*\(|"
    r"or\s+'?1'?\s*=\s*'?1'?|or\s+1\s*=\s*1|and\s+1\s*=\s*1|information_schema)",
    re.IGNORECASE,
)
STRICT_FIELD = re.compile(r"['\";]")          # login fields: quotes/semicolons never legit
XSS_PATTERN = re.compile(r"<\s*/?\s*[a-z!]|javascript:|on[a-z]+\s*=|&#x|data:text/html", re.IGNORECASE)


def is_sqli(text: str, strict: bool = False) -> bool:
    text = text or ""
    if SQLI_PATTERN.search(text):
        return True
    return bool(strict and STRICT_FIELD.search(text))


def is_xss(text: str) -> bool:
    return bool(XSS_PATTERN.search(text or ""))


# --------------------------------------------------------------------------- #
#  Logging                                                                      #
# --------------------------------------------------------------------------- #
def log_event(kind: str, message: str, status: str = "ok") -> None:
    with LOCK:
        SEQ["id"] += 1
        LOG.append({
            "id": SEQ["id"],
            "ts": time.time(),
            "mode": MODE["value"],
            "kind": kind,
            "message": message,
            "status": status,          # ok | pwn | blocked | fail | lock
        })
        if len(LOG) > 300:
            del LOG[: len(LOG) - 300]


# --------------------------------------------------------------------------- #
#  SQLite helpers                                                               #
# --------------------------------------------------------------------------- #
def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def seed_db() -> None:
    if DB_FILE.exists():
        DB_FILE.unlink()
    conn = connect()
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)")
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL, description TEXT, rating REAL)")
    cur.execute("CREATE TABLE reviews (id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT, created TEXT, sanitized INTEGER DEFAULT 0)")
    cur.executemany("INSERT INTO products (name, category, price, description, rating) VALUES (?, ?, ?, ?, ?)", PRODUCTS)
    cur.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", USERS)
    cur.executemany("INSERT INTO reviews (product_id, author, body, created, sanitized) VALUES (?, ?, ?, ?, ?)", REVIEWS)
    conn.commit()
    conn.close()


if not DB_FILE.exists():
    seed_db()


# --------------------------------------------------------------------------- #
#  Security header state (for the Findings panel)                               #
# --------------------------------------------------------------------------- #
def headers_state() -> list[dict]:
    sec = MODE["value"] == "secured"
    return [
        {"name": "Content-Security-Policy", "value": "default-src 'self'; script-src 'nonce-…'", "ok": sec},
        {"name": "X-Content-Type-Options", "value": "nosniff", "ok": sec},
        {"name": "X-Frame-Options", "value": "DENY", "ok": sec},
        {"name": "Referrer-Policy", "value": "strict-origin-when-cross-origin", "ok": sec},
        {"name": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()", "ok": sec},
        {"name": "X-Powered-By", "value": "Flask (verbose stack disclosure)", "ok": not sec},
    ]


# --------------------------------------------------------------------------- #
#  Pages / meta                                                                 #
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    g.nonce = uuid.uuid4().hex + uuid.uuid4().hex
    return render_template("index.html", nonce=g.nonce, mode=MODE["value"])


@app.after_request
def security_headers(resp):
    """Secured Mode: full header set. Vulnerable Mode: intentionally none (F-06)."""
    if MODE["value"] == "secured":
        nonce = getattr(g, "nonce", None)
        if nonce:
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'nonce-" + nonce + "'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
            )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        for h in ("Server", "X-Powered-By"):
            try:
                del resp.headers[h]
            except Exception:
                pass
    else:
        resp.headers["X-Powered-By"] = "Flask/3.0 (verbose mode)"
        # deliberately NO CSP / X-Frame-Options / nosniff in Vulnerable Mode
    return resp


# --------------------------------------------------------------------------- #
#  API: mode switch                                                             #
# --------------------------------------------------------------------------- #
@app.post("/api/mode")
def api_mode():
    data = request.get_json(silent=True) or {}
    want = "secured" if str(data.get("mode", "")).lower() == "secured" else "vulnerable"
    prev = MODE["value"]
    MODE["value"] = want
    FAILED.clear()
    LOCKED.clear()
    if want != prev:
        if want == "secured":
            log_event("MODE", "SECURED MODE armed — parameterized queries, input validation, output encoding, 5-attempt rate limit, security headers", "ok")
            log_event("HDR", "Security headers applied: CSP(nonce), nosniff, X-Frame-Options: DENY, Referrer-Policy, Permissions-Policy", "ok")
        else:
            log_event("MODE", "VULNERABLE MODE armed — string-concatenated SQL, unencoded output, no rate limiting, no security headers", "pwn")
    return jsonify(ok=True, mode=want, headers=headers_state())


# --------------------------------------------------------------------------- #
#  API: login                                                                   #
# --------------------------------------------------------------------------- #
@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    user = str(data.get("username") or "").strip()
    pwd = str(data.get("password") or "")
    mode = MODE["value"]
    key = user.lower()
    LAST_USER["name"] = user

    # ---- Secured Mode: rate limiting -------------------------------------- #
    if mode == "secured":
        until = LOCKED.get(key, 0.0)
        if until > time.time():
            rem = int(until - time.time()) + 1
            log_event("RATE", f"Login rejected — account locked ({rem}s remaining after {MAX_ATTEMPTS} failed attempts)", "lock")
            return jsonify(ok=False, status="locked", attempts=MAX_ATTEMPTS, remaining=rem,
                           message=f"Account locked. Try again in {rem}s."), 423
        # ---- Secured Mode: input validation before the query --------------- #
        if is_sqli(user, strict=True) or is_sqli(pwd, strict=True):
            log_event("SQLI", "SQL injection attempt detected / blocked — payload rejected by input validation, parameterized query never needed", "blocked")
            return jsonify(ok=False, status="blocked", attempts=FAILED.get(key, 0), remaining=0,
                           message="Blocked: malicious pattern rejected by the validation layer."), 400

    conn = connect()
    try:
        if mode == "vulnerable":
            # F-01: classic string concatenation (intentional, demo only)
            sql = f"SELECT id, username, role FROM users WHERE username = '{user}' AND password = '{pwd}'"
            rows = conn.execute(sql).fetchall()
        else:
            sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
            rows = conn.execute(sql, (user, pwd)).fetchall()
    except Exception as exc:
        conn.close()
        if mode == "vulnerable":
            # F-05: verbose error disclosure
            log_event("SQLI", f"Query crashed and the raw database error was returned to the client — {exc}", "pwn")
            return jsonify(ok=False, status="error", message=f"Database error: {exc}"), 500
        log_event("AUTH", "Database error handled safely — generic response returned, details only in server log", "fail")
        return jsonify(ok=False, status="error", message="Unexpected server error. Please try again."), 500
    conn.close()

    if rows:
        name = rows[0]["username"]
        injected = mode == "vulnerable" and is_sqli(user + " " + pwd)
        if injected:
            log_event("SQLI", f"Attack succeeded — SQL injection bypassed authentication (logged in as '{name}' with no valid password)", "pwn")
            msg = f"AUTH BYPASS — you are '{name}' without knowing the password."
        else:
            log_event("AUTH", f"Login successful for '{name}' via {'string-concatenated query' if mode == 'vulnerable' else 'parameterized query'}", "ok")
            msg = f"Welcome back, {name}. Login verified."
        FAILED.pop(key, None)
        LOCKED.pop(key, None)
        return jsonify(ok=True, status="success", user=name, role=rows[0]["role"], injected=injected, message=msg)

    # ---- failed attempt ---------------------------------------------------- #
    if mode == "secured":
        n = FAILED.get(key, 0) + 1
        if n >= MAX_ATTEMPTS:
            FAILED[key] = 0
            LOCKED[key] = time.time() + LOCK_SECONDS
            log_event("RATE", f"Rate limit triggered — {MAX_ATTEMPTS} failed attempts, account locked for {LOCK_SECONDS}s", "lock")
            return jsonify(ok=False, status="locked", attempts=MAX_ATTEMPTS, remaining=LOCK_SECONDS,
                           message=f"Too many failed attempts. Account locked for {LOCK_SECONDS}s."), 423
        FAILED[key] = n
        left = MAX_ATTEMPTS - n
        log_event("AUTH", f"Login failed — invalid credentials ({n}/{MAX_ATTEMPTS} attempts, {left} left before lockout)", "fail")
        return jsonify(ok=False, status="fail", attempts=n, remaining=0,
                       message=f"Invalid credentials. {left} attempt(s) before lockout."), 401

    log_event("AUTH", "Login failed — invalid credentials (no rate limiting in Vulnerable Mode)", "fail")
    return jsonify(ok=False, status="fail", attempts=0, remaining=0,
                   message="Invalid username or password."), 401


# --------------------------------------------------------------------------- #
#  API: product search                                                          #
# --------------------------------------------------------------------------- #
@app.post("/api/search")
def api_search():
    data = request.get_json(silent=True) or {}
    q = str(data.get("query") or "").strip()
    mode = MODE["value"]

    if mode == "secured" and is_sqli(q):
        log_event("SQLI", "SQL injection attempt detected / blocked in product search — payload never reached the database", "blocked")
        return jsonify(ok=False, status="blocked", results=[],
                       message="Blocked: search input rejected by the validation layer.")

    conn = connect()
    try:
        if mode == "vulnerable":
            # F-02: search term concatenated straight into the LIKE clause
            sql = ("SELECT * FROM products WHERE name LIKE '%{q}%' "
                   "OR category LIKE '%{q}%' OR description LIKE '%{q}%'").format(q=q)
            rows = conn.execute(sql).fetchall()
        else:
            like = f"%{q}%"
            sql = ("SELECT * FROM products WHERE name LIKE ? OR category LIKE ? OR description LIKE ?")
            rows = conn.execute(sql, (like, like, like)).fetchall()
    except Exception as exc:
        conn.close()
        if mode == "vulnerable":
            log_event("SQLI", f"Injected probe broke the query — raw sqlite3 error leaked schema details: {exc}", "pwn")
            return jsonify(ok=False, status="error", results=[], message=f"Database error: {exc}"), 500
        log_event("SEARCH", "Query failed safely — generic error returned, no internals disclosed", "fail")
        return jsonify(ok=False, status="error", results=[], message="Search failed. Please refine your query."), 500
    conn.close()

    results = [dict(r) for r in rows]
    if mode == "vulnerable" and is_sqli(q):
        log_event("SQLI", f"Attack succeeded — injected condition dumped {len(results)} row(s) from the products table", "pwn")
        msg = f"Injected query returned {len(results)} rows — full catalog exposed."
    else:
        log_event("SEARCH", f"Search executed via {'string concatenation' if mode == 'vulnerable' else 'parameterized query'} — {len(results)} result(s)", "ok")
        msg = f"{len(results)} product(s) found."
    return jsonify(ok=True, status="ok", results=results, message=msg)


@app.get("/api/products")
def api_products():
    conn = connect()
    rows = conn.execute("SELECT * FROM products ORDER BY id").fetchall()
    conn.close()
    return jsonify(ok=True, results=[dict(r) for r in rows])


# --------------------------------------------------------------------------- #
#  API: reviews (XSS demo)                                                      #
# --------------------------------------------------------------------------- #
@app.get("/api/reviews")
def api_reviews():
    conn = connect()
    rows = conn.execute(
        "SELECT r.id, r.product_id, r.author, r.body, r.created, r.sanitized, p.name AS product "
        "FROM reviews r LEFT JOIN products p ON p.id = r.product_id ORDER BY r.id DESC"
    ).fetchall()
    conn.close()
    return jsonify(ok=True, results=[dict(r) for r in rows])


@app.post("/api/reviews")
def api_review():
    data = request.get_json(silent=True) or {}
    try:
        product_id = int(data.get("product_id") or 1)
    except (TypeError, ValueError):
        product_id = 1
    author = str(data.get("author") or "").strip()[:40] or "anonymous"
    body = str(data.get("body") or "").strip()
    if not body:
        return jsonify(ok=False, status="empty", message="Comment cannot be empty."), 400
    if len(body) > 500:
        return jsonify(ok=False, status="empty", message="Comment too long (max 500 chars)."), 400

    mode = MODE["value"]
    xss = is_xss(body)
    created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if mode == "secured":
        # F-03 fix: encode at the data layer + client renders with textContent
        stored, sanitized = html.escape(body, quote=True), (1 if xss else 0)
        if xss:
            log_event("XSS", "XSS attempt detected / blocked — payload HTML-encoded at the data layer, rendered via textContent (alert neutralized)", "blocked")
            msg = "Payload neutralised: stored in encoded form, displayed as harmless text."
        else:
            log_event("REVIEW", "Review accepted — validated, encoded and stored safely", "ok")
            msg = "Review published safely."
    else:
        # F-03: stored raw, rendered with innerHTML in the browser
        stored, sanitized = body, 0
        if xss:
            log_event("XSS", "Attack succeeded — stored XSS payload persisted; it executes for every user who views this review", "pwn")
            msg = "Review published! The payload executes as soon as it renders."
        else:
            log_event("REVIEW", "Review published — stored and rendered with no output encoding", "ok")
            msg = "Review published."

    conn = connect()
    cur = conn.execute(
        "INSERT INTO reviews (product_id, author, body, created, sanitized) VALUES (?, ?, ?, ?, ?)",
        (product_id, author, stored, created, sanitized),
    )
    conn.commit()
    rid = cur.lastrowid
    pname = conn.execute("SELECT name FROM products WHERE id = ?", (product_id,)).fetchone()
    conn.close()
    return jsonify(ok=True, status="ok", message=msg, review={
        "id": rid, "product_id": product_id, "product": (pname["name"] if pname else "Unknown"),
        "author": author, "body": stored, "created": created, "sanitized": sanitized,
    })


# --------------------------------------------------------------------------- #
#  API: log / state / reset                                                     #
# --------------------------------------------------------------------------- #
@app.get("/api/log")
def api_log():
    since = request.args.get("since", 0, type=int)
    with LOCK:
        entries = [e for e in LOG if e["id"] > since]
        total = SEQ["id"]
    return jsonify(entries=entries, total=total, mode=MODE["value"])


@app.get("/api/state")
def api_state():
    user = (request.args.get("user") or LAST_USER["name"] or "").strip().lower()
    until = LOCKED.get(user, 0.0)
    now = time.time()
    locked = until > now
    return jsonify(
        mode=MODE["value"],
        headers=headers_state(),
        rate={
            "armed": MODE["value"] == "secured",
            "user": user,
            "attempts": FAILED.get(user, 0) if not locked else MAX_ATTEMPTS,
            "max": MAX_ATTEMPTS,
            "locked": locked,
            "remaining": int(until - now) + 1 if locked else 0,
        },
    )


@app.post("/api/reset")
def api_reset():
    FAILED.clear()
    LOCKED.clear()
    with LOCK:
        LOG.clear()
    seed_db()
    log_event("SYS", "Demo reset — database reseeded, counters cleared, log wiped", "ok")
    return jsonify(ok=True, mode=MODE["value"])


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print()
    print("=" * 68)
    print("  SHOPSECURE — pre-launch penetration test demo (local only)")
    print(f"  http://127.0.0.1:{port}")
    print("  demo creds : admin / admin123")
    print("  SQLi payload : ' OR '1'='1' --")
    print("  XSS payload  : <img src=x onerror=\"alert('XSS Demo!')\">")
    print("=" * 68)
    print()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
