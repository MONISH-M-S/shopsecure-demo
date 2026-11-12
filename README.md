# ShopSecure — Pre-Launch Penetration Test for an E-Commerce Site

Case study demo · **Unit: Implementing Security Defenses**

A fictional e-commerce store with **one switch and two security postures** — run the same
attack in *Vulnerable Mode* (red) and watch it succeed, then flip to *Secured Mode* (green)
and watch every payload get blocked.

**▶ Live demo (no install):** https://monish-m-s.github.io/shopsecure-demo/
**▶ Repo:** https://github.com/MONISH-M-S/shopsecure-demo

## Run locally (Flask + SQLite — the assignment deliverable)

```bash
pip install flask
python app.py
# open http://127.0.0.1:5000
```

Demo credentials: `admin` / `admin123`

## Demo payloads

| Feature | Type this | Vulnerable Mode | Secured Mode |
|---|---|---|---|
| Login → username | `' OR '1'='1' --` | Logs you in as `admin` | Blocked by validation |
| Search box | `' OR '1'='1' --` | Dumps all 12 products | Blocked, 0 results |
| Search box | `'` | Raw DB error leaks schema | Generic error |
| Review comment | `<img src=x onerror="alert('XSS Demo!')">` | Alert popup fires | Literal text + `SANITIZED` badge |
| Login → password | 5 wrong attempts | Never locks | Locked 60 s (live countdown) |

Flip the big switch after each attack — the **Live Attack Log** turns from red
`ATTACK SUCCEEDED` to green `BLOCKED`, and every badge in **Findings** flips `FAIL → PASS`.

## What's inside

```
app.py                 Flask backend — vulnerable & secured code paths, attack log, SQLite
templates/index.html   Single-page UI (dark cyberpunk theme, matrix background, animations)
docs/                  Static build for GitHub Pages: same UI + SQLite compiled to WebAssembly
presentation/          (local only) slide deck .pptx, report .docx, website QR .png
```

**Findings:** F-01 SQLi login (Critical 9.8) · F-02 SQLi search (High 8.6) · F-03 Stored XSS
(High 8.1) · F-04 No rate limiting (Medium 6.5) · F-05 Verbose errors (Medium 5.3) ·
F-06 Missing headers (Low 3.7) — all retest **PASS** in Secured Mode.

---

*Local classroom exercise only. Fake data, toy database — never test systems you don't own.*
