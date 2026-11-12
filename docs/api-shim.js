/* ShopSecure static backend — the same API as app.py, running entirely in the
   browser against a real SQLite database compiled to WebAssembly (sql.js).
   Loaded before the main app script; intercepts fetch("/api/...").
   Used by the GitHub Pages build (docs/). */
(function () {
  "use strict";

  var realFetch = window.fetch.bind(window);
  var SQL = null, db = null;

  var MODE = { value: "vulnerable" };
  var LOG = [], SEQ = { id: 0 };
  var FAILED = {}, LOCKED = {};
  var LAST_USER = { name: "" };
  var MAX_ATTEMPTS = 5, LOCK_SECONDS = 60;

  /* ------------------------------ toy data ------------------------------ */
  var USERS = [
    ["admin", "admin123", "administrator"],
    ["maya", "neonlife", "customer"],
    ["guest", "guest", "customer"]
  ];
  var PRODUCTS = [
    ["Neon Flux Hoodie", "Apparel", 59.99, "Reflective-strike hoodie with thermal lining and taped seams.", 4.6],
    ["Cyber Runner Sneakers", "Footwear", 89.0, "Lightweight runners with reactive gel heel and glow trim.", 4.4],
    ["Holo Visor Sunglasses", "Accessories", 24.5, "Polarized wrap-around visor with mirror finish.", 4.1],
    ["Quantum Mechanical Keyboard", "Electronics", 119.0, "Hot-swappable switches, per-key RGB, aluminium deck.", 4.8],
    ["Pulse Wireless Mouse", "Electronics", 39.99, "26K DPI sensor, 70h battery, silent clicks.", 4.5],
    ["Grid Runner Backpack", "Accessories", 74.0, "22L commuter pack with laptop sleeve and rain cover.", 4.7],
    ["Plasma Desk Lamp", "Home", 45.0, "Stepless dimming, USB-C power, colour temperature memory.", 4.2],
    ["Static Denim Jacket", "Apparel", 95.0, "Washed denim with embroidered glitch motif on the back.", 4.3],
    ["Echo Noise-Cancel Headphones", "Electronics", 149.0, "Hybrid ANC, 40h battery, multipoint Bluetooth.", 4.9],
    ["Vector Water Bottle", "Home", 19.99, "750ml insulated steel bottle, keeps cold 24h.", 4.0],
    ["Glitch Print T-Shirt", "Apparel", 29.0, "Heavyweight cotton with discharge-printed glitch art.", 4.5],
    ["Hexagon Leather Wallet", "Accessories", 34.0, "Slim bifold with RFID-blocking lining.", 4.2]
  ];
  var REVIEWS = [
    [1, "Maya", "Fits great and the reflective strips actually work at night. 5/5.", "2026-11-01 18:22:10", 0],
    [9, "Dmitri", "Battery lasts forever and the ANC kills the train noise completely.", "2026-11-02 09:14:55", 0],
    [2, "Sam", "True to size, comfy for city walking. Order half size up if wide feet.", "2026-11-03 21:47:31", 0]
  ];

  /* ---------------------------- detection ------------------------------- */
  var SQLI = /('|"|;|--|\/\*|union[\s/]+select|select[\s/]+from|drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|alter\s+table|exec(ute)?\s|sleep\s*\(|benchmark\s*\(|or\s+'?1'?\s*=\s*'?1'?|or\s+1\s*=\s*1|and\s+1\s*=\s*1|information_schema)/i;
  var STRICT = /['";]/;
  var XSS = /<\s*\/?\s*[a-z!]|javascript:|on[a-z]+\s*=|&#x|data:text\/html/i;

  function isSqli(t, strict) { t = t || ""; return SQLI.test(t) || (!!strict && STRICT.test(t)); }
  function isXss(t) { return XSS.test(t || ""); }
  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
  }

  function logEvent(kind, message, status) {
    SEQ.id++;
    LOG.push({ id: SEQ.id, ts: Date.now() / 1000, mode: MODE.value, kind: kind,
               message: message, status: status || "ok" });
    if (LOG.length > 300) LOG.splice(0, LOG.length - 300);
  }

  /* ------------------------------ database ------------------------------ */
  function seed() {
    if (db) { try { db.close(); } catch (e) {} }
    db = new SQL.Database();
    db.run(
      "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);" +
      "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL, description TEXT, rating REAL);" +
      "CREATE TABLE reviews (id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT, created TEXT, sanitized INTEGER DEFAULT 0);"
    );
    var i;
    for (i = 0; i < PRODUCTS.length; i++)
      db.run("INSERT INTO products (name, category, price, description, rating) VALUES (?,?,?,?,?)", PRODUCTS[i]);
    for (i = 0; i < USERS.length; i++)
      db.run("INSERT INTO users (username, password, role) VALUES (?,?,?)", USERS[i]);
    for (i = 0; i < REVIEWS.length; i++)
      db.run("INSERT INTO reviews (product_id, author, body, created, sanitized) VALUES (?,?,?,?,?)", REVIEWS[i]);
  }

  function q(sql, params) {
    var stmt = db.prepare(sql);
    if (params) stmt.bind(params);
    var rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  }
  function lastId() {
    var r = db.exec("SELECT last_insert_rowid()");
    return r.length ? r[0].values[0][0] : 0;
  }

  /* ------------------------- response helpers --------------------------- */
  function json(data, status) {
    return new Response(JSON.stringify(data === undefined ? {} : data), {
      status: status || 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  /* Static hosting cannot set response headers; CSP / nosniff / XFO etc. are
     applied by the Flask backend (app.py). Shown honestly here. */
  function headersState() {
    return [
      { name: "Content-Security-Policy", value: "not set — static hosting (Flask build uses nonce CSP)", ok: false },
      { name: "X-Content-Type-Options", value: "not set — static hosting (Flask build sends nosniff)", ok: false },
      { name: "X-Frame-Options", value: "not set — static hosting (Flask build sends DENY)", ok: false },
      { name: "Referrer-Policy", value: "not set — static hosting (Flask build: strict-origin-when-cross-origin)", ok: false },
      { name: "Permissions-Policy", value: "not set — static hosting (Flask build: camera=(), mic=(), geo=())", ok: false },
      { name: "X-Powered-By", value: "absent — no server stack disclosed", ok: true }
    ];
  }

  /* ------------------------------ handlers ------------------------------ */
  function handle(url, init) {
    var path = url.split("?")[0];
    var qs = new URLSearchParams(url.split("?")[1] || "");
    var body = null;
    try { body = init && init.body ? JSON.parse(init.body) : null; } catch (e) { body = null; }

    return ready.then(function () {
      switch (path) {

        /* ---------------------------------------------------------- mode */
        case "/api/mode": {
          var want = body && String(body.mode).toLowerCase() === "secured" ? "secured" : "vulnerable";
          var prev = MODE.value;
          MODE.value = want;
          FAILED = {}; LOCKED = {};
          if (want !== prev) {
            if (want === "secured") {
              logEvent("MODE", "SECURED MODE armed — parameterized queries, input validation, output encoding, 5-attempt rate limit", "ok");
              logEvent("HDR", "Security headers are applied by the Flask build of this demo (CSP nonce, nosniff, DENY, Referrer-Policy)", "ok");
            } else {
              logEvent("MODE", "VULNERABLE MODE armed — string-concatenated SQL, unencoded output, no rate limiting", "pwn");
            }
          }
          return json({ ok: true, mode: want, headers: headersState() });
        }

        /* ---------------------------------------------------------- login */
        case "/api/login": {
          var user = String((body && body.username) || "").trim();
          var pwd = String((body && body.password) || "");
          var mode = MODE.value;
          var key = user.toLowerCase();
          LAST_USER.name = user;

          if (mode === "secured") {
            var until = LOCKED[key] || 0;
            if (until > Date.now() / 1000) {
              var rem = Math.ceil(until - Date.now() / 1000);
              logEvent("RATE", "Login rejected — account locked (" + rem + "s remaining after " + MAX_ATTEMPTS + " failed attempts)", "lock");
              return json({ ok: false, status: "locked", attempts: MAX_ATTEMPTS, remaining: rem,
                            message: "Account locked. Try again in " + rem + "s." }, 423);
            }
            if (isSqli(user, true) || isSqli(pwd, true)) {
              logEvent("SQLI", "SQL injection attempt detected / blocked — payload rejected by input validation, parameterized query never needed", "blocked");
              return json({ ok: false, status: "blocked", attempts: FAILED[key] || 0, remaining: 0,
                            message: "Blocked: malicious pattern rejected by the validation layer." }, 400);
            }
          }

          var rows;
          try {
            if (mode === "vulnerable") {
              rows = q("SELECT id, username, role FROM users WHERE username = '" + user + "' AND password = '" + pwd + "'");
            } else {
              rows = q("SELECT id, username, role FROM users WHERE username = ? AND password = ?", [user, pwd]);
            }
          } catch (err) {
            if (mode === "vulnerable") {
              logEvent("SQLI", "Query crashed and the raw database error was returned to the client — " + err.message, "pwn");
              return json({ ok: false, status: "error", message: "Database error: " + err.message }, 500);
            }
            logEvent("AUTH", "Database error handled safely — generic response returned, details only in the log", "fail");
            return json({ ok: false, status: "error", message: "Unexpected server error. Please try again." }, 500);
          }

          if (rows.length) {
            var name = rows[0].username;
            var injected = mode === "vulnerable" && isSqli(user + " " + pwd);
            if (injected) {
              logEvent("SQLI", "Attack succeeded — SQL injection bypassed authentication (logged in as '" + name + "' with no valid password)", "pwn");
              return json({ ok: true, status: "success", user: name, role: rows[0].role, injected: true,
                            message: "AUTH BYPASS — you are '" + name + "' without knowing the password." });
            }
            logEvent("AUTH", "Login successful for '" + name + "' via " + (mode === "vulnerable" ? "string-concatenated query" : "parameterized query"), "ok");
            delete FAILED[key]; delete LOCKED[key];
            return json({ ok: true, status: "success", user: name, role: rows[0].role, injected: false,
                          message: "Welcome back, " + name + ". Login verified." });
          }

          if (mode === "secured") {
            var n = (FAILED[key] || 0) + 1;
            if (n >= MAX_ATTEMPTS) {
              FAILED[key] = 0;
              LOCKED[key] = Date.now() / 1000 + LOCK_SECONDS;
              logEvent("RATE", "Rate limit triggered — " + MAX_ATTEMPTS + " failed attempts, account locked for " + LOCK_SECONDS + "s", "lock");
              return json({ ok: false, status: "locked", attempts: MAX_ATTEMPTS, remaining: LOCK_SECONDS,
                            message: "Too many failed attempts. Account locked for " + LOCK_SECONDS + "s." }, 423);
            }
            FAILED[key] = n;
            var left = MAX_ATTEMPTS - n;
            logEvent("AUTH", "Login failed — invalid credentials (" + n + "/" + MAX_ATTEMPTS + " attempts, " + left + " left before lockout)", "fail");
            return json({ ok: false, status: "fail", attempts: n, remaining: 0,
                          message: "Invalid credentials. " + left + " attempt(s) before lockout." }, 401);
          }

          logEvent("AUTH", "Login failed — invalid credentials (no rate limiting in Vulnerable Mode)", "fail");
          return json({ ok: false, status: "fail", attempts: 0, remaining: 0,
                        message: "Invalid username or password." }, 401);
        }

        /* --------------------------------------------------------- search */
        case "/api/search": {
          var sq = String((body && body.query) || "").trim();
          var smode = MODE.value;

          if (smode === "secured" && isSqli(sq)) {
            logEvent("SQLI", "SQL injection attempt detected / blocked in product search — payload never reached the database", "blocked");
            return json({ ok: false, status: "blocked", results: [],
                          message: "Blocked: search input rejected by the validation layer." }, 400);
          }

          var srows;
          try {
            if (smode === "vulnerable") {
              srows = q("SELECT * FROM products WHERE name LIKE '%" + sq + "%' OR category LIKE '%" + sq + "%' OR description LIKE '%" + sq + "%'");
            } else {
              var like = "%" + sq + "%";
              srows = q("SELECT * FROM products WHERE name LIKE ? OR category LIKE ? OR description LIKE ?", [like, like, like]);
            }
          } catch (err2) {
            if (smode === "vulnerable") {
              logEvent("SQLI", "Injected probe broke the query — raw error leaked schema details: " + err2.message, "pwn");
              return json({ ok: false, status: "error", results: [], message: "Database error: " + err2.message }, 500);
            }
            logEvent("SEARCH", "Query failed safely — generic error returned, no internals disclosed", "fail");
            return json({ ok: false, status: "error", results: [], message: "Search failed. Please refine your query." }, 500);
          }

          if (smode === "vulnerable" && isSqli(sq)) {
            logEvent("SQLI", "Attack succeeded — injected condition dumped " + srows.length + " row(s) from the products table", "pwn");
            return json({ ok: true, status: "ok", results: srows,
                          message: "Injected query returned " + srows.length + " rows — full catalog exposed." });
          }
          logEvent("SEARCH", "Search executed via " + (smode === "vulnerable" ? "string concatenation" : "parameterized query") + " — " + srows.length + " result(s)", "ok");
          return json({ ok: true, status: "ok", results: srows, message: srows.length + " product(s) found." });
        }

        /* ------------------------------------------------------- products */
        case "/api/products":
          return json({ ok: true, results: q("SELECT * FROM products ORDER BY id") });

        /* -------------------------------------------------------- reviews */
        case "/api/reviews":
          if (init && init.method === "POST") {
            var pid = parseInt((body && body.product_id) || 1, 10) || 1;
            var author = String((body && body.author) || "").trim().slice(0, 40) || "anonymous";
            var cbody = String((body && body.body) || "").trim();
            if (!cbody) return json({ ok: false, status: "empty", message: "Comment cannot be empty." }, 400);
            if (cbody.length > 500) return json({ ok: false, status: "empty", message: "Comment too long (max 500 chars)." }, 400);

            var rmode = MODE.value;
            var xss = isXss(cbody);
            var created = new Date().toISOString().slice(0, 19).replace("T", " ");
            var stored, sanitized, rmsg;

            if (rmode === "secured") {
              stored = esc(cbody);
              sanitized = xss ? 1 : 0;
              if (xss) {
                logEvent("XSS", "XSS attempt detected / blocked — payload HTML-encoded at the data layer, rendered via textContent (alert neutralized)", "blocked");
                rmsg = "Payload neutralised: stored in encoded form, displayed as harmless text.";
              } else {
                logEvent("REVIEW", "Review accepted — validated, encoded and stored safely", "ok");
                rmsg = "Review published safely.";
              }
            } else {
              stored = cbody; sanitized = 0;
              if (xss) {
                logEvent("XSS", "Attack succeeded — stored XSS payload persisted; it executes for every user who views this review", "pwn");
                rmsg = "Review published! The payload executes as soon as it renders.";
              } else {
                logEvent("REVIEW", "Review published — stored and rendered with no output encoding", "ok");
                rmsg = "Review published.";
              }
            }

            db.run("INSERT INTO reviews (product_id, author, body, created, sanitized) VALUES (?,?,?,?,?)",
                   [pid, author, stored, created, sanitized]);
            var rid = lastId();
            var prow = q("SELECT name FROM products WHERE id = ?", [pid]);
            return json({ ok: true, status: "ok", message: rmsg, review: {
              id: rid, product_id: pid, product: prow.length ? prow[0].name : "Unknown",
              author: author, body: stored, created: created, sanitized: sanitized } });
          }
          return json({ ok: true, results: q(
            "SELECT r.id, r.product_id, r.author, r.body, r.created, r.sanitized, p.name AS product " +
            "FROM reviews r LEFT JOIN products p ON p.id = r.product_id ORDER BY r.id DESC") });

        /* ------------------------------------------------------------ log */
        case "/api/log": {
          var since = parseInt(qs.get("since") || "0", 10) || 0;
          var entries = LOG.filter(function (e) { return e.id > since; });
          return json({ entries: entries, total: SEQ.id, mode: MODE.value });
        }

        /* ----------------------------------------------------------- state */
        case "/api/state": {
          var suser = (qs.get("user") || LAST_USER.name || "").trim().toLowerCase();
          var suntil = LOCKED[suser] || 0;
          var locked = suntil > Date.now() / 1000;
          return json({
            mode: MODE.value,
            headers: headersState(),
            rate: {
              armed: MODE.value === "secured",
              user: suser,
              attempts: locked ? MAX_ATTEMPTS : (FAILED[suser] || 0),
              max: MAX_ATTEMPTS,
              locked: locked,
              remaining: locked ? Math.ceil(suntil - Date.now() / 1000) : 0
            }
          });
        }

        /* ----------------------------------------------------------- reset */
        case "/api/reset":
          FAILED = {}; LOCKED = {};
          LOG = [];
          seed();
          logEvent("SYS", "Demo reset — database reseeded, counters cleared, log wiped", "ok");
          return json({ ok: true, mode: MODE.value });

        default:
          return json({ ok: false, status: "error", message: "Unknown endpoint: " + path }, 404);
      }
    }).catch(function (e) {
      return json({ ok: false, status: "error", message: "Backend error: " + (e && e.message) }, 500);
    });
  }

  /* ------------------------- fetch interception -------------------------- */
  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || "";
    if (url.indexOf("/api/") !== -1) return handle(url, init);
    return realFetch(input, init);
  };

  /* ------------------------------- boot --------------------------------- */
  var ready = (typeof window.initSqlJs === "function"
      ? window.initSqlJs({ locateFile: function (f) { return "vendor/" + f; } })
      : Promise.reject(new Error("sql.js failed to load"))
    ).then(function (S) { SQL = S; seed(); return true; });

  ready.catch(function (e) {
    console.error("ShopSecure static backend failed to start:", e);
  });
})();
