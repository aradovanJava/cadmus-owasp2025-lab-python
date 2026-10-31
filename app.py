"""
============================================================================
 OWASP Top 10:2025 — Deliberately Vulnerable Python Web Application
 CADMUS-CR-15 · Secure Coding (Python) · Teaching lab for module N1 and CR1-CR4
============================================================================

 ⚠  SECURITY WARNING — READ BEFORE RUNNING  ⚠
 This application is INTENTIONALLY INSECURE. It exists only to teach how to
 find and fix vulnerabilities. Every route below contains a flaw on purpose.

   • Run it ONLY on an isolated / offline lab machine or VM.
   • It binds to 127.0.0.1 by default — do NOT expose it to any network.
   • NEVER deploy it, put it on the internet, or run it with real data.
   • Delete the SQLite file (owasp_lab.db) between sessions to reset state.

 Each vulnerable handler is tagged  # [VULNERABLE A0X:2025 ...]  and is paired
 with a  # [SECURE FIX]  comment showing the remediation. The secure versions
 are collected in secure_reference.py and shown on each page in the UI.

 Target: Python 3.11+ (tested on 3.12; compatible with 3.14).
============================================================================
"""

import hashlib
import os
import pickle          # used to demonstrate insecure deserialization (A08)
import base64
import sqlite3
import subprocess
import logging
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, render_template_string, g, Response, abort,
)

# Optional dependency, used only by the SSRF demo (A01). The app still starts
# without it; the fetch demo will explain if it is missing.
try:
    import requests
except Exception:                       # pragma: no cover
    requests = None

DB_PATH = os.path.join(os.path.dirname(__file__), "owasp_lab.db")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# [VULNERABLE A04:2025 Cryptographic Failures] Hard-coded, weak secret key
#   committed to source. Anyone with the code can forge session cookies.
# [VULNERABLE A02:2025 Security Misconfiguration] Debug mode is enabled at the
#   bottom of this file, exposing the interactive Werkzeug debugger (RCE).
# [SECURE FIX] Load the key from an environment variable / secrets manager and
#   never enable debug outside local development:
#       app.secret_key = os.environ["APP_SECRET_KEY"]
# ---------------------------------------------------------------------------
app.secret_key = "dev-secret-please-change-123"   # noqa: hard-coded on purpose

# [VULNERABLE A09:2025 Security Logging & Alerting Failures]
#   Logging is configured to CRITICAL only, so failed logins, access-control
#   violations, and other security events are never recorded. There is also no
#   alerting anywhere in the app.
# [SECURE FIX] Log security-relevant events at INFO/WARNING to a protected sink
#   and forward to a SIEM with alerting. Never log secrets or full card/PII.
logging.basicConfig(level=logging.CRITICAL)
log = logging.getLogger("owasp_lab")


# ===========================================================================
# Database helpers + seed data
# ===========================================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def md5(text: str) -> str:
    # [VULNERABLE A04:2025] MD5 is fast, unsalted and broken for passwords.
    # [SECURE FIX] Use a slow, salted algorithm: argon2id (argon2-cffi) or bcrypt.
    return hashlib.md5(text.encode()).hexdigest()


def init_db():
    """Create and seed the demo database (idempotent)."""
    first_time = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,          -- stored as weak MD5 (A04)
            role     TEXT,
            balance  INTEGER,
            api_key  TEXT,
            ssn      TEXT           -- sensitive data, stored in the clear (A04)
        );
        CREATE TABLE IF NOT EXISTS products (
            id    INTEGER PRIMARY KEY,
            name  TEXT,
            price INTEGER
        );
        CREATE TABLE IF NOT EXISTS notes (
            id     INTEGER PRIMARY KEY,
            author TEXT,
            body   TEXT              -- rendered without escaping (stored XSS, A05)
        );
        """
    )
    if first_time:
        # [VULNERABLE A02:2025] Ships with well-known default credentials.
        # [VULNERABLE A07:2025] Trivial passwords, no complexity policy.
        db.executemany(
            "INSERT INTO users (username, password, role, balance, api_key, ssn) "
            "VALUES (?,?,?,?,?,?)",
            [
                ("admin", md5("admin"), "admin", 100000, "AK-ADMIN-0001", "111-11-1111"),
                ("alice", md5("password1"), "user", 500, "AK-ALICE-7421", "222-22-2222"),
                ("bob",   md5("qwerty"),    "user", 750, "AK-BOB-3310",   "333-33-3333"),
            ],
        )
        db.executemany(
            "INSERT INTO products (name, price) VALUES (?,?)",
            [("Keyboard", 40), ("Monitor", 180), ("Webcam", 65), ("USB-C Hub", 30)],
        )
        db.execute(
            "INSERT INTO notes (author, body) VALUES (?,?)",
            ("system", "Welcome to the notes board. Try posting a note!"),
        )
    db.commit()
    db.close()


def current_user():
    if "user_id" not in session:
        return None
    row = get_db().execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    return row


# ===========================================================================
# CATALOG — metadata, code excerpts, and demo form specs for each category.
# Rendered by templates/category.html so every page has the same structure:
#   description → live demo → vulnerable code → secure fix → mapping.
# ===========================================================================
CATALOG = {
    "a01": {
        "code": "A01:2025",
        "name": "Broken Access Control",
        "tag": "Includes SSRF in 2025",
        "owasp": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
        "mitre": "T1190 Exploit Public-Facing Application",
        "blurb": "Authentication answers \"who are you\"; authorization answers "
                 "\"are you allowed\". This app checks the first and forgets the "
                 "second. Two demos: an IDOR (read any profile by id) and an "
                 "unprotected admin page. SSRF now lives in this category too.",
        "root_cause": "Access decisions are missing or made on the client side; "
                      "the server trusts the id in the URL.",
        "control": "Deny by default; enforce object-level authorization on the "
                   "server for every request; never rely on hidden UI.",
        "forms": [
            {"action": "/a01/profile", "label": "View profile by id (try 1 = admin)",
             "fields": [{"name": "uid", "placeholder": "e.g. 1", "value": "1"}],
             "submit": "Open profile"},
            {"action": "/a01/fetch", "label": "URL preview fetcher (SSRF) — try an internal address",
             "fields": [{"name": "url", "placeholder": "http://127.0.0.1:5000/admin",
                         "value": "http://127.0.0.1:5000/"}],
             "submit": "Fetch"},
        ],
    },
    "a02": {
        "code": "A02:2025",
        "name": "Security Misconfiguration",
        "tag": "Up from #5 in 2021",
        "owasp": "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
        "mitre": "T1592 Gather Victim Host Information",
        "blurb": "Everything was built correctly but wired up wrong: debug mode "
                 "on, default admin/admin credentials, no security headers, and "
                 "a config endpoint that leaks secrets.",
        "root_cause": "Insecure defaults are shipped and never hardened for "
                      "production.",
        "control": "Harden by default, remove defaults, add security headers, "
                   "keep debug off, and audit configuration in CI.",
        "forms": [
            {"action": "/a02/config", "label": "Exposed debug/config endpoint",
             "fields": [], "submit": "Show app config"},
        ],
    },
    "a03": {
        "code": "A03:2025",
        "name": "Software Supply Chain Failures",
        "tag": "NEW in 2025",
        "owasp": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
        "mitre": "T1195 Supply Chain Compromise",
        "blurb": "Risk you inherit from your dependencies. requirements-vulnerable.txt "
                 "pins several outdated packages with known CVEs. Scan it with "
                 "pip-audit or Snyk, and generate an SBOM (CycloneDX/SPDX).",
        "root_cause": "Unpinned / outdated / unverified third-party components and "
                      "no visibility into the dependency tree.",
        "control": "Pin and verify dependencies, generate and review an SBOM, run "
                   "SCA in CI, and patch on a schedule.",
        "forms": [
            {"action": "/a03/audit", "label": "Simulated SCA report for the pinned manifest",
             "fields": [], "submit": "Run mock dependency audit"},
        ],
    },
    "a04": {
        "code": "A04:2025",
        "name": "Cryptographic Failures",
        "tag": "",
        "owasp": "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
        "mitre": "T1552 Unsecured Credentials",
        "blurb": "Passwords are stored as unsalted MD5, the secret key is "
                 "hard-coded, and sensitive data (SSNs, API keys) sits in the "
                 "clear. This page dumps the password table to prove it.",
        "root_cause": "Weak/again-fast hashing, hard-coded keys, and sensitive "
                      "data stored or transmitted without protection.",
        "control": "argon2id/bcrypt for passwords, secrets from a manager, TLS "
                   "everywhere, encrypt sensitive data at rest.",
        "forms": [
            {"action": "/a04/dump", "label": "Show how credentials are stored",
             "fields": [], "submit": "Reveal stored passwords"},
        ],
    },
    "a05": {
        "code": "A05:2025",
        "name": "Injection",
        "tag": "",
        "owasp": "https://owasp.org/Top10/2025/A05_2025-Injection/",
        "mitre": "T1059 Command and Scripting Interpreter",
        "blurb": "Untrusted input reaches an interpreter. Three demos: SQL "
                 "injection in product search, OS command injection in a host "
                 "checker, and reflected XSS in a greeting.",
        "root_cause": "Code and data share one channel; input is concatenated "
                      "into a query, a shell command, or HTML.",
        "control": "Parameterized queries, safe process APIs (no shell), and "
                   "context-aware output encoding / auto-escaping.",
        "forms": [
            {"action": "/a05/search", "label": "Product search (SQLi) — try:  ' OR '1'='1",
             "fields": [{"name": "q", "placeholder": "Keyboard", "value": "Keyboard"}],
             "submit": "Search"},
            {"action": "/a05/ping", "label": "Host checker (command injection) — try:  localhost; echo PWNED",
             "fields": [{"name": "host", "placeholder": "localhost", "value": "localhost"}],
             "submit": "Check host"},
            {"action": "/a05/greet", "label": "Greeting (reflected XSS) — try:  <script>alert(1)</script>",
             "fields": [{"name": "name", "placeholder": "your name", "value": "student"}],
             "submit": "Greet me"},
        ],
    },
    "a06": {
        "code": "A06:2025",
        "name": "Insecure Design",
        "tag": "",
        "owasp": "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
        "mitre": "T1565 Data Manipulation",
        "blurb": "A flaw in what the system was designed to do. The money-transfer "
                 "feature never considered negative amounts, so you can transfer "
                 "a negative sum to steal from another account.",
        "root_cause": "Missing threat modelling and business-rule validation at "
                      "design time — the abuse case was never considered.",
        "control": "Threat-model early, define and enforce business rules "
                   "server-side, add abuse-case tests.",
        "forms": [
            {"action": "/a06/transfer", "label": "Transfer funds — try a negative amount",
             "fields": [{"name": "to", "placeholder": "bob", "value": "bob"},
                        {"name": "amount", "placeholder": "-500", "value": "-500"}],
             "submit": "Transfer"},
        ],
    },
    "a07": {
        "code": "A07:2025",
        "name": "Authentication Failures",
        "tag": "",
        "owasp": "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
        "mitre": "T1110 Brute Force",
        "blurb": "Login has no rate limiting or lockout (brute-force friendly), "
                 "and the \"remember me\" token is just md5(username) — trivially "
                 "forgeable. Generate a token for any user below.",
        "root_cause": "Predictable tokens, no anti-automation, weak password "
                      "and session handling.",
        "control": "MFA, account lockout / rate limiting, and cryptographically "
                   "random, server-side session identifiers.",
        "forms": [
            {"action": "/a07/token", "label": "Forge a 'remember me' token for any user",
             "fields": [{"name": "username", "placeholder": "admin", "value": "admin"}],
             "submit": "Generate token"},
        ],
    },
    "a08": {
        "code": "A08:2025",
        "name": "Software or Data Integrity Failures",
        "tag": "",
        "owasp": "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
        "mitre": "T1195.002 Compromise Software Supply Chain",
        "blurb": "The \"restore session\" feature deserializes a pickle blob from "
                 "the user with no integrity check — arbitrary code execution. A "
                 "safe sample blob is provided; never paste an untrusted one.",
        "root_cause": "Deserializing untrusted data with a dangerous format "
                      "(pickle) and no signature/integrity verification.",
        "control": "Avoid native deserialization of untrusted input; use JSON; "
                   "verify signatures / integrity on any data or update.",
        "forms": [
            {"action": "/a08/restore", "label": "Restore session from a pickle blob (base64)",
             "fields": [{"name": "blob", "placeholder": "base64 pickle", "value": "SAMPLE"}],
             "submit": "Restore"},
        ],
    },
    "a09": {
        "code": "A09:2025",
        "name": "Security Logging & Alerting Failures",
        "tag": "Renamed in 2025",
        "owasp": "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
        "mitre": "T1070 Indicator Removal",
        "blurb": "Failed logins and access-control violations are never logged, so "
                 "an attack leaves no trace and triggers no alert. This page shows "
                 "the (empty) security log.",
        "root_cause": "Security events are not recorded, are unmonitored, or the "
                      "logs capture sensitive data instead of useful signals.",
        "control": "Log auth and access-control events to a protected store, "
                   "monitor, and alert — without logging secrets/PII.",
        "forms": [
            {"action": "/a09/log", "label": "Show the security event log",
             "fields": [], "submit": "View security log"},
        ],
    },
    "a10": {
        "code": "A10:2025",
        "name": "Mishandling of Exceptional Conditions",
        "tag": "NEW in 2025",
        "owasp": "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
        "mitre": "T1211 Exploitation for Defense Evasion",
        "blurb": "Two anti-patterns: an endpoint that leaks a full stack trace to "
                 "the user (info disclosure), and an auth check that \"fails open\" "
                 "— granting access when an error occurs.",
        "root_cause": "Errors are swallowed, leaked verbatim, or handled by "
                      "defaulting to the insecure/allow path.",
        "control": "Fail closed, return generic errors to users, send detail to "
                   "secure logs, and handle exceptions deliberately.",
        "forms": [
            {"action": "/a10/divide", "label": "Divide (leaks a stack trace on error) — set divisor to 0",
             "fields": [{"name": "a", "value": "10"}, {"name": "b", "value": "0"}],
             "submit": "Divide"},
            {"action": "/a10/secure-area", "label": "Access a 'secure' area that fails open on error",
             "fields": [{"name": "token", "placeholder": "(leave blank to trigger the error)", "value": ""}],
             "submit": "Enter secure area"},
        ],
    },
}


# ===========================================================================
# Home / dashboard + generic category renderer
# ===========================================================================
@app.route("/")
def index():
    return render_template("index.html", catalog=CATALOG, user=current_user())


def render_category(key, result=None, result_is_html=False):
    from secure_reference import SECURE_CODE, VULN_CODE
    meta = CATALOG[key]
    return render_template(
        "category.html",
        key=key, meta=meta, user=current_user(),
        vuln_code=VULN_CODE.get(key, ""), fix_code=SECURE_CODE.get(key, ""),
        result=result, result_is_html=result_is_html, catalog=CATALOG,
    )


@app.route("/<key>")
def category(key):
    if key not in CATALOG:
        abort(404)
    return render_category(key)


# ===========================================================================
# A01 — Broken Access Control  (IDOR, missing admin check, SSRF)
# ===========================================================================
@app.route("/a01/profile", methods=["POST"])
def a01_profile():
    uid = request.form.get("uid", "")
    # [VULNERABLE A01:2025] No check that the requested id belongs to the
    #   logged-in user (IDOR). Any id can be read, including the admin's.
    # [SECURE FIX]  if not current_user() or current_user()["id"] != int(uid): abort(403)
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        return render_category("a01", result="No such user id.")
    out = (f"id={row['id']}  username={row['username']}  role={row['role']}\n"
           f"balance={row['balance']}  api_key={row['api_key']}  ssn={row['ssn']}")
    return render_category("a01", result=out)


@app.route("/admin")
def admin():
    # [VULNERABLE A01:2025] No authorization check at all — anyone can reach the
    #   admin dashboard directly, and the SSRF demo above can even fetch it.
    # [SECURE FIX]  u = current_user();  if not u or u["role"] != "admin": abort(403)
    users = get_db().execute("SELECT id, username, role, balance FROM users").fetchall()
    rows = "\n".join(f"  {u['id']}: {u['username']} ({u['role']}) balance={u['balance']}"
                     for u in users)
    return Response("ADMIN DASHBOARD (should be protected!)\n\n" + rows,
                    mimetype="text/plain")


@app.route("/a01/fetch", methods=["POST"])
def a01_fetch():
    url = request.form.get("url", "")
    # [VULNERABLE A01:2025 / SSRF] The server fetches any URL the user supplies,
    #   including internal addresses (127.0.0.1, cloud metadata, etc.).
    # [SECURE FIX] Validate against an allow-list of hosts/schemes, resolve the
    #   host and block private/link-local ranges, and disable redirects.
    if requests is None:
        return render_category("a01", result="(install 'requests' to run this demo)")
    try:
        resp = requests.get(url, timeout=3)
        body = resp.text[:500]
        return render_category("a01",
                               result=f"Fetched {url}  (status {resp.status_code})\n\n{body}")
    except Exception as exc:                       # noqa: broad on purpose here
        return render_category("a01", result=f"Fetch error: {exc}")


# ===========================================================================
# A02 — Security Misconfiguration
# ===========================================================================
@app.route("/a02/config", methods=["POST"])
def a02_config():
    # [VULNERABLE A02:2025] A debug/config endpoint that leaks internal settings
    #   and secrets. Combined with debug=True, the Werkzeug console allows RCE.
    # [SECURE FIX] Remove such endpoints; keep secrets out of responses; ship a
    #   hardened config with debug disabled and security headers set.
    info = (
        f"DEBUG            = {app.debug}\n"
        f"SECRET_KEY       = {app.secret_key}\n"
        f"DEFAULT ADMIN    = admin / admin\n"
        f"SECURITY HEADERS = (none set — no CSP, HSTS, X-Frame-Options)\n"
        f"DB PATH          = {DB_PATH}"
    )
    return render_category("a02", result=info)


# ===========================================================================
# A03 — Software Supply Chain Failures
# ===========================================================================
@app.route("/a03/audit", methods=["POST"])
def a03_audit():
    # This is a *simulated* SCA report describing requirements-vulnerable.txt.
    # In the Cyber Range, students run the real tools (pip-audit / Snyk) against
    # that file and generate an SBOM. See README for commands.
    report = (
        "Mock SCA report for requirements-vulnerable.txt\n"
        "------------------------------------------------\n"
        "Flask     0.12.2   → CVE-2018-1000656 (DoS via crafted JSON)\n"
        "Jinja2    2.10     → CVE-2019-10906   (sandbox escape)\n"
        "requests  2.19.1   → CVE-2018-18074   (credentials leak on redirect)\n"
        "PyYAML    5.1      → CVE-2020-1747    (arbitrary code via full_load)\n"
        "urllib3   1.24.1   → CVE-2019-11324   (cert verification weakness)\n\n"
        "Action: upgrade all, pin exact versions, and re-scan in CI.\n"
        "Generate an SBOM:  cyclonedx-py requirements -i requirements.txt -o sbom.json"
    )
    return render_category("a03", result=report)


# ===========================================================================
# A04 — Cryptographic Failures
# ===========================================================================
@app.route("/a04/dump", methods=["POST"])
def a04_dump():
    # [VULNERABLE A04:2025] Passwords are unsalted MD5; SSNs/keys are plaintext.
    #   MD5('password1') is instantly reversible via any rainbow table.
    # [SECURE FIX] Store argon2id/bcrypt hashes; encrypt sensitive fields at rest.
    rows = get_db().execute("SELECT username, password, ssn, api_key FROM users").fetchall()
    lines = ["username | md5(password)                     | ssn         | api_key",
             "-" * 78]
    for r in rows:
        lines.append(f"{r['username']:<8} | {r['password']} | {r['ssn']} | {r['api_key']}")
    lines.append("\nCracked in seconds: admin=admin, alice=password1, bob=qwerty")
    return render_category("a04", result="\n".join(lines))


# ===========================================================================
# A05 — Injection  (SQLi, command injection, reflected XSS)
# ===========================================================================
@app.route("/a05/search", methods=["POST"])
def a05_search():
    q = request.form.get("q", "")
    # [VULNERABLE A05:2025] User input concatenated into SQL. Payload  ' OR '1'='1
    #   returns every row.
    # [SECURE FIX]  db.execute("... WHERE name LIKE ?", (f"%{q}%",))
    sql = "SELECT id, name, price FROM products WHERE name = '" + q + "'"
    try:
        rows = get_db().execute(sql).fetchall()
        out = f"Executed: {sql}\n\n" + (
            "\n".join(f"  {r['id']}: {r['name']} — {r['price']}" for r in rows)
            or "  (no rows)")
    except Exception as exc:
        out = f"Executed: {sql}\n\nSQL error: {exc}"
    return render_category("a05", result=out)


@app.route("/a05/ping", methods=["POST"])
def a05_ping():
    host = request.form.get("host", "")
    # [VULNERABLE A05:2025] User input passed to a shell. Payload  localhost; echo PWNED
    #   runs an extra command. (Uses 'echo' as a safe stand-in for the target cmd.)
    # [SECURE FIX] Never use a shell with input: subprocess.run(["ping","-c","1",host],
    #   shell=False) after validating 'host' against a strict pattern.
    cmd = "echo Checking host: " + host
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        out = f"Executed (shell=True): {cmd}\n\n{result.stdout}{result.stderr}"
    except Exception as exc:
        out = f"Command error: {exc}"
    return render_category("a05", result=out)


@app.route("/a05/greet", methods=["POST"])
def a05_greet():
    name = request.form.get("name", "")
    # [VULNERABLE A05:2025 / XSS] The name is echoed back and marked as HTML-safe
    #   in the template (result_is_html=True), so <script> executes in the browser.
    # [SECURE FIX] Let Jinja2 auto-escape (do NOT use |safe) or call
    #   markupsafe.escape(name) before rendering.
    return render_category("a05", result=f"<p>Hello, {name}! Nice to meet you.</p>",
                           result_is_html=True)


# ===========================================================================
# A06 — Insecure Design  (business-logic flaw)
# ===========================================================================
@app.route("/a06/transfer", methods=["POST"])
def a06_transfer():
    to = request.form.get("to", "")
    amount_raw = request.form.get("amount", "0")
    u = current_user()
    if not u:
        return render_category("a06", result="Log in first (top-right) to try this demo.")
    try:
        amount = int(amount_raw)
    except ValueError:
        return render_category("a06", result="Amount must be a whole number.")
    # [VULNERABLE A06:2025] The design never restricts 'amount' to positive
    #   values, so a negative transfer *pulls* money from the recipient to you.
    # [SECURE FIX] Enforce the business rule server-side: if amount <= 0: reject.
    #   Verify recipient exists and the sender has sufficient balance.
    db = get_db()
    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, u["id"]))
    db.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, to))
    db.commit()
    me = get_db().execute("SELECT balance FROM users WHERE id = ?", (u["id"],)).fetchone()
    return render_category(
        "a06",
        result=f"Transferred {amount} to {to}. Your new balance: {me['balance']} "
               f"(a negative amount increased it — the abuse case was never handled).")


# ===========================================================================
# A07 — Authentication Failures  (predictable token, no lockout)
# ===========================================================================
@app.route("/a07/token", methods=["POST"])
def a07_token():
    username = request.form.get("username", "")
    # [VULNERABLE A07:2025] "remember me" token = md5(username): fully predictable
    #   and forgeable for any account. Login (see /login) also has no lockout.
    # [SECURE FIX] Issue a cryptographically random token bound server-side to the
    #   session (secrets.token_urlsafe), and add rate limiting / lockout on login.
    token = md5(username)
    return render_category(
        "a07",
        result=f"remember_token for '{username}' = {token}\n"
               f"Anyone can compute this — it authenticates as that user.")


# ===========================================================================
# A08 — Software or Data Integrity Failures  (insecure deserialization)
# ===========================================================================
_SAMPLE_BLOB = base64.b64encode(pickle.dumps({"theme": "dark", "role": "user"})).decode()


@app.route("/a08/restore", methods=["POST"])
def a08_restore():
    blob = request.form.get("blob", "")
    if blob == "SAMPLE" or not blob:
        blob = _SAMPLE_BLOB
    # [VULNERABLE A08:2025] pickle.loads runs arbitrary code embedded in the blob;
    #   there is no signature/integrity check on the incoming data.
    # [SECURE FIX] Use JSON for untrusted data (json.loads), or verify an HMAC
    #   signature before trusting any serialized payload. Never unpickle input.
    try:
        data = pickle.loads(base64.b64decode(blob))
        out = (f"Restored session (via pickle.loads): {data}\n\n"
               f"A crafted blob here would execute code on the server.")
    except Exception as exc:
        out = f"Deserialization error: {exc}"
    return render_category("a08", result=out)


# ===========================================================================
# A09 — Security Logging & Alerting Failures
# ===========================================================================
SECURITY_LOG = []   # nothing ever gets appended — that's the point.


@app.route("/a09/log", methods=["POST"])
def a09_log():
    # [VULNERABLE A09:2025] Failed logins and access-control violations are never
    #   recorded (see /login and /admin), so this log is always empty and no
    #   alert can ever fire.
    # [SECURE FIX] log.warning("failed login user=%s ip=%s", username, request.remote_addr)
    #   on each security event, ship to a protected store, and alert on thresholds.
    body = "\n".join(SECURITY_LOG) if SECURITY_LOG else (
        "(security log is empty — no auth failures or access violations are "
        "recorded anywhere in this app)")
    return render_category("a09", result=body)


# ===========================================================================
# A10 — Mishandling of Exceptional Conditions
# ===========================================================================
@app.route("/a10/divide", methods=["POST"])
def a10_divide():
    a = request.form.get("a", "0")
    b = request.form.get("b", "0")
    # [VULNERABLE A10:2025] No handling of bad input; with debug=True the full
    #   stack trace (and interactive console) is returned to the user.
    # [SECURE FIX] Validate inputs, catch specific exceptions, return a generic
    #   message to the user, and log the detail server-side.
    result = int(a) / int(b)          # ZeroDivisionError / ValueError leak a trace
    return render_category("a10", result=f"{a} / {b} = {result}")


@app.route("/a10/secure-area", methods=["POST"])
def a10_secure_area():
    token = request.form.get("token", "")
    # [VULNERABLE A10:2025] "Fail open": when the check raises, the except block
    #   grants access instead of denying it.
    # [SECURE FIX] Default to deny; only grant on an explicit, successful check:
    #     try: ok = verify(token)
    #     except Exception: ok = False        # fail CLOSED
    #     if not ok: abort(403)
    try:
        # token.upper() on a non-string, or a lookup miss, raises here
        valid = validate_token(token)
        out = "Access GRANTED — token valid." if valid else "Access denied — bad token."
    except Exception:
        out = "Access GRANTED (fail-open bug!) — an error skipped the check entirely."
    return render_category("a10", result=out)


def validate_token(token):
    # Raises on empty/None input, which the caller wrongly treats as "allow".
    known = {"S3CRET-TOKEN"}
    return token.strip().upper() in known if token else (_ for _ in ()).throw(
        ValueError("no token supplied"))


# ===========================================================================
# Minimal auth (used by the A06 transfer demo). Intentionally weak.
# ===========================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, md5(password)),
        ).fetchone()
        if row:
            session["user_id"] = row["id"]
            return redirect(url_for("index"))
        # [VULNERABLE A07/A09] Failed login: no lockout, no logging, no alert.
        error = "Invalid credentials (try admin/admin, alice/password1, bob/qwerty)."
    return render_template("login.html", error=error, user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 70)
    print(" OWASP Top 10:2025 vulnerable lab is starting.")
    print(" INTENTIONALLY INSECURE — isolated lab use only. Do NOT expose it.")
    print(" Open http://127.0.0.1:5000/  ·  demo logins: admin/admin, alice/password1")
    print("=" * 70 + "\n")
    # [VULNERABLE A02:2025] debug=True exposes the Werkzeug debugger (RCE) and
    #   verbose tracebacks. Bound to 127.0.0.1 so it is not network-reachable.
    # [SECURE FIX] debug=False in any shared/production environment.
    app.run(host="127.0.0.1", port=5000, debug=True)
