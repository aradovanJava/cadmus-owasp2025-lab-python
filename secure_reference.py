"""
secure_reference.py
-------------------
Side-by-side code excerpts rendered on every category page: the vulnerable
pattern as it appears in app.py, and the secure remediation. Keeping them here
lets the UI show "before / after" without cluttering the running handlers.

These are teaching snippets — the SECURE_CODE versions are what a learner should
produce during the Cyber Range refactoring exercise (CR2).
"""

VULN_CODE = {
    "a01": (
        "# IDOR: no ownership check — any id can be read\n"
        "@app.route('/a01/profile', methods=['POST'])\n"
        "def a01_profile():\n"
        "    uid = request.form.get('uid')\n"
        "    row = db.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()\n"
        "    return show(row)          # whose row? nobody checked\n"
        "\n"
        "# SSRF: server fetches any URL the user supplies\n"
        "resp = requests.get(request.form['url'])\n"
        "\n"
        "# Missing check: /admin has no authorization at all\n"
        "@app.route('/admin')\n"
        "def admin():\n"
        "    return dashboard()"
    ),
    "a02": (
        "app.secret_key = 'dev-secret-please-change-123'   # hard-coded\n"
        "app.run(debug=True)                               # RCE console\n"
        "# ships with admin/admin; no CSP/HSTS/X-Frame-Options headers\n"
        "# /a02/config leaks the secret key and settings"
    ),
    "a03": (
        "# requirements-vulnerable.txt (the scan target)\n"
        "Flask==0.12.2\n"
        "Jinja2==2.10\n"
        "requests==2.19.1\n"
        "PyYAML==5.1\n"
        "urllib3==1.24.1\n"
        "# unpinned transitive deps, no SBOM, no SCA in CI"
    ),
    "a04": (
        "def md5(t):\n"
        "    return hashlib.md5(t.encode()).hexdigest()   # unsalted, fast, broken\n"
        "\n"
        "# passwords stored as md5(...); SSNs and api_keys stored in clear text\n"
        "# secret key hard-coded; no TLS enforced"
    ),
    "a05": (
        "# SQL injection\n"
        "sql = \"SELECT * FROM products WHERE name = '\" + q + \"'\"\n"
        "db.execute(sql)\n"
        "\n"
        "# OS command injection\n"
        "subprocess.run('echo Checking host: ' + host, shell=True)\n"
        "\n"
        "# reflected XSS (template marks user input as |safe)\n"
        "return f'<p>Hello, {name}!</p>'   # rendered unescaped"
    ),
    "a06": (
        "# business-logic flaw: negative amounts never rejected\n"
        "amount = int(request.form['amount'])\n"
        "db.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, me))\n"
        "db.execute('UPDATE users SET balance = balance + ? WHERE username = ?', (amount, to))\n"
        "# amount = -500  →  your balance goes UP"
    ),
    "a07": (
        "# predictable 'remember me' token\n"
        "token = md5(username)          # same for everyone who knows the name\n"
        "\n"
        "# login has no lockout / rate limiting → brute force is free"
    ),
    "a08": (
        "# insecure deserialization — arbitrary code execution\n"
        "data = pickle.loads(base64.b64decode(blob))   # blob comes from the user\n"
        "# no signature, no integrity check, dangerous format"
    ),
    "a09": (
        "# failed logins and access violations are never recorded\n"
        "if not row:\n"
        "    error = 'Invalid credentials'   # not logged, no alert\n"
        "SECURITY_LOG = []                    # stays empty forever"
    ),
    "a10": (
        "# leaks a full stack trace to the user (with debug=True)\n"
        "result = int(a) / int(b)            # ZeroDivisionError → traceback\n"
        "\n"
        "# fails OPEN: an error grants access\n"
        "try:\n"
        "    valid = validate_token(token)\n"
        "except Exception:\n"
        "    out = 'Access GRANTED'           # should have denied!"
    ),
}

SECURE_CODE = {
    "a01": (
        "# Enforce object-level authorization, deny by default\n"
        "u = current_user()\n"
        "if not u:\n"
        "    abort(401)\n"
        "row = db.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()\n"
        "if not row or (row['id'] != u['id'] and u['role'] != 'admin'):\n"
        "    abort(403)\n"
        "\n"
        "# SSRF: allow-list + block private ranges + no redirects\n"
        "if not is_allowed(url):\n"
        "    abort(400)\n"
        "resp = requests.get(url, allow_redirects=False, timeout=3)\n"
        "\n"
        "# Protect /admin\n"
        "if not u or u['role'] != 'admin':\n"
        "    abort(403)"
    ),
    "a02": (
        "app.secret_key = os.environ['APP_SECRET_KEY']     # from a secrets manager\n"
        "app.run(debug=False)                              # never debug in shared envs\n"
        "\n"
        "@app.after_request\n"
        "def headers(r):\n"
        "    r.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
        "    r.headers['X-Frame-Options'] = 'DENY'\n"
        "    r.headers['Strict-Transport-Security'] = 'max-age=31536000'\n"
        "    return r\n"
        "# force a password change on first admin login; remove debug endpoints"
    ),
    "a03": (
        "# pin exact, current versions; verify and scan in CI\n"
        "Flask==3.0.3\n"
        "requests==2.32.3\n"
        "\n"
        "# CI gate:\n"
        "pip-audit -r requirements.txt          # fail build on known CVEs\n"
        "cyclonedx-py requirements -i requirements.txt -o sbom.json   # SBOM"
    ),
    "a04": (
        "from argon2 import PasswordHasher\n"
        "ph = PasswordHasher()\n"
        "hashed = ph.hash(password)             # salted, slow, memory-hard\n"
        "ph.verify(hashed, password)\n"
        "\n"
        "# encrypt SSN/keys at rest; enforce TLS; secrets from a manager"
    ),
    "a05": (
        "# parameterized query — data can never become code\n"
        "db.execute('SELECT * FROM products WHERE name LIKE ?', (f'%{q}%',))\n"
        "\n"
        "# no shell; validate host; pass args as a list\n"
        "if not re.fullmatch(r'[a-zA-Z0-9.-]+', host): abort(400)\n"
        "subprocess.run(['ping', '-c', '1', host], shell=False, timeout=3)\n"
        "\n"
        "# output encoding — let Jinja2 auto-escape (drop |safe)\n"
        "return render_template('greet.html', name=name)"
    ),
    "a06": (
        "# enforce the business rule server-side\n"
        "amount = int(request.form['amount'])\n"
        "if amount <= 0:\n"
        "    abort(400, 'amount must be positive')\n"
        "if me['balance'] < amount:\n"
        "    abort(400, 'insufficient funds')\n"
        "if not recipient_exists(to):\n"
        "    abort(404)\n"
        "# wrap both updates in a single transaction"
    ),
    "a07": (
        "import secrets\n"
        "token = secrets.token_urlsafe(32)     # random, unguessable\n"
        "store_token(user_id, token)           # bound server-side to the session\n"
        "\n"
        "# add lockout / rate limiting and MFA on login"
    ),
    "a08": (
        "import json\n"
        "data = json.loads(blob)               # safe format for untrusted input\n"
        "\n"
        "# if you must accept a binary payload, verify an HMAC first:\n"
        "if not hmac.compare_digest(sig, expected_sig(blob)):\n"
        "    abort(400)"
    ),
    "a09": (
        "log.warning('failed_login user=%s ip=%s', username, request.remote_addr)\n"
        "log.warning('access_denied path=%s user=%s', request.path, uid)\n"
        "# ship to a protected, append-only store; alert on thresholds;\n"
        "# never log passwords, tokens, or full PII"
    ),
    "a10": (
        "# validate, catch specific errors, generic message out, detail to log\n"
        "try:\n"
        "    result = int(a) / int(b)\n"
        "except (ValueError, ZeroDivisionError):\n"
        "    log.info('bad divide input')\n"
        "    abort(400, 'invalid input')\n"
        "\n"
        "# fail CLOSED\n"
        "try:\n"
        "    ok = validate_token(token)\n"
        "except Exception:\n"
        "    ok = False\n"
        "if not ok:\n"
        "    abort(403)"
    ),
}
