# OWASP Top 10:2025 — Vulnerable Python Web Application

**Course:** CADMUS-CR-15 · Secure Coding (Python)
**Use with:** Module **N1** (Secure-by-Design Foundations & OWASP Framework) and the Cyber Range labs **CR1–CR4**.

A single deliberately vulnerable Flask web app with a browser GUI. Every one of the
ten **OWASP Top 10:2025** categories has a live demo you can exploit, the vulnerable
source shown next to the secure fix, and the OWASP + MITRE ATT&CK mapping.

---

## ⚠ Safety — read first

This application is **intentionally insecure**. It is a teaching target, not a product.

- Run it **only** on an **isolated / offline** lab machine or throwaway VM.
- It binds to **`127.0.0.1`** on purpose — **do not** change the host or expose it to any network.
- **Never** deploy it, put it online, or run it against real data or credentials.
- Some demos (command injection, `pickle` deserialization, SSRF, the Werkzeug debug console)
  can execute code on the host if fed a crafted payload — that is the lesson. Keep it contained.
- Delete `owasp_lab.db` between sessions to reset all state.

---

## Requirements

- **Python 3.11 or newer** (developed on 3.12; compatible with 3.14).
- The packages in `requirements.txt` (`Flask`, `requests`).

## Run it

```bash
# 1. (recommended) create an isolated virtual environment
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate

# 2. install the clean runtime dependencies
pip install -r requirements.txt

# 3. start the lab (creates owasp_lab.db on first run)
python app.py

# 4. open the GUI
#    http://127.0.0.1:5000/
```

Demo logins: `admin / admin` · `alice / password1` · `bob / qwerty`.

---

## What's in the box

```
owasp2025-lab/
├── app.py                       # the Flask app — every route is vulnerable on purpose
├── secure_reference.py          # before/after code excerpts shown on each page
├── templates/                   # base, dashboard, category page, login
├── static/style.css             # GUI styling
├── requirements.txt             # CLEAN deps to run the app (safe to install)
├── requirements-vulnerable.txt  # SCAN TARGET: outdated pins with known CVEs (do NOT install)
├── README.md                    # this file
└── INSTRUCTOR_GUIDE.md          # facilitation notes, exploit payloads, N1 exercise
```

Vulnerabilities are tagged in the source. Search the code to find every one:

```bash
grep -n "VULNERABLE" app.py        # each flaw, by category
grep -n "SECURE FIX" app.py        # the paired remediation
```

---

## Coverage — OWASP Top 10:2025

| # | Category | Demo(s) in the app | Example payload / trigger |
|---|----------|--------------------|---------------------------|
| **A01** | Broken Access Control *(incl. SSRF)* | IDOR profile view · unprotected `/admin` · URL fetcher | profile id `1`; `GET /admin`; fetch `http://127.0.0.1:5000/admin` |
| **A02** | Security Misconfiguration | debug on · default creds · config/secret leak · no headers | open the config endpoint |
| **A03** | Software Supply Chain Failures | outdated pinned deps + SBOM/SCA exercise | scan `requirements-vulnerable.txt` |
| **A04** | Cryptographic Failures | unsalted MD5 passwords · plaintext SSN/keys · hard-coded key | reveal stored passwords |
| **A05** | Injection | SQLi · OS command injection · reflected XSS | `' OR '1'='1`; `localhost; echo PWNED`; `<script>alert(1)</script>` |
| **A06** | Insecure Design | money transfer accepts negative amounts | log in, transfer `-500` |
| **A07** | Authentication Failures | predictable `md5(username)` token · no lockout | forge a token for `admin` |
| **A08** | Software or Data Integrity Failures | `pickle.loads` on user data, no integrity check | restore the sample blob |
| **A09** | Security Logging & Alerting Failures | auth failures / access violations never logged | view the (empty) security log |
| **A10** | Mishandling of Exceptional Conditions | stack-trace leak · auth check that fails **open** | divide by `0`; enter secure area with a blank token |

Category list and definitions: <https://owasp.org/Top10/2025/>.

---

## Suggested lab flow

1. **N1 (lecture):** on each page, practise the core skill — *spot the weakness, map it to a
   category, name the control.* The root-cause / control boxes and the before/after code
   support the guided-analysis and reflective-exercise slides.
2. **CR1 (identify):** run **SAST** (SonarQube) and **DAST** (OWASP ZAP) against the running app;
   triage findings against the OWASP list.
3. **CR2 (refactor):** turn each `# [VULNERABLE]` handler into its `# [SECURE FIX]`. The target
   code is in `secure_reference.py`.
4. **CR3 (dependencies):** scan `requirements-vulnerable.txt` and generate an SBOM:
   ```bash
   pip install pip-audit cyclonedx-bom
   pip-audit -r requirements-vulnerable.txt
   cyclonedx-py requirements -i requirements.txt -o sbom.json
   ```
5. **CR4 (validate):** add the scans to a CI pipeline so fixes are verified on every build.

See `INSTRUCTOR_GUIDE.md` for facilitation notes and the full set of exploit payloads.

---

*Generated for the CADMUS project (Grant Agreement No. 101190006). Category names and
structure follow OWASP Top 10:2025; MITRE ATT&CK technique IDs are indicative.*
