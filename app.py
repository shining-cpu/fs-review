"""
FS Review portal
================
A small, secure Flask web app for uploading financial-statement files
(.docx / .pdf / .xlsx) and viewing an automated review report.

- Login required (passwords are hashed, never stored in plain text).
- Sessions are signed with a secret key.
- Uploaded files are stored on disk; a lightweight automated review runs
  on .docx files and the findings are shown as a report.

Run locally:    python app.py
Production:     gunicorn app:app   (see README.md)
"""

import os
import re
import json
import uuid
import datetime as dt
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
RECORDS_FILE = os.path.join(DATA_DIR, "records.json")

ALLOWED_EXTENSIONS = {".docx", ".pdf", ".xlsx", ".xls"}
MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25 MB

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
# Secret key: set FLASK_SECRET_KEY in production. Falls back to a generated
# value for local use (sessions reset on restart if not set).
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# --------------------------------------------------------------------------
# Templates are embedded here (no separate templates/ folder needed)
# --------------------------------------------------------------------------
from jinja2 import DictLoader

BASE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}FS Review{% endblock %}</title>
  <style>
    :root{
      --bg:#f4f6f9; --card:#ffffff; --ink:#1f2937; --muted:#6b7280;
      --line:#e5e7eb; --brand:#1d4ed8; --brand-dark:#1e40af;
      --good:#047857; --good-bg:#ecfdf5; --bad:#b91c1c; --bad-bg:#fef2f2;
      --warn:#92400e; --warn-bg:#fffbeb;
    }
    *{box-sizing:border-box}
    body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
      background:var(--bg);color:var(--ink);line-height:1.5}
    a{color:var(--brand);text-decoration:none}
    a:hover{text-decoration:underline}
    .topbar{background:var(--brand);color:#fff;padding:14px 24px;display:flex;
      align-items:center;justify-content:space-between}
    .topbar .brand{font-weight:700;font-size:18px;letter-spacing:.2px}
    .topbar a{color:#dbeafe}
    .wrap{max-width:920px;margin:32px auto;padding:0 20px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:12px;
      padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.04);margin-bottom:20px}
    h1{font-size:22px;margin:0 0 4px}
    h2{font-size:16px;margin:0 0 12px;color:var(--ink)}
    .muted{color:var(--muted);font-size:14px}
    .btn{display:inline-block;background:var(--brand);color:#fff;border:none;
      padding:10px 18px;border-radius:8px;font-size:15px;cursor:pointer;font-weight:600}
    .btn:hover{background:var(--brand-dark);text-decoration:none}
    .btn.secondary{background:#fff;color:var(--brand);border:1px solid var(--brand)}
    .btn.danger{background:#fff;color:var(--bad);border:1px solid var(--bad);padding:6px 12px;font-size:13px}
    input[type=text],input[type=password]{width:100%;padding:11px 12px;border:1px solid var(--line);
      border-radius:8px;font-size:15px;margin-top:6px}
    label{font-size:14px;font-weight:600}
    table{width:100%;border-collapse:collapse;font-size:14px}
    th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line)}
    th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
    .flash{padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px}
    .flash.error{background:var(--bad-bg);color:var(--bad);border:1px solid #fecaca}
    .flash.success{background:var(--good-bg);color:var(--good);border:1px solid #a7f3d0}
    .pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}
    .pill.good{background:var(--good-bg);color:var(--good)}
    .pill.bad{background:var(--bad-bg);color:var(--bad)}
    .pill.warn{background:var(--warn-bg);color:var(--warn)}
    .dropzone{border:2px dashed #c7d2fe;border-radius:12px;padding:28px;text-align:center;
      background:#f8faff;margin:8px 0 16px}
    ul{margin:8px 0;padding-left:20px}
    li{margin:3px 0}
  </style>
</head>
<body>
  <div class="topbar">
    <div class="brand">FS Review Portal</div>
    <div>
      {% if session.get('user') %}
        <span style="color:#dbeafe;font-size:14px">{{ session.get('name') }}</span>
        &nbsp;·&nbsp; <a href="{{ url_for('logout') }}">Log out</a>
      {% endif %}
    </div>
  </div>
  <div class="wrap">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}
    {% block content %}{% endblock %}
  </div>
</body>
</html>"""

LOGIN_HTML = """{% extends "base.html" %}
{% block title %}Sign in · FS Review{% endblock %}
{% block content %}
<div class="card" style="max-width:420px;margin:40px auto">
  <h1>Sign in</h1>
  <p class="muted">Enter your credentials to access the FS review portal.</p>
  <form method="post" action="{{ url_for('login') }}" style="margin-top:16px">
    <div style="margin-bottom:14px">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="username" required autofocus>
    </div>
    <div style="margin-bottom:20px">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>
    </div>
    <button class="btn" type="submit" style="width:100%">Sign in</button>
  </form>
</div>
{% endblock %}"""

DASHBOARD_HTML = """{% extends "base.html" %}
{% block title %}Dashboard · FS Review{% endblock %}
{% block content %}
<div class="card">
  <h1>Upload financial statements</h1>
  <p class="muted">Allowed file types: .docx, .pdf, .xlsx, .xls — max 25 MB. A review report is generated on upload.</p>
  <form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
    <div class="dropzone">
      <input type="file" name="file" accept=".docx,.pdf,.xlsx,.xls" required
             style="font-size:15px">
      <p class="muted" style="margin:10px 0 0">Choose a file, then submit.</p>
    </div>
    <button class="btn" type="submit">Upload &amp; review</button>
  </form>
</div>

<div class="card">
  <h2>Reviewed files</h2>
  {% if records %}
  <table>
    <thead>
      <tr><th>File</th><th>Type</th><th>Size</th><th>Uploaded</th><th></th></tr>
    </thead>
    <tbody>
      {% for r in records %}
      <tr>
        <td><a href="{{ url_for('report', rec_id=r.id) }}">{{ r.original_name }}</a><br>
            <span class="muted" style="font-size:12px">by {{ r.uploaded_by }}</span></td>
        <td>{{ r.ext.lstrip('.')|upper }}</td>
        <td>{{ r.size_bytes|filesize }}</td>
        <td class="muted">{{ r.uploaded_at.replace('T',' ') }}</td>
        <td><a href="{{ url_for('report', rec_id=r.id) }}">View report →</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="muted">No files reviewed yet. Upload one above to get started.</p>
  {% endif %}
</div>
{% endblock %}"""

REPORT_HTML = """{% extends "base.html" %}
{% block title %}Review report · {{ r.original_name }}{% endblock %}
{% block content %}
<div class="card">
  <p class="muted"><a href="{{ url_for('dashboard') }}">← Back to dashboard</a></p>
  <h1>Review report</h1>
  <p class="muted">{{ r.original_name }} · {{ r.ext.lstrip('.')|upper }} · {{ r.size_bytes|filesize }}
     · uploaded {{ r.uploaded_at.replace('T',' ') }} by {{ r.uploaded_by }}</p>
  <p style="margin-top:14px">
    <a class="btn secondary" href="{{ url_for('download', rec_id=r.id) }}">Download original</a>
    <a class="btn" href="{{ url_for('download_report', rec_id=r.id) }}">Download review report (Word)</a>
  </p>
</div>

{% set f = r.findings %}

{% if f.error %}
<div class="card">
  <span class="pill bad">Could not parse</span>
  <p style="margin-top:12px">{{ f.error }}</p>
</div>
{% else %}

<div class="card">
  <h2>Document structure</h2>
  <p><strong>{{ f.tables }}</strong> table(s), <strong>{{ f.paragraph_count }}</strong> non-empty paragraph(s).</p>
  {% if f.sections_found %}
    <p style="margin-top:12px"><strong>Sections detected:</strong></p>
    <ul>{% for s in f.sections_found %}<li>{{ s }}</li>{% endfor %}</ul>
  {% endif %}
  {% if f.sections_missing %}
    <p style="margin-top:12px"><strong>Common sections not detected</strong>
       <span class="muted">(may be absent, named differently, or in a separate file):</span></p>
    <ul>{% for s in f.sections_missing %}<li class="muted">{{ s }}</li>{% endfor %}</ul>
  {% endif %}
</div>

<div class="card">
  <h2>Arithmetic / tally checks {% if f.tally_checks %}<span class="pill bad">{{ f.tally_checks|length }} flagged</span>{% else %}<span class="pill good">No mismatches found</span>{% endif %}</h2>
  {% if f.tally_checks %}
  <p class="muted">Subtotals/totals where the lines above do not add up to the stated figure — verify each:</p>
  <table>
    <thead><tr><th>Table</th><th>Total line</th><th>Issue</th><th>Sum of lines</th><th>Stated</th><th>Difference</th></tr></thead>
    <tbody>
      {% for c in f.tally_checks %}
      <tr>
        <td>{{ c.table }}</td><td>{{ c.label }}</td>
        <td>{% if c.kind == 'sign / brackets' %}<span class="pill warn">sign / brackets</span>{% else %}<span class="pill bad">does not add up</span>{% endif %}</td>
        <td>{{ "{:,.2f}".format(c.sum_of_parts) }}</td>
        <td>{{ "{:,.2f}".format(c.stated_total) }}</td>
        <td style="color:#b91c1c">{{ "{:,.2f}".format(c.difference) }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="muted">No column-total mismatches were detected.</p>
  {% endif %}
</div>

<div class="card">
  <h2>Balance sheet equation
    {% if f.balance_checks %}
      {% set unbalanced = f.balance_checks | selectattr('balanced', 'equalto', false) | list %}
      {% if unbalanced %}<span class="pill bad">Does not balance</span>{% else %}<span class="pill good">Balances</span>{% endif %}
    {% else %}<span class="pill warn">Not found</span>{% endif %}</h2>
  {% if f.balance_checks %}
  <p class="muted">Total assets vs. total equity + total liabilities:</p>
  <table>
    <thead><tr><th>Total assets</th><th>Equity + liabilities</th><th>Difference</th><th>Status</th></tr></thead>
    <tbody>
      {% for b in f.balance_checks %}
      <tr>
        <td>{{ "{:,.2f}".format(b.total_assets) }}</td>
        <td>{{ "{:,.2f}".format(b.equity_plus_liabilities) }}</td>
        <td {% if not b.balanced %}style="color:#b91c1c"{% endif %}>{{ "{:,.2f}".format(b.difference) }}</td>
        <td>{% if b.balanced %}<span class="pill good">OK</span>{% else %}<span class="pill bad">Off</span>{% endif %}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="muted">Could not locate "Total assets" / "Total equity" / "Total liabilities" lines to test the balance equation. Check the labels in the statement of financial position.</p>
  {% endif %}
</div>

<div class="card">
  <h2>Profit &amp; loss flow {% if f.pl_checks %}<span class="pill bad">{{ f.pl_checks|length }} flagged</span>{% else %}<span class="pill good">Consistent</span>{% endif %}</h2>
  {% if f.pl_checks %}
  <table>
    <thead><tr><th>Table</th><th>Check</th><th>Expected</th><th>Stated</th><th>Difference</th></tr></thead>
    <tbody>
      {% for c in f.pl_checks %}
      <tr><td>{{ c.table }}</td><td>{{ c.check }}</td>
        <td>{{ "{:,.2f}".format(c.expected) }}</td>
        <td>{{ "{:,.2f}".format(c.stated) }}</td>
        <td style="color:#b91c1c">{{ "{:,.2f}".format(c.difference) }}</td></tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="muted">Gross profit and loss/profit for the year tie to their components (or no P&amp;L detected).</p>
  {% endif %}
</div>

<div class="card">
  <h2>Cross-add checks (changes in equity, etc.) {% if f.row_checks %}<span class="pill bad">{{ f.row_checks|length }} flagged</span>{% else %}<span class="pill good">OK</span>{% endif %}</h2>
  {% if f.row_checks %}
  <table>
    <thead><tr><th>Table</th><th>Row</th><th>Sum across</th><th>Stated total</th><th>Difference</th></tr></thead>
    <tbody>
      {% for c in f.row_checks %}
      <tr><td>{{ c.table }}</td><td>{{ c.row }}</td>
        <td>{{ "{:,.2f}".format(c.sum_across) }}</td>
        <td>{{ "{:,.2f}".format(c.stated_total) }}</td>
        <td style="color:#b91c1c">{{ "{:,.2f}".format(c.difference) }}</td></tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="muted">Rows with a "Total" column add across correctly (or none found).</p>
  {% endif %}
</div>

<div class="card">
  <h2>FRS disclosure checklist</h2>
  <p class="muted">Keyword scan for common Singapore FRS disclosures. "Not found" doesn't always mean missing — it flags items to confirm manually.</p>
  <table>
    <thead><tr><th>FRS</th><th>Disclosure</th><th>Detected?</th></tr></thead>
    <tbody>
      {% for k in f.frs_checks %}
      <tr>
        <td>{{ k.frs }}</td><td>{{ k.item }}</td>
        <td>{% if k.present %}<span class="pill good">Found</span>{% else %}<span class="pill warn">Not found — check</span>{% endif %}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div class="card">
  <h2>AI review — FRS judgement &amp; grammar
    {% if f.ai.enabled %}<span class="pill good">enabled</span>{% else %}<span class="pill warn">off</span>{% endif %}</h2>
  {% if not f.ai.enabled %}
    <p class="muted">{{ f.ai.error }}</p>
  {% else %}
    {% if f.ai.narrative %}<p>{{ f.ai.narrative }}</p>{% endif %}
    <p style="margin-top:12px"><strong>FRS observations</strong></p>
    {% if f.ai.frs_observations %}
    <table>
      <thead><tr><th>FRS</th><th>Issue</th><th>Detail</th><th>Recommendation</th></tr></thead>
      <tbody>
        {% for o in f.ai.frs_observations %}
        <tr><td>{{ o.frs }}</td><td>{{ o.issue }}</td><td>{{ o.detail }}</td><td>{{ o.recommendation }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}<p class="muted">No FRS issues raised.</p>{% endif %}
    <p style="margin-top:12px"><strong>Grammar &amp; wording</strong></p>
    {% if f.ai.grammar_issues %}
    <table>
      <thead><tr><th>Location</th><th>Current</th><th>Suggested</th></tr></thead>
      <tbody>
        {% for g in f.ai.grammar_issues %}
        <tr><td>{{ g.location }}</td><td>{{ g.current }}</td><td>{{ g.suggested }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}<p class="muted">No grammar issues raised.</p>{% endif %}
  {% endif %}
</div>

<div class="card">
  <h2>Language &amp; spelling (rule scan) {% if f.language_issues %}<span class="pill warn">{{ f.language_issues|length }} to review</span>{% else %}<span class="pill good">Nothing flagged</span>{% endif %}</h2>
  {% if f.language_issues %}
  <table>
    <thead><tr><th>Type</th><th>Found</th><th>Suggest</th><th>Context</th></tr></thead>
    <tbody>
      {% for g in f.language_issues %}
      <tr>
        <td>{{ g.kind }}</td><td>{{ g.found }}</td><td>{{ g.suggest }}</td>
        <td class="muted">…{{ g.context }}…</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="muted">No British-English or common-typo issues detected by the rule scan.</p>
  {% endif %}
</div>

{% if f.warnings %}
<div class="card">
  <h2>Notes &amp; scope</h2>
  <ul>{% for w in f.warnings %}<li class="muted">{{ w }}</li>{% endfor %}</ul>
</div>
{% endif %}

{% endif %}

<div class="card" style="background:#fffbeb;border-color:#fde68a">
  <p class="muted" style="margin:0">This automated review is a first-pass aid, not a substitute for a full
  FRS/IFRS compliance review by a qualified reviewer.</p>
</div>

<form method="post" action="{{ url_for('delete', rec_id=r.id) }}"
      onsubmit="return confirm('Delete this file and its report?')">
  <button class="btn danger" type="submit">Delete file</button>
</form>
{% endblock %}"""

app.jinja_loader = DictLoader({
    "base.html": BASE_HTML,
    "login.html": LOGIN_HTML,
    "dashboard.html": DASHBOARD_HTML,
    "report.html": REPORT_HTML,
})


# --------------------------------------------------------------------------
# Tiny JSON "database" helpers
# --------------------------------------------------------------------------
def _load(path, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def _save(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_users():
    """Users are { username: {password_hash, name} }.

    On first run we seed an admin account. The default password should be
    changed immediately (or set ADMIN_PASSWORD before first launch).
    """
    users = _load(USERS_FILE, None)
    if users is None:
        admin_pw = os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")
        users = {
            "admin": {
                "password_hash": generate_password_hash(admin_pw),
                "name": "Administrator",
            }
        }
        _save(USERS_FILE, users)
    return users


def load_records():
    return _load(RECORDS_FILE, [])


def save_records(records):
    _save(RECORDS_FILE, records)


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_users()
        user = users.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user"] = username
            session["name"] = user.get("name", username)
            nxt = request.args.get("next") or url_for("dashboard")
            return redirect(nxt)
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Lightweight automated review of a .docx financial statement
# --------------------------------------------------------------------------
KEY_SECTIONS = [
    "statement of financial position",
    "statement of comprehensive income",
    "statement of profit or loss",
    "statement of changes in equity",
    "statement of cash flows",
    "notes to the financial statements",
    "directors' statement",
    "independent auditor",
]

# American -> British spelling (Singapore entities use British English)
US_TO_UK = {
    "organization": "organisation", "organizations": "organisations",
    "recognize": "recognise", "recognized": "recognised", "recognizes": "recognises",
    "recognizing": "recognising", "capitalize": "capitalise",
    "capitalized": "capitalised", "realize": "realise", "realized": "realised",
    "amortize": "amortise", "amortized": "amortised", "utilize": "utilise",
    "utilized": "utilised", "labor": "labour", "color": "colour",
    "center": "centre", "fulfill": "fulfil", "favor": "favour",
    "analyze": "analyse", "analyzed": "analysed", "offset off": "offset",
}

# Common typos seen in financial statements
COMMON_TYPOS = {
    "theses": "these", "finanical": "financial", "financal": "financial",
    "statment": "statement", "statments": "statements",
    "comparitive": "comparative", "accomodate": "accommodate",
    "recieve": "receive", "recievable": "receivable", "seperate": "separate",
    "occured": "occurred", "non-curent": "non-current", "balacne": "balance",
    "liabilites": "liabilities", "expences": "expenses", "incured": "incurred",
}

# FRS disclosure checklist — keyword presence heuristics
FRS_CHECKS = [
    ("FRS 1", "Going concern basis stated",
     ["going concern"]),
    ("FRS 1", "Significant judgements & estimates note",
     ["significant judgement", "significant estimate", "judgements and estimates",
      "key sources of estimation"]),
    ("FRS 2", "Inventory cost formula (FIFO / weighted average)",
     ["first-in", "first in", "weighted average", "fifo"]),
    ("FRS 12", "Deferred tax disclosure",
     ["deferred tax"]),
    ("FRS 109", "Financial instruments note",
     ["financial instrument", "financial asset", "financial liabilit"]),
    ("FRS 115", "Revenue recognition timing (over time / point in time)",
     ["over time", "point in time", "performance obligation"]),
    ("FRS 116", "Leases (right-of-use / lease liability)",
     ["right-of-use", "right of use", "lease liabilit", "lease liability"]),
]


def _to_number(text):
    """Parse an accounting-style number; parentheses mean negative."""
    if text is None:
        return None
    t = text.strip().replace("–", "-").replace("−", "-")
    if t in ("", "-", "–", "—", "nil", "Nil", "NIL"):
        return None
    neg = t.startswith("(") and t.endswith(")")
    t = t.strip("()").replace(",", "").replace("$", "").strip()
    try:
        val = float(t)
        return -val if neg else val
    except ValueError:
        return None


def _grid(table):
    """Return (labels, numgrid): first-column text labels and a numeric grid."""
    labels, numgrid = [], []
    for row in table.rows:
        cells = [c.text for c in row.cells]
        labels.append(cells[0].strip() if cells else "")
        numgrid.append([_to_number(c) for c in cells])
    return labels, numgrid


# Grand totals sum *subtotals* across sections, not leaf lines — so they are
# not checked by the simple "sum the lines above" rule (it would misfire).
GRAND_TOTALS = {
    "total assets", "total liabilities", "total equity and liabilities",
    "total equity & liabilities", "net assets", "net current assets",
    "total comprehensive income", "total comprehensive loss",
}


def _note_columns(table):
    """Column indexes that are 'Note' reference columns (values like 7, 8, 9)."""
    skip = set()
    for row in table.rows:
        cells = [c.text.strip().lower() for c in row.cells]
        for i, txt in enumerate(cells):
            if txt == "note":
                skip.add(i)
        if any(c in ("$", "2025", "2024", "2023", "2026") for c in cells):
            break  # header row reached
    return skip


def check_table_totals(t_idx, table):
    """Check each subtotal against the line items directly above it.

    Conservative on purpose, to avoid false positives on real statements:
    - resets at blank rows and section headers (so balance-sheet sections
      aren't summed together);
    - never treats a 'Total' row as a line item;
    - skips 'Note' reference columns and grand totals;
    - treats a nil dash ('-') as zero, not a section break;
    - flags a sign/brackets inconsistency when the sum equals the stated
      figure in magnitude but the signs differ (e.g. 430,872 vs (430,872)).
    """
    issues = []
    labels, numgrid = _grid(table)
    if len(numgrid) < 3:
        return issues
    ncols = max((len(r) for r in numgrid), default=0)
    skipcols = _note_columns(table)
    moneycols = [c for c in range(1, ncols) if c not in skipcols]
    # A "data row" has a number in at least one money column; otherwise it is a
    # section header / separator.
    is_data = [
        any(numgrid[r][c] is not None for c in moneycols if c < len(numgrid[r]))
        for r in range(len(numgrid))
    ]
    for c in moneycols:
        seg = []
        for r, label in enumerate(labels):
            low = label.lower().strip()
            val = numgrid[r][c] if c < len(numgrid[r]) else None
            if not low:                       # blank row -> section break
                seg = []
                continue
            if "total" in low:                # subtotal / total line
                if low not in GRAND_TOTALS and val is not None and len(seg) >= 2:
                    s = sum(seg)
                    diff = s - val
                    if abs(diff) > 0.5 and val != 0:
                        rel = abs(diff) / (abs(val) + 1e-9)
                        if abs(s + val) <= 0.5:        # same size, opposite sign
                            issues.append({
                                "table": t_idx + 1, "label": label[:55],
                                "sum_of_parts": round(s, 2),
                                "stated_total": round(val, 2),
                                "difference": round(diff, 2),
                                "kind": "sign / brackets",
                            })
                        elif rel < 1.0:                # conservative arithmetic slip
                            issues.append({
                                "table": t_idx + 1, "label": label[:55],
                                "sum_of_parts": round(s, 2),
                                "stated_total": round(val, 2),
                                "difference": round(diff, 2),
                                "kind": "sum",
                            })
                seg = []
                continue                      # never treat a total as a line item
            if not is_data[r]:                # section header with no numbers
                seg = []
                continue
            seg.append(val if val is not None else 0.0)  # nil '-' counts as 0
    return issues


def check_balance_equation(doc):
    """Try to confirm Total assets == Total equity + Total liabilities."""
    results = []
    # Collect labelled totals from all tables, per numeric column
    for table in doc.tables:
        labels, numgrid = _grid(table)
        ncols = max((len(r) for r in numgrid), default=0)
        for c in range(1, ncols):
            picks = {"assets": None, "equity": None, "liabilities": None,
                     "eq_and_liab": None}
            for r, label in enumerate(labels):
                low = label.lower()
                val = numgrid[r][c] if c < len(numgrid[r]) else None
                if val is None:
                    continue
                if "total equity and" in low or "total equity & " in low:
                    picks["eq_and_liab"] = val
                elif "total asset" in low:
                    picks["assets"] = val
                elif "total equit" in low:
                    picks["equity"] = val
                elif "total liabilit" in low:
                    picks["liabilities"] = val
            if picks["assets"] is not None:
                target = picks["eq_and_liab"]
                if target is None and picks["equity"] is not None and picks["liabilities"] is not None:
                    target = picks["equity"] + picks["liabilities"]
                if target is not None:
                    diff = picks["assets"] - target
                    results.append({
                        "total_assets": round(picks["assets"], 2),
                        "equity_plus_liabilities": round(target, 2),
                        "difference": round(diff, 2),
                        "balanced": abs(diff) <= 0.5,
                    })
    # De-duplicate identical results
    seen, uniq = set(), []
    for r in results:
        key = (r["total_assets"], r["equity_plus_liabilities"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


def _find_row(labels, numgrid, c, *keys, exclude=()):
    """First numeric value in column c whose label matches any key."""
    for r, label in enumerate(labels):
        low = label.lower()
        if any(k in low for k in keys) and not any(x in low for x in exclude):
            v = numgrid[r][c] if c < len(numgrid[r]) else None
            if v is not None:
                return v
    return None


def check_pl(t_idx, table):
    """Profit & loss flow checks (only if the table looks like a P&L)."""
    out = []
    labels, numgrid = _grid(table)
    low_all = " ".join(labels).lower()
    if "gross profit" not in low_all and "gross loss" not in low_all:
        return out
    skip = _note_columns(table)
    ncols = max((len(r) for r in numgrid), default=0)
    for c in [x for x in range(1, ncols) if x not in skip]:
        rev = _find_row(labels, numgrid, c, "revenue", "sales", "turnover", exclude=("cost",))
        cogs = _find_row(labels, numgrid, c, "cost of goods", "cost of sales")
        gp = _find_row(labels, numgrid, c, "gross profit", "gross loss")
        pbt = _find_row(labels, numgrid, c, "before tax", "before taxation")
        tax = _find_row(labels, numgrid, c, "income tax", "tax expense", "taxation")
        net = _find_row(labels, numgrid, c, "for the financial year", "for the year",
                        "loss for", "profit for")
        if rev is not None and cogs is not None and gp is not None:
            exp = rev + cogs if cogs < 0 else rev - cogs
            if abs(exp - gp) > 0.5:
                out.append({"table": t_idx + 1,
                            "check": "Gross profit = Revenue − Cost of sales",
                            "expected": round(exp, 2), "stated": round(gp, 2),
                            "difference": round(exp - gp, 2)})
        if net is not None and pbt is not None:
            tx = tax or 0
            exp = pbt + tx if (tax is None or tx < 0) else pbt - tx
            if abs(exp - net) > 0.5:
                out.append({"table": t_idx + 1,
                            "check": "Loss/profit for year = Before tax − Tax",
                            "expected": round(exp, 2), "stated": round(net, 2),
                            "difference": round(exp - net, 2)})
    return out


def check_row_totals(t_idx, table):
    """Horizontal check: when the LAST column is a 'Total' column, each row's
    components should add across to it (e.g. Statement of Changes in Equity)."""
    out = []
    labels, numgrid = _grid(table)
    last_is_total = False
    for row in table.rows:
        cells = [c.text.strip().lower() for c in row.cells]
        if cells and "total" in cells[-1]:
            last_is_total = True
            break
    if not last_is_total:
        return out
    ncols = max((len(r) for r in numgrid), default=0)
    for r in range(len(numgrid)):
        row = numgrid[r]
        comps = [v for v in row[1:ncols - 1] if v is not None]
        tot = row[ncols - 1] if ncols - 1 < len(row) else None
        if tot is not None and len(comps) >= 2 and abs(sum(comps) - tot) > 0.5:
            out.append({"table": t_idx + 1,
                        "row": (labels[r][:40] or f"row {r + 1}"),
                        "sum_across": round(sum(comps), 2),
                        "stated_total": round(tot, 2),
                        "difference": round(sum(comps) - tot, 2)})
    return out


def check_language(doc):
    """British-English and common-typo checks across all paragraphs."""
    issues = []
    seen = set()
    for p in doc.paragraphs:
        text = p.text
        low = text.lower()
        for us, uk in US_TO_UK.items():
            if re.search(r"\b" + re.escape(us) + r"\b", low) and us not in seen:
                seen.add(us)
                issues.append({"kind": "Spelling (US→UK)",
                               "found": us, "suggest": uk,
                               "context": text.strip()[:90]})
        for typo, fix in COMMON_TYPOS.items():
            if re.search(r"\b" + re.escape(typo) + r"\b", low) and typo not in seen:
                seen.add(typo)
                issues.append({"kind": "Likely typo",
                               "found": typo, "suggest": fix,
                               "context": text.strip()[:90]})
        if re.search(r"\bSec\.?\s+\d", text) and "Sec." not in seen:
            seen.add("Sec.")
            issues.append({"kind": "Abbreviation",
                           "found": "Sec.", "suggest": "Section",
                           "context": text.strip()[:90]})
    return issues


def check_frs(full_text_low, has_inventory):
    out = []
    for frs, item, keywords in FRS_CHECKS:
        if frs == "FRS 2" and not has_inventory:
            continue
        present = any(k in full_text_low for k in keywords)
        out.append({"frs": frs, "item": item, "present": present})
    return out


# --------------------------------------------------------------------------
# AI review (Claude) — the judgement half: FRS compliance + grammar + summary.
# The deterministic checks above handle the arithmetic; this adds the reasoning.
# Requires the ANTHROPIC_API_KEY environment variable. Skips gracefully if unset.
# --------------------------------------------------------------------------
AI_MODEL = os.environ.get("FS_REVIEW_MODEL", "claude-haiku-4-5-20251001")

AI_PROMPT = """You are a Singapore financial-statements reviewer reviewing the \
unaudited financial statements of a Singapore-incorporated company. The arithmetic \
has ALREADY been independently verified by a separate program, so do NOT re-check \
sums — focus on disclosure judgement and language.

Review the extracted financial statements below and report:

1. FRS compliance against Singapore FRS 1 (going concern adequacy when there are \
accumulated losses/net current liabilities; significant judgements & estimates; \
standards issued-but-not-yet-effective dates correct for the financial year), \
FRS 2 (inventory cost formula, only if inventory exists), FRS 12 (deferred tax / \
unutilised tax losses recognised or disclosed with amounts), FRS 109 (financial \
instruments note includes ONLY financial instruments — not prepayments, inventory \
or tax), FRS 115 (revenue recognition basis — over time vs point in time — clearly \
stated and consistent), FRS 116 (leases recognised if the company leases premises).

2. Grammar/typography: spelling, British vs American English (SG uses British), \
singular/plural (Director vs Directors), defined-term capitalisation ("the Company"), \
leftover placeholders (square brackets, blanks), and abbreviations.

Return STRICT JSON only, no prose around it, in exactly this shape:
{"frs_observations":[{"frs":"FRS 12","issue":"...","detail":"...","recommendation":"..."}],
 "grammar_issues":[{"location":"...","current":"...","suggested":"..."}],
 "narrative":"2-4 sentence overall summary"}

If something is fine, omit it rather than inventing issues. Financial statements text:

"""


def extract_full_text(doc):
    parts = []
    for i, table in enumerate(doc.tables):
        parts.append(f"\n--- TABLE {i + 1} ---")
        for row in table.rows:
            parts.append(" | ".join(c.text.strip() for c in row.cells))
    for p in doc.paragraphs:
        if p.text.strip():
            parts.append(p.text.strip())
    return "\n".join(parts)


def _parse_json(raw):
    raw = (raw or "").strip()
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1]
        if raw[:4].lower() == "json":
            raw = raw[4:]
    s, e = raw.find("{"), raw.rfind("}")
    if s >= 0 and e > s:
        try:
            return json.loads(raw[s:e + 1])
        except Exception:
            return {}
    return {}


def ai_review(extracted_text):
    """Judgement-based review via Claude. Returns a dict with 'enabled' flag."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return {"enabled": False,
                "error": "AI review not enabled — set ANTHROPIC_API_KEY to turn it on.",
                "frs_observations": [], "grammar_issues": [], "narrative": ""}
    try:
        import anthropic
    except Exception:
        return {"enabled": False,
                "error": "The 'anthropic' package is not installed (pip install anthropic).",
                "frs_observations": [], "grammar_issues": [], "narrative": ""}
    try:
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model=AI_MODEL,
            max_tokens=4000,
            messages=[{"role": "user", "content": AI_PROMPT + extracted_text[:60000]}],
        )
        raw = "".join(getattr(b, "text", "") for b in msg.content)
        data = _parse_json(raw)
        return {
            "enabled": True, "error": None,
            "frs_observations": data.get("frs_observations", []),
            "grammar_issues": data.get("grammar_issues", []),
            "narrative": data.get("narrative", ""),
        }
    except Exception as e:
        return {"enabled": False, "error": f"AI review could not run: {e}",
                "frs_observations": [], "grammar_issues": [], "narrative": ""}


def review_docx(path):
    """Return a dict of findings for a .docx file (rule-based, offline)."""
    findings = {
        "type": "docx",
        "sections_found": [], "sections_missing": [],
        "tables": 0, "paragraph_count": 0,
        "tally_checks": [], "balance_checks": [],
        "pl_checks": [], "row_checks": [],
        "frs_checks": [], "language_issues": [],
        "ai": {"enabled": False, "error": None, "frs_observations": [],
               "grammar_issues": [], "narrative": ""},
        "warnings": [], "error": None,
    }
    try:
        from docx import Document
    except Exception:
        findings["error"] = (
            "python-docx is not installed, so the .docx could not be parsed. "
            "Run: pip install python-docx"
        )
        return findings
    try:
        doc = Document(path)
    except Exception as e:
        findings["error"] = f"Could not open document: {e}"
        return findings

    full_text_low = "\n".join(p.text for p in doc.paragraphs).lower()
    # include table text for section / FRS keyword detection
    for table in doc.tables:
        for row in table.rows:
            full_text_low += "\n" + " ".join(c.text for c in row.cells).lower()

    findings["paragraph_count"] = len([p for p in doc.paragraphs if p.text.strip()])
    findings["tables"] = len(doc.tables)

    for section in KEY_SECTIONS:
        (findings["sections_found"] if section in full_text_low
         else findings["sections_missing"]).append(section.title())

    for t_idx, table in enumerate(doc.tables):
        findings["tally_checks"].extend(check_table_totals(t_idx, table))
        findings["pl_checks"].extend(check_pl(t_idx, table))
        findings["row_checks"].extend(check_row_totals(t_idx, table))

    findings["balance_checks"] = check_balance_equation(doc)
    findings["language_issues"] = check_language(doc)
    findings["frs_checks"] = check_frs(full_text_low, "inventor" in full_text_low)
    findings["ai"] = ai_review(extract_full_text(doc))

    findings["warnings"].append(
        "This is an automated, rule-based first pass (arithmetic, balance equation, "
        "British-English spelling and an FRS disclosure checklist). It does NOT yet "
        "include the AI-assisted FRS judgement and full grammar review — those "
        "need the paid upgrade described in the project plan. A qualified reviewer "
        "should still perform the final FRS/IFRS review."
    )
    return findings


def basic_review(path, ext):
    if ext == ".docx":
        return review_docx(path)
    return {
        "type": ext.lstrip("."),
        "error": None,
        "warnings": [
            f"Automated parsing for {ext} files is not enabled in this build. "
            "Please upload the financial statements as a .docx for the full "
            "automated review. The file has been stored."
        ],
        "sections_found": [], "sections_missing": [],
        "tables": 0, "paragraph_count": 0,
        "tally_checks": [], "balance_checks": [],
        "pl_checks": [], "row_checks": [],
        "frs_checks": [], "language_issues": [],
        "ai": {"enabled": False, "error": None, "frs_observations": [],
               "grammar_issues": [], "narrative": ""},
    }


# --------------------------------------------------------------------------
# App routes
# --------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    records = sorted(load_records(), key=lambda r: r["uploaded_at"], reverse=True)
    return render_template("dashboard.html", records=records, name=session.get("name"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("Please choose a file to upload.", "error")
        return redirect(url_for("dashboard"))

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        flash(f"File type {ext or '(none)'} is not allowed. "
              f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}.", "error")
        return redirect(url_for("dashboard"))

    rec_id = uuid.uuid4().hex[:12]
    safe_name = secure_filename(file.filename)
    stored_name = f"{rec_id}_{safe_name}"
    stored_path = os.path.join(UPLOAD_DIR, stored_name)
    file.save(stored_path)

    findings = basic_review(stored_path, ext)

    record = {
        "id": rec_id,
        "original_name": file.filename,
        "stored_name": stored_name,
        "ext": ext,
        "size_bytes": os.path.getsize(stored_path),
        "uploaded_by": session.get("name"),
        "uploaded_at": dt.datetime.now().isoformat(timespec="seconds"),
        "findings": findings,
    }
    records = load_records()
    records.append(record)
    save_records(records)

    flash("File uploaded and reviewed.", "success")
    return redirect(url_for("report", rec_id=rec_id))


@app.route("/report/<rec_id>")
@login_required
def report(rec_id):
    record = next((r for r in load_records() if r["id"] == rec_id), None)
    if not record:
        abort(404)
    return render_template("report.html", r=record)


@app.route("/download/<rec_id>")
@login_required
def download(rec_id):
    record = next((r for r in load_records() if r["id"] == rec_id), None)
    if not record:
        abort(404)
    return send_from_directory(
        UPLOAD_DIR, record["stored_name"],
        as_attachment=True, download_name=record["original_name"],
    )


@app.route("/delete/<rec_id>", methods=["POST"])
@login_required
def delete(rec_id):
    records = load_records()
    record = next((r for r in records if r["id"] == rec_id), None)
    if record:
        try:
            os.remove(os.path.join(UPLOAD_DIR, record["stored_name"]))
        except OSError:
            pass
        records = [r for r in records if r["id"] != rec_id]
        save_records(records)
        flash("Record deleted.", "success")
    return redirect(url_for("dashboard"))


def build_word_report(record):
    """Build a .docx review report from a record's findings; returns a BytesIO."""
    import io
    from docx import Document as _Doc
    from docx.shared import Pt, RGBColor, Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement

    DARK, RED, GREEN = "1F3864", "FCE4D6", "E2EFDA"
    f = record["findings"]

    def setfont(run, size=10, bold=False, color=None):
        run.font.name = "Arial"; run.font.size = Pt(size); run.font.bold = bold
        if color:
            run.font.color.rgb = RGBColor.from_string(color)

    def shade(cell, hexc):
        tcPr = cell._tc.get_or_add_tcPr(); sh = OxmlElement('w:shd')
        sh.set(qn('w:val'), 'clear'); sh.set(qn('w:fill'), hexc); tcPr.append(sh)

    def H(text, size=13):
        p = doc.add_paragraph(); setfont(p.add_run(text), size, True, DARK)

    def body(text, size=10, bold=False):
        p = doc.add_paragraph(); setfont(p.add_run(text), size, bold)

    def table(headers, rows, shades=None):
        t = doc.add_table(rows=1, cols=len(headers)); t.style = "Table Grid"
        for i, h in enumerate(headers):
            c = t.rows[0].cells[i]; c.text = ""
            setfont(c.paragraphs[0].add_run(h), 9, True, "FFFFFF"); shade(c, DARK)
        for ri, row in enumerate(rows):
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = ""; setfont(cells[i].paragraphs[0].add_run(str(v)), 9)
                if shades and shades[ri]:
                    shade(cells[i], shades[ri])

    doc = _Doc()
    doc.styles["Normal"].font.name = "Arial"; doc.styles["Normal"].font.size = Pt(10)
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    setfont(p.add_run("FINANCIAL STATEMENTS REVIEW REPORT"), 17, True, DARK)
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    setfont(p.add_run(record["original_name"]), 11, True, "2E5496")
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    setfont(p.add_run("Reviewed " + record["uploaded_at"].replace("T", " ")), 9, False, "606060")

    if f.get("error"):
        body(f["error"]);
    else:
        H("Numerical & arithmetic findings")
        if f["tally_checks"] or f["pl_checks"] or f["row_checks"] or \
           any(not b["balanced"] for b in f["balance_checks"]):
            rows, sh = [], []
            for c in f["tally_checks"]:
                rows.append([f"Table {c['table']}", c["label"],
                             f"{c['sum_of_parts']:,.2f}", f"{c['stated_total']:,.2f}",
                             c.get("kind", "sum")]); sh.append(RED)
            for c in f["pl_checks"]:
                rows.append([f"Table {c['table']}", c["check"],
                             f"{c['expected']:,.2f}", f"{c['stated']:,.2f}", "P&L"]); sh.append(RED)
            for c in f["row_checks"]:
                rows.append([f"Table {c['table']}", c["row"],
                             f"{c['sum_across']:,.2f}", f"{c['stated_total']:,.2f}", "cross-add"]); sh.append(RED)
            for b in f["balance_checks"]:
                if not b["balanced"]:
                    rows.append(["Balance sheet", "Assets vs Equity+Liabilities",
                                 f"{b['total_assets']:,.2f}", f"{b['equity_plus_liabilities']:,.2f}",
                                 "balance"]); sh.append(RED)
            table(["Source", "Item", "Calculated", "Reported", "Type"], rows, sh)
        else:
            body("All arithmetic checks passed (totals, balance equation, P&L flow, cross-adds).")

        ai = f.get("ai", {})
        if ai.get("enabled"):
            if ai.get("narrative"):
                H("AI summary"); body(ai["narrative"])
            if ai.get("frs_observations"):
                H("FRS compliance observations")
                table(["FRS", "Issue", "Detail", "Recommendation"],
                      [[o.get("frs", ""), o.get("issue", ""), o.get("detail", ""),
                        o.get("recommendation", "")] for o in ai["frs_observations"]])
            if ai.get("grammar_issues"):
                H("Grammar & wording")
                table(["Location", "Current", "Suggested"],
                      [[g.get("location", ""), g.get("current", ""), g.get("suggested", "")]
                       for g in ai["grammar_issues"]])
        else:
            H("AI review"); body(ai.get("error", "AI review not enabled."))

        H("FRS disclosure checklist")
        table(["FRS", "Disclosure", "Detected"],
              [[k["frs"], k["item"], "Yes" if k["present"] else "Check"] for k in f["frs_checks"]],
              [GREEN if k["present"] else RED for k in f["frs_checks"]])

    p = doc.add_paragraph()
    setfont(p.add_run("This automated review is a first-pass aid, not a substitute for a full "
                      "FRS/IFRS compliance review by a qualified reviewer."), 8, False, "808080")
    buf = io.BytesIO(); doc.save(buf); buf.seek(0)
    return buf


@app.route("/report/<rec_id>/report.docx")
@login_required
def download_report(rec_id):
    from flask import send_file
    record = next((r for r in load_records() if r["id"] == rec_id), None)
    if not record:
        abort(404)
    buf = build_word_report(record)
    name = os.path.splitext(record["original_name"])[0] + "_reviewed.docx"
    return send_file(buf, as_attachment=True, download_name=name,
                     mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


@app.template_filter("filesize")
def filesize(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


if __name__ == "__main__":
    # Ensure seed user exists on first run.
    load_users()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
