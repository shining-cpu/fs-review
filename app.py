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


def check_table_totals(t_idx, table):
    """Find rows labelled '...total...' and check the column sums above them.

    Works generically: for each numeric column, when a 'total' row is reached,
    the values since the previous total (a section) should sum to it.
    """
    issues = []
    labels, numgrid = _grid(table)
    if len(numgrid) < 3:
        return issues
    ncols = max((len(r) for r in numgrid), default=0)
    for c in range(1, ncols):  # column 0 is usually the label
        seg = []                # numbers accumulated since last total
        for r, label in enumerate(labels):
            # Skip header rows (empty label) — their year numbers (2025/2024)
            # must not be summed into the line items.
            if not label.strip():
                continue
            val = numgrid[r][c] if c < len(numgrid[r]) else None
            is_total = "total" in label.lower()
            if is_total and val is not None and seg:
                parts = [v for v in seg if v is not None]
                if len(parts) >= 2:
                    s = sum(parts)
                    diff = s - val
                    rel = abs(diff) / (abs(val) + 1e-9)
                    if abs(diff) > 0.5 and val != 0 and rel < 3:
                        issues.append({
                            "table": t_idx + 1,
                            "label": label.strip()[:60] or f"column {c+1}",
                            "sum_of_parts": round(s, 2),
                            "stated_total": round(val, 2),
                            "difference": round(diff, 2),
                        })
                seg = []        # start a new section after a total
            elif val is not None:
                seg.append(val)
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


def review_docx(path):
    """Return a dict of findings for a .docx file (rule-based, offline)."""
    findings = {
        "type": "docx",
        "sections_found": [], "sections_missing": [],
        "tables": 0, "paragraph_count": 0,
        "tally_checks": [], "balance_checks": [],
        "frs_checks": [], "language_issues": [],
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

    findings["balance_checks"] = check_balance_equation(doc)
    findings["language_issues"] = check_language(doc)
    findings["frs_checks"] = check_frs(full_text_low, "inventor" in full_text_low)

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
        "frs_checks": [], "language_issues": [],
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
