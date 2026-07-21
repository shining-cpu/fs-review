# Assembly Works — FS Review Portal

Internal web portal that reviews unaudited financial statements (Word .docx) for
Singapore-incorporated companies. Upload an FS, get back:

- A severity-ranked punch list of corrections (error + recommended correction)
- Deterministic arithmetic checks — balance equation, P&L casts, cross-adds,
  cash-flow ties, note-to-face ties, related-party / s.162 director loans,
  going-concern solvency
- AI review (Gemini) — FRS observations, corrected figures, suggested wording
- Paste-ready disclosure templates triggered by the findings
- A **Reviewed report** (.docx) and a **Revised FS** — the original file with
  Word margin comments, tracked-change phrasing corrections, and proposed
  disclosures appended in blue

Live at **https://fs-review.onrender.com** · Repo `shining-cpu/fs-review`

---

## Architecture (one file)

Everything lives in **`app.py`** — Flask routes, embedded HTML templates
(Jinja2 DictLoader), the review engine, Word report builders, storage and auth.

| File | Purpose |
|------|---------|
| `app.py` | The whole application |
| `Procfile` | How Render starts it: `gunicorn app:app --workers 1 --threads 4 --timeout 180` |
| `requirements.txt` | Python dependencies |
| `test_app.py` | Test suite for the review engine (`pytest -q`) |
| `.github/workflows/ci.yml` | Runs the tests automatically on every push to GitHub |
| `logo.png` (optional) | Assembly Works logo — appears on Word reports if present |

**Storage:** Neon Postgres when `DATABASE_URL` is set (users, records, OTP codes,
login tokens, audit log). Without it, JSON files under `data/` — fine for local
testing only (Render's disk is wiped on each deploy).

**Login:** password, email magic-link, or emailed 6-digit OTP (10-min expiry,
5 attempts). Invite-only; admins and users with invite rights can add people.

**Audit trail:** every login, upload, download, delete and invite is logged —
see *Audit log* in the nav (admin only), downloadable as CSV, plus a one-click
JSON backup at *Download backup*.

---

## Environment variables (Render → Environment)

| Variable | Required | What it does |
|----------|----------|--------------|
| `DATABASE_URL` | Yes (production) | Neon Postgres connection string |
| `FLASK_SECRET_KEY` | **Yes — set this** | Keeps sessions valid across restarts. Any long random string. Without it everyone is logged out on every deploy/restart |
| `GEMINI_API_KEY` | For AI review | Google AI Studio key (free tier) |
| `GEMINI_MODEL` | No | Defaults to `gemini-2.5-flash` — the free model. Do **not** set `gemini-2.5-pro` (not on free tier, quota 0) |
| `RESEND_API_KEY` | For email login | Resend key (magic links + OTP emails) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Yes | Seeds the admin account |
| `APP_BASE_URL` | For email login | `https://fs-review.onrender.com` |

---

## Deploying a change (the runbook)

1. Edit `app.py` (or have Claude edit it).
2. GitHub → repo → open the file → **Upload files** / edit → commit to `main`.
   CI runs the tests automatically — a green tick means the engine still works.
3. Render dashboard → the service → **Manual Deploy → Deploy latest commit**.
4. Wait for **"Deploy live"** on the Events tab (~2–4 min).
5. Hard-refresh the portal (Ctrl+Shift+R).

If a deploy breaks the site: Render → Events → previous deploy → **Rollback**.

---

## Running locally / tests

```bash
pip install -r requirements.txt pytest
python app.py            # http://localhost:5000 (JSON-file storage)
pytest -q                # run the engine tests
```

---

## Troubleshooting

| Symptom | Cause & fix |
|---------|-------------|
| First page load takes ~1 min | Render free tier sleeps after 15 min idle. Fix: UptimeRobot pinging `/healthz` every 10 min, or upgrade to Starter ($7/mo, always-on) |
| "Out of memory" in Render logs | 512 MB free-tier limit; a huge file or concurrent reviews. It auto-restarts. Upgrade to Starter for 2 GB |
| AI review section says error / empty | Check `GEMINI_API_KEY` is set and `GEMINI_MODEL` is `gemini-2.5-flash`. Free tier also rate-limits: wait a minute and re-run |
| Everyone logged out after deploy | `FLASK_SECRET_KEY` not set (see above) |
| OTP / magic-link emails not arriving | Check `RESEND_API_KEY`, and that assemblyworks.co is verified in Resend |
| Upload rejected | 25 MB limit; .docx only for review |

---

## Notes & known limits

- Free Gemini tier may use submitted content for training — accepted trade-off
  for now; upgrade to a paid key for confidentiality-sensitive clients.
- The automated review is a first-pass aid, not a substitute for a qualified
  reviewer's full FRS/IFRS review.
- PPE-note recompute is deliberately AI-guided (formats vary too much for a
  deterministic rule).
