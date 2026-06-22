# FS Review Portal

A secure web app for uploading financial-statement files (.docx / .pdf / .xlsx)
and viewing an automated review report. Access is gated by username + password.

## What it does

- **Login** — passwords are hashed (never stored in plain text); sessions are signed.
- **Upload** — drag in a `.docx`, `.pdf`, `.xlsx`, or `.xls` (max 25 MB).
- **Review report** — for `.docx` files it auto-detects the standard FS sections,
  counts tables, and runs column-total tally checks, then shows the findings.
- **Manage** — download the original or delete a record.

> The automated review is a first-pass aid, not a substitute for a full FRS/IFRS
> compliance review.

## Run it locally

You need Python 3.10+.

```bash
cd "FS review in HTML"
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

**First login:** username `admin`, password `ChangeMe123!`
(or set `ADMIN_PASSWORD` before the first run). Change it right away — see below.

## Managing users

```bash
python manage_users.py add jane SuperSecret123 "Jane Tan"
python manage_users.py list
python manage_users.py remove jane
```

To replace the default admin password, just `add admin <new password> "Administrator"`.

## Deploy it (hosted website)

The app is a standard Flask + gunicorn app, so any of these work. **Render** is the
simplest for a non-developer:

### Render (recommended)
1. Put this folder in a GitHub repo (or upload it).
2. On https://render.com → **New → Web Service** → connect the repo.
3. Settings:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `gunicorn app:app`
4. Add environment variables (Render → Environment):
   - `FLASK_SECRET_KEY` — a long random string (keeps logins secure across restarts).
   - `ADMIN_PASSWORD` — your chosen first admin password.
5. Deploy. Render gives you a public `https://...onrender.com` URL.

### Important for hosting
- Uploaded files and the users/records files are stored on disk under `uploads/`
  and `data/`. On hosts with ephemeral disks (free Render tier), these reset on
  redeploy. For permanent storage, attach a persistent disk or move storage to a
  database / cloud bucket — happy to set that up if you need it.
- Always set `FLASK_SECRET_KEY` in production; otherwise sessions reset on restart.

## Files

| File | Purpose |
|------|---------|
| `app.py` | The web app (routes, auth, review logic). |
| `templates/` | HTML pages (login, dashboard, report). |
| `manage_users.py` | Add / list / remove users from the command line. |
| `requirements.txt` | Python dependencies. |
| `Procfile` | Start command for hosts like Render/Heroku. |
| `uploads/`, `data/` | Created on first run; hold files and user/record data. |
