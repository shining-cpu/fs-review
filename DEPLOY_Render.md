# Host the FS Review Portal on GitHub + Render (free)

Two stages: put the code on GitHub (website, drag-and-drop), then point Render at it.
All in the browser — no command line. End result: a public `https://...onrender.com`
address with your password login.

---

## Stage 1 — Put the code on GitHub

1. In the browser address bar go to **github.com/new** (sign in / create a free
   account first if needed).
2. **Repository name:** `fs-review`  ·  choose **Private**  ·  click **Create repository**.
3. On the next page, click the link **"uploading an existing file"**.
4. Open your project folder in File Explorer:
   `Documents → Claude → Projects → FS review in HTML`
5. Select and drag these **into the GitHub upload box**:
   - `app.py`
   - `manage_users.py`
   - `requirements.txt`
   - `Procfile`
   - `README.md`
   - `.gitignore`
   - the **`templates`** folder (drag the whole folder — GitHub keeps the structure)

   Do **not** upload the `data` or `uploads` folders, or the PythonAnywhere files —
   they're not needed.
6. Click **Commit changes**. Your repo now has the code.

---

## Stage 2 — Deploy on Render

1. Go to **render.com** and click **Get Started / Sign in** — choose **"Sign in with
   GitHub"** (this also lets Render see your repo). Approve access to the `fs-review` repo.
2. Click **New +** → **Web Service**.
3. Pick your **fs-review** repository → **Connect**.
4. Fill in the settings:
   - **Name:** anything (e.g. `fs-review`)
   - **Region:** leave default
   - **Branch:** `main`
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `gunicorn app:app`
   - **Instance type:** **Free**
5. Click **Advanced** (or scroll to **Environment Variables**) and add two:
   - Key `FLASK_SECRET_KEY`  ·  Value: a long random string of letters/numbers
   - Key `ADMIN_PASSWORD`  ·  Value: the first admin password you want
6. Click **Create Web Service**. Render builds and deploys (a few minutes). When it's
   live you'll get a link like `https://fs-review-xxxx.onrender.com`.
7. Open it, log in with **admin** + the password you set. Done.

---

## Things to know about Render's free tier

- **It sleeps when idle.** After ~15 minutes of no use, the free service powers down.
  The next visit takes roughly 50 seconds to wake up, then it's normal. (Paid tiers
  stay awake.)
- **Storage resets on redeploy.** Uploaded files and any extra user accounts live on a
  temporary disk and are wiped whenever Render rebuilds the service. Fine for testing;
  for permanent storage we'd add a small database — ask me when you want that.
- **Updating the app later:** re-upload the changed file to GitHub (same "Add file →
  Upload files" flow). Render redeploys automatically within a minute.

## Adding more reviewers
Because the free disk resets, the simplest for now is to share the admin login. For
permanent multi-user accounts, we'd move to the database setup mentioned above.
