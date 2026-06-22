# Host the FS Review Portal on PythonAnywhere (no GitHub, no command line)

Everything below is done in your web browser. Takes about 10 minutes.
Your site will end up at `https://YOURUSERNAME.pythonanywhere.com`.

---

## Step 1 — Create a free account
1. Go to https://www.pythonanywhere.com/registration/register/beginner/
2. Sign up (free "Beginner" plan). Pick a username — it becomes part of your web
   address, e.g. username `acme` → `acme.pythonanywhere.com`.

## Step 2 — Create the web app
1. After logging in, click the **Web** tab (top menu).
2. Click **Add a new web app** → **Next**.
3. When asked for a framework, choose **Manual configuration** (NOT "Flask").
4. Choose **Python 3.10** (or the highest 3.x shown) → **Next**.
5. It finishes and shows your web app config page. Leave it open.

## Step 3 — Upload the project files
1. Click the **Files** tab.
2. Under "Directories", you'll see a folder named **mysite/** — click it.
   (If it's not there, type `mysite` in the "New directory" box and create it.)
3. Inside `mysite/`, use **Upload a file** to upload:
   - `app.py`
   - `manage_users.py`
   - `requirements.txt`
4. Still inside `mysite/`, create a new directory called **templates**
   (type `templates` in the new-directory box → create), open it, and upload
   these four files into it:
   - `base.html`
   - `login.html`
   - `dashboard.html`
   - `report.html`

   ⚠️ The four HTML files MUST sit inside `mysite/templates/`, not loose in `mysite/`.

## Step 4 — Install python-docx
1. Click the **Consoles** tab → **Bash** (this opens a black box in the browser).
2. Type exactly this and press Enter:
   ```
   pip install --user python-docx
   ```
3. Wait for it to finish (a few seconds), then you can close the console tab.
   (Flask itself is already installed for you.)

## Step 5 — Point the web app at the FS Review app
1. Go back to the **Web** tab.
2. Scroll to the **Code** section. Next to "WSGI configuration file" there's a
   link like `/var/www/YOURUSERNAME_pythonanywhere_com_wsgi.py` — click it.
3. It opens an editor with some sample code. **Select all and delete it**, then
   paste the contents of the file `pythonanywhere_wsgi.py` I gave you
   (open that file, copy everything).
4. In what you pasted, change three things:
   - replace `YOURUSERNAME` with your actual PythonAnywhere username,
   - set `ADMIN_PASSWORD` to the first admin password you want,
   - set `FLASK_SECRET_KEY` to any long random string of letters/numbers.
5. Click the green **Save** button (top right of the editor).

## Step 6 — Launch
1. Back on the **Web** tab, click the big green **Reload** button.
2. Click your site link at the top: `https://YOURUSERNAME.pythonanywhere.com`
3. Log in with username **admin** and the password you set in step 5.

Done — that's your live, password-protected FS review site.

---

## Adding more reviewers later
In the **Consoles → Bash** window, run:
```
cd ~/mysite
python3 manage_users.py add jane SomePassword123 "Jane Tan"
```
Then reload the web app. (Or share the admin login for now.)

## Notes
- The free plan needs you to click "Run until 3 months from today" on the Web tab
  every ~3 months to keep it alive — PythonAnywhere reminds you by email.
- Uploaded financial files are stored on your PythonAnywhere account under
  `mysite/uploads/`. They persist (unlike free Render).
