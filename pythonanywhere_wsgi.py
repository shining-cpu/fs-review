# ===========================================================================
# PythonAnywhere WSGI config for the FS Review Portal
# Paste this into your WSGI configuration file (Web tab -> WSGI link),
# then edit the THREE values marked below.
# ===========================================================================
import os
import sys

# ---- 1) Your PythonAnywhere username --------------------------------------
USERNAME = "YOURUSERNAME"        # <-- change to your PythonAnywhere username

# ---- 2) Your secrets ------------------------------------------------------
os.environ["ADMIN_PASSWORD"] = "ChangeThisPassword123!"   # <-- first admin password
os.environ["FLASK_SECRET_KEY"] = "put-a-long-random-string-here-abc123xyz789"  # <-- any long random text

# ---- Make the app importable ----------------------------------------------
project_path = "/home/" + USERNAME + "/mysite"
if project_path not in sys.path:
    sys.path.insert(0, project_path)

# PythonAnywhere runs the app from /var/www, so anchor file paths to the project
os.chdir(project_path)

# ---- Hand the Flask app to the web server ---------------------------------
from app import app as application
