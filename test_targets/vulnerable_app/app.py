"""
Deliberately Vulnerable Flask Application — Test Target for Co-AI-RedTeam.

⚠️ DO NOT deploy this. It contains intentional security flaws for testing.
"""

import os
import sqlite3
import subprocess

from flask import Flask, redirect, render_template_string, request, session

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-123"  # CWE-798: Hardcoded Credentials


def get_db():
    """Get database connection."""
    conn = sqlite3.connect("users.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    return conn


# ─── CWE-89: SQL Injection ──────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    """Login endpoint — vulnerable to SQL injection."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    # VULNERABLE: Direct string interpolation in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query).fetchone()

    if result:
        session["user"] = result[1]
        session["role"] = result[3]
        return redirect("/dashboard")
    return "Login failed", 401


# ─── CWE-78: OS Command Injection ───────────────────────────────────────────

@app.route("/ping")
def ping():
    """Network diagnostic tool — vulnerable to command injection."""
    host = request.args.get("host", "localhost")

    # VULNERABLE: User input passed directly to shell command
    output = subprocess.check_output(
        f"ping -c 1 {host}",
        shell=True,
        text=True,
    )
    return f"<pre>{output}</pre>"


# ─── CWE-79: Cross-Site Scripting (XSS) ─────────────────────────────────────

@app.route("/search")
def search():
    """Search page — vulnerable to reflected XSS."""
    query = request.args.get("q", "")

    # VULNERABLE: User input rendered without escaping
    template = f"""
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <p>No results found.</p>
    </body>
    </html>
    """
    return render_template_string(template)


# ─── CWE-22: Path Traversal ─────────────────────────────────────────────────

@app.route("/file")
def read_file():
    """File reader — vulnerable to path traversal."""
    filename = request.args.get("name", "readme.txt")

    # VULNERABLE: No path validation — allows ../../etc/passwd
    filepath = os.path.join("uploads", filename)
    try:
        with open(filepath, "r") as f:
            return f"<pre>{f.read()}</pre>"
    except FileNotFoundError:
        return "File not found", 404


# ─── CWE-918: Server-Side Request Forgery (SSRF) ────────────────────────────

@app.route("/fetch")
def fetch_url():
    """URL fetcher — vulnerable to SSRF."""
    import urllib.request

    url = request.args.get("url", "")

    # VULNERABLE: No URL validation — allows internal network access
    try:
        response = urllib.request.urlopen(url)
        return response.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}", 500


# ─── CWE-502: Insecure Deserialization ──────────────────────────────────────

@app.route("/load", methods=["POST"])
def load_data():
    """Data loader — vulnerable to insecure deserialization."""
    import pickle
    import base64

    data = request.form.get("data", "")

    # VULNERABLE: Deserializing untrusted user input
    try:
        obj = pickle.loads(base64.b64decode(data))
        return f"Loaded: {obj}"
    except Exception as e:
        return f"Error: {e}", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
