from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import pyodbc
import re
import sqlite3

def get_db_connection():
    conn = sqlite3.connect('database.db')  # Your DB file
    conn.row_factory = sqlite3.Row  # Allows dict-like access
    return conn

app = Flask(__name__)
app.secret_key = "yoursecretkey"  # move to .env later

# --- SQL Server connection string ---
# Use the driver you actually have installed: "ODBC Driver 18 for SQL Server" or "ODBC Driver 17 for SQL Server"
CONN_STR = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost;"                  # if you use SQLEXPRESS: SERVER=localhost\\SQLEXPRESS;
    "DATABASE=audit_app;"                # make sure this DB exists
    "Trusted_Connection=yes;"            # uses Windows auth; remove and use UID/PWD for SQL logins
    "Encrypt=yes;TrustServerCertificate=yes;"  # avoids TLS errors on dev
)

def get_db():
    return pyodbc.connect(CONN_STR)

# -------------------------
# Home -> redirect to login
# -------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))

# -------------------------
# Register (uses Account.html)
# -------------------------
@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        # accept either the new or old field names
        full_name = (request.form.get("full_name") or request.form.get("name") or "").strip()
        email     = (request.form.get("email") or "").strip().lower()
        username  = (request.form.get("username") or "").strip()
        password  = request.form.get("password") or ""
        confirm   = request.form.get("confirm_password") or ""
        role_raw  = (request.form.get("role") or "").strip()
        role      = role_raw.lower()

        if not all([full_name, email, username, password, confirm, role]):
            flash("Please fill all fields and select a role.")
            return redirect(url_for("account"))
        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("account"))
        if role not in {"admin", "auditor", "user"}:
            flash("Invalid role selected.")
            return redirect(url_for("account"))

        pw_hash = generate_password_hash(password)

        with get_db() as conn:
            cur = conn.cursor()
            # unique check on username or email
            cur.execute("SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email))
            if cur.fetchone():
                flash("Username or email already exists.")
                return redirect(url_for("account"))

            cur.execute(
                """
                INSERT INTO users (username, password_hash, role, full_name, email)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, pw_hash, role, full_name, email),
            )
            conn.commit()

        flash("Account created. You can log in now.")
        return redirect(url_for("login"))

    return render_template("Account.html")

# -------------------------
# Login (uses index.html)
# Supports username OR email in the first field
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = (request.form.get("username") or request.form.get("email") or "").strip()
        password   = request.form.get("password") or ""

        # heuristic: treat as email if it contains '@'
        is_email = "@" in identifier

        with get_db() as conn:
            cur = conn.cursor()
            if is_email:
                cur.execute(
                    "SELECT id, username, password_hash, role, full_name FROM users WHERE email = ?",
                    (identifier,)
                )
            else:
                cur.execute(
                    "SELECT id, username, password_hash, role, full_name FROM users WHERE username = ?",
                    (identifier,)
                )
            row = cur.fetchone()

        if row and check_password_hash(row[2], password):
            session["username"] = row[1]
            session["role"] = row[3]
            flash(f"Welcome {row[4]} ({row[3]})")
            return redirect(url_for(f"{row[3]}_dashboard"))

        flash("Invalid credentials", "danger")

    return render_template("index.html")

# -------------------------
# Dashboards
# -------------------------
def login_required(view):
    from functools import wraps
    @wraps(view)
    def w(*a, **kw):
        if "username" not in session:
            flash("Please log in.")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return w

@app.route("/admin")
@login_required
def admin_dashboard():
    if session.get("role") != "admin":
        flash("Not authorized.")
        return redirect(url_for(f"{session.get('role')}_dashboard"))
    return render_template("admin_dashboard.html")

@app.route("/auditor")
@login_required
def auditor_dashboard():
    if session.get("role") != "auditor":
        flash("Not authorized.")
        return redirect(url_for(f"{session.get('role')}_dashboard"))
    return render_template("auditor_dashboard.html")

@app.route("/user")
@login_required
def user_dashboard():
    if session.get("role") != "user":
        flash("Not authorized.")
        return redirect(url_for(f"{session.get('role')}_dashboard"))
    return render_template("user_dashboard.html")

# metrics for your cards
@app.route("/metrics")
@login_required
def metrics():
    return jsonify({
        "total_audits": 128,
        "pending_audits": 7,
        "compliance_rate": "92%",
        "reports_generated": 54
    })

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))

if __name__== "_main_":
    app.run(debug=True)
    from werkzeug.security import generate_password_hash
print(generate_password_hash("admin123"))  # replace with desired admin password

from werkzeug.security import generate_password_hash
print(generate_password_hash("admin123"))  # replace with desired admin password
# assume conn is a pyodbc connection
with get_db_connection() as conn:
    cur = conn.cursor()
    cur.execute("EXEC dbo.sp_get_metrics")
    row = cur.fetchone()
    # row.total_audits, row.pending_audits, row.compliance_rate, row.reports_generated
    data = {
        "total_audits": row[0],
        "pending_audits": row[1],
        "compliance_rate": row[2],
        "reports_generated": row[3],
    }

