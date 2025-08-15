from __future__ import annotations

import os
import urllib.parse
from functools import wraps
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------------------------------------------------------
# App & DB config
# -----------------------------------------------------------------------------
app = Flask(__name__)

# Secret key for sessions (use env var in production)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

def _default_mssql_url() -> str:
    """
    Build a SQL Server URL using the first available ODBC SQL Server driver.
    Uses Windows auth to localhost; change DB name if needed.
    """
    driver = "ODBC Driver 18 for SQL Server"
    try:
        import pyodbc
        drivers = [d for d in pyodbc.drivers() if "SQL Server" in d]
        if drivers:
            # Prefer 18, then 17, else last available
            driver = next((d for d in drivers if "18" in d), drivers[0])
    except Exception:
        # pyodbc not installed yet; keep default
        pass

    drv = urllib.parse.quote_plus(driver)
    return (
        "mssql+pyodbc://@localhost/audit_app"
        f"?driver={drv}&trusted_connection=yes&Encrypt=yes&TrustServerCertificate=yes"
    )

# IMPORTANT: if you set DATABASE_URL in PowerShell, the app will use it.
# Example:
#   $env:DATABASE_URL="mssql+pyodbc://@localhost%5CSQLEXPRESS/audit_app?driver=ODBC+Driver+18+for+SQL+Server&trusted_connection=yes&Encrypt=yes&TrustServerCertificate=yes"
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", _default_mssql_url())
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Model
# -----------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"

    id           = db.Column(db.Integer, primary_key=True)
    full_name    = db.Column(db.String(120), nullable=False)
    email        = db.Column(db.String(120), unique=True, nullable=False)
    username     = db.Column(db.String(80),  unique=True, nullable=False)
    password_hash= db.Column(db.String(255), nullable=False)
    role         = db.Column(db.String(20),  nullable=False)  # admin|auditor|user
    created_at   = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

# -----------------------------------------------------------------------------
# Create tables once at startup (Flask 3.x compatible)
# -----------------------------------------------------------------------------
def init_db():
    with app.app_context():
        db.create_all()

init_db()

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session or "role" not in session:
            flash("Please log in.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                flash("Not authorized.")
                role = session.get("role")
                return redirect(url_for(f"{role}_dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email     = request.form.get("email", "").strip().lower()
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "")
        confirm   = request.form.get("confirm_password", "")
        role      = request.form.get("role", "").strip().lower()

        if not all([full_name, email, username, password, confirm, role]):
            flash("Please fill all fields.")
            return redirect(url_for("account"))
        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("account"))
        if role not in ("admin", "auditor", "user"):
            flash("Invalid role.")
            return redirect(url_for("account"))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.")
            return redirect(url_for("account"))

        u = User(full_name=full_name, email=email, username=username, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()

        flash("Account created. You can log in now.")
        return redirect(url_for("login"))

    # NOTE: make sure your template is named exactly 'account.html'
    return render_template("account.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = (request.form.get("username") or "").strip()
        password   = request.form.get("password") or ""

        # username or email
        user = User.query.filter_by(email=identifier).first() if "@" in identifier \
               else User.query.filter_by(username=identifier).first()

        if user and user.check_password(password):
            session["username"] = user.username
            session["role"]     = user.role
            flash(f"Welcome {user.full_name} ({user.role})")
            return redirect(url_for(f"{user.role}_dashboard"))

        flash("Invalid credentials.")

    # NOTE: make sure your template is named exactly 'index.html'
    return render_template("index.html")

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/auditor")
@role_required("auditor")
def auditor_dashboard():
    return render_template("auditor_dashboard.html")

@app.route("/user")
@role_required("user")
def user_dashboard():
    return render_template("user_dashboard.html")

@app.route("/metrics")
@login_required
def metrics():
    # Try stored procedure if we're on SQL Server (mssql+pyodbc)
    if app.config["SQLALCHEMY_DATABASE_URI"].lower().startswith("mssql"):
        try:
            with db.engine.begin() as conn:
                result = conn.exec_driver_sql("EXEC dbo.sp_get_metrics")
                row = result.fetchone()
                if row:
                    return jsonify({
                        "total_audits":      row[0],
                        "pending_audits":    row[1],
                        "compliance_rate":   row[2],
                        "reports_generated": row[3],
                    })
        except Exception as e:
            # Log to console, keep UI working with fallback numbers
            print(f"[metrics] Stored procedure failed: {e}")

    # Fallback demo metrics
    return jsonify({
        "total_audits": 128,
        "pending_audits": 7,
        "compliance_rate": "92%",
        "reports_generated": 54,
    })

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
