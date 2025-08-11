from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify

app = Flask(__name__)
app.secret_key = "dev"  # TODO: move to .env later

# In-memory users (resets on restart)
# username -> dict(password, role, full_name, email)
USERS = {
    "admin":   {"password": "admin123",   "role": "admin",   "full_name": "System Admin", "email": "admin@example.com"},
    "auditor": {"password": "auditor123", "role": "auditor", "full_name": "Lead Auditor", "email": "auditor@example.com"},
    "demo":    {"password": "demo123",    "role": "user",    "full_name": "Demo User",    "email": "demo@example.com"},
}
ALLOWED_ROLES = {"admin", "auditor", "user"}


# -------------------------
# Helpers / Decorators
# -------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session or "role" not in session:
            flash("Please log in.")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                flash("Not authorized.")
                # redirect to user's own dashboard if possible
                role = session.get("role")
                if role in ("admin", "auditor", "user"):
                    return redirect(url_for(f"{role}_dashboard"))
                return redirect(url_for("home"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def dashboard_endpoint_for(role: str) -> str:
    return {
        "admin": "admin_dashboard",
        "auditor": "auditor_dashboard",
        "user": "user_dashboard",
    }.get(role, "home")


# -------------------------
# Routes
# -------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user = USERS.get(username)

    if user and user["password"] == password:
        session["username"] = username
        session["role"] = user["role"]
        flash(f"Welcome {user['full_name']} ({user['role']})")
        return redirect(url_for(dashboard_endpoint_for(user["role"])))

    flash("Invalid username or password.")
    return redirect(url_for("home"))


@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email     = request.form.get("email", "").strip()
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "")
        confirm   = request.form.get("confirm_password", "")
        role_raw  = request.form.get("role", "").strip()  # "Admin" / "Auditor" / "User"
        role      = role_raw.lower()

        if not all([full_name, email, username, password, confirm, role]):
            flash("Please fill all fields and select a role.")
            return redirect(url_for("account"))
        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("account"))
        if role not in ALLOWED_ROLES:
            flash("Invalid role selected.")
            return redirect(url_for("account"))
        if username in USERS:
            flash("Username already exists.")
            return redirect(url_for("account"))

        USERS[username] = {
            "password": password,  # plain for demo; will hash when DB is added
            "role": role,
            "full_name": full_name,
            "email": email,
        }
        flash("Account created. You can log in now.")
        return redirect(url_for("home"))

    return render_template("Account.html")


# Compatibility route: /dashboard -> send to role dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")
    return redirect(url_for(dashboard_endpoint_for(role)))


# Role dashboards (render your Bootstrap templates)
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


# Metrics API used by all three dashboards
@app.route("/metrics")
@login_required
def metrics():
    # Dummy values for now; replace with real computations later
    data = {
        "total_audits": 128,
        "pending_audits": 7,
        "compliance_rate": "92%",
        "reports_generated": 54
    }
    return jsonify(data)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("home"))


# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)
