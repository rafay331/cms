from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "dev"  # replace from .env later

# demo in-memory "users" store (username -> password)
USERS = {"demo": "demo123"}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if USERS.get(username) == password:
        return redirect(url_for("dashboard"))
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
        if not all([full_name, email, username, password, confirm]):
            flash("Please fill all fields.")
            return redirect(url_for("account"))
        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("account"))
        if username in USERS:
            flash("Username already taken.")
            return redirect(url_for("account"))
        USERS[username] = password
        flash("Account created. You can log in now.")
        return redirect(url_for("home"))
    return render_template("Account.html")

@app.route("/dashboard")
def dashboard():
    # You can create a templates/dashboard.html later
    return "<h1>Dashboard</h1><p>Logged in!</p><p><a href='/'>Back</a></p>"

if __name__ == "__main__":
    app.run(debug=True)
