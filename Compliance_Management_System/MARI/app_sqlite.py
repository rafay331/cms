"""
Flask application for the Compliance Management System using SQLite via SQLAlchemy.

This module defines a Flask application with the following features:

* User registration (``/account``) with full name, email, username, password and role (admin, auditor or user).
* User login (``/login``) supporting either username or email as the identifier.
* Role-based dashboards for admin (``/admin``), auditor (``/auditor``) and regular users (``/user``).  Access is
  restricted based on the authenticated user's role.
* A JSON endpoint (``/metrics``) providing example metric values for dashboard cards.
* Session-based authentication with login required for all dashboard routes.  Users are stored in a SQLite
  database using SQLAlchemy.  Passwords are hashed using Werkzeug's secure hashing utility.

By default the application uses SQLite (``sqlite:///database.db``), but you can override the database by setting
the ``DATABASE_URL`` environment variable to a SQLAlchemy-compatible connection string (e.g. for MySQL or SQL
Server).  The secret key is configurable via ``SECRET_KEY`` environment variable.

To initialize the database tables, simply run this module with Python.  The database will be created on the first
request thanks to the ``@app.before_first_request`` hook.
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Optional

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------------------------------------------------------
# Application setup
# -----------------------------------------------------------------------------

# Create and configure the Flask application
app = Flask(__name__)

# Configure the secret key and database URI.  Using environment variables allows
# deployment environments to override the defaults without modifying code.  If
# DATABASE_URL is not set, SQLite will be used.  If SECRET_KEY is not set, a
# hard-coded fallback is used; in production you should always set SECRET_KEY.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialise the SQLAlchemy ORM
db = SQLAlchemy(app)


# -----------------------------------------------------------------------------
# Database models
# -----------------------------------------------------------------------------

class User(db.Model):
    """Representation of a user account for the system."""

    __tablename__ = 'users'

    id: int = db.Column(db.Integer, primary_key=True)
    full_name: str = db.Column(db.String(120), nullable=False)
    email: str = db.Column(db.String(120), unique=True, nullable=False)
    username: str = db.Column(db.String(80), unique=True, nullable=False)
    password_hash: str = db.Column(db.String(255), nullable=False)
    role: str = db.Column(db.String(20), nullable=False)

    def set_password(self, password: str) -> None:
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Check a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)


# -----------------------------------------------------------------------------
# Initialisation hooks
# -----------------------------------------------------------------------------

@app.before_first_request
def create_tables() -> None:
    """Create all database tables on the first request.

    This ensures that the database exists when you first run the application.
    You could alternatively run ``flask db migrate`` / ``flask db upgrade``
    if using Flask-Migrate, but for simple projects this hook is sufficient.
    """
    db.create_all()


# -----------------------------------------------------------------------------
# Helpers and decorators
# -----------------------------------------------------------------------------

def login_required(view):
    """View decorator to enforce that a user is logged in.

    If the session does not contain a username and role, the user is redirected
    to the login page.  This decorator can be stacked with role checks.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'username' not in session or 'role' not in session:
            flash('Please log in.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped


# -----------------------------------------------------------------------------
# Route handlers
# -----------------------------------------------------------------------------

@app.route('/')
def home() -> object:
    """Root route that redirects to the login page."""
    return redirect(url_for('login'))


@app.route('/account', methods=['GET', 'POST'])
def account() -> object:
    """Handle user registration.

    The registration form supports the fields defined in the template:
    ``full_name``, ``email``, ``username``, ``password``, ``confirm_password``
    and ``role``.  All fields are required and the role must be one of
    ``admin``, ``auditor`` or ``user``.

    If registration succeeds, the user is redirected to the login page with a
    success message.  Otherwise an appropriate flash message is shown.
    """

    if request.method == 'POST':
        full_name = (request.form.get('full_name') or request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        confirm = request.form.get('confirm_password') or ''
        role_raw = (request.form.get('role') or '').strip()
        role = role_raw.lower()

        # Validate input
        if not all([full_name, email, username, password, confirm, role]):
            flash('Please fill all fields and select a role.')
            return redirect(url_for('account'))
        if password != confirm:
            flash('Passwords do not match.')
            return redirect(url_for('account'))
        if role not in ('admin', 'auditor', 'user'):
            flash('Invalid role selected.')
            return redirect(url_for('account'))

        # Check for existing user by username or email
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists.')
            return redirect(url_for('account'))

        # Create the new user
        user = User(full_name=full_name, email=email, username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created. You can log in now.')
        return redirect(url_for('login'))

    # GET request: render the registration form
    return render_template('account.html')


@app.route('/login', methods=['GET', 'POST'])
def login() -> object:
    """Handle user login.

    The form accepts either a username or email in the first field.  The
    password is checked against the stored hash.  On success, the username
    and role are stored in the session and the user is redirected to their
    role-specific dashboard.  On failure, a flash message is shown.
    """

    if request.method == 'POST':
        identifier = (request.form.get('username') or request.form.get('email') or '').strip()
        password = request.form.get('password') or ''

        # Determine if the identifier is an email address
        user: Optional[User]
        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()

        if user and user.check_password(password):
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome {user.full_name} ({user.role})')
            return redirect(url_for(f'{user.role}_dashboard'))

        flash('Invalid credentials', 'danger')

    # GET request or failed login: render login form
    return render_template('index.html')


@app.route('/admin')
@login_required
def admin_dashboard() -> object:
    """Render the admin dashboard, restricting access to admins only."""
    if session.get('role') != 'admin':
        flash('Not authorized.')
        role = session.get('role')
        # Redirect to the appropriate dashboard or login if role is missing
        return redirect(url_for(f'{role}_dashboard')) if role else redirect(url_for('login'))
    return render_template('admin_dashboard.html')


@app.route('/auditor')
@login_required
def auditor_dashboard() -> object:
    """Render the auditor dashboard, restricting access to auditors only."""
    if session.get('role') != 'auditor':
        flash('Not authorized.')
        role = session.get('role')
        return redirect(url_for(f'{role}_dashboard')) if role else redirect(url_for('login'))
    return render_template('auditor_dashboard.html')


@app.route('/user')
@login_required
def user_dashboard() -> object:
    """Render the user dashboard, restricting access to regular users only."""
    if session.get('role') != 'user':
        flash('Not authorized.')
        role = session.get('role')
        return redirect(url_for(f'{role}_dashboard')) if role else redirect(url_for('login'))
    return render_template('user_dashboard.html')


@app.route('/metrics')
@login_required
def metrics() -> object:
    """Return metric values as JSON for the dashboard cards.

    In a real application these values would be computed from the database or
    other business logic.  Here we return static values as placeholders.
    """
    return jsonify({
        'total_audits': 128,
        'pending_audits': 7,
        'compliance_rate': '92%',
        'reports_generated': 54
    })


@app.route('/logout')
def logout() -> object:
    """Log the current user out by clearing the session."""
    session.clear()
    flash('Logged out.')
    return redirect(url_for('login'))


if __name__ == '__main__':
    # When running this file directly, start the development server.  The debug
    # flag enables hot reloading and improved error messages.  In production
    # environments you should disable debug and use a production WSGI server.
    app.run(debug=True)
