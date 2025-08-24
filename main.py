# --- Bootstrap: auto-install required packages if missing ---
import importlib, subprocess, sys

def ensure_pkg(pypi_name, import_name=None):
    name = import_name or pypi_name
    try:
        importlib.import_module(name)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pypi_name])

# Ensure dependencies
for p in [
    ("Flask", "flask"),
    ("Flask-Login", "flask_login"),
    ("Flask-SQLAlchemy", "flask_sqlalchemy"),
    ("Flask-WTF", "flask_wtf"),
    ("requests", "requests"),
]:
    ensure_pkg(p[0], p[1])

# --- Imports (safe after ensure_pkg) ---
import json
import os
from datetime import timedelta, datetime

import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, has_request_context
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    current_user, logout_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf

# --- App / DB Setup ---
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///webhooks.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)

# CSRF
app.config["WTF_CSRF_ENABLED"] = True
csrf = CSRFProtect(app)

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "landing"


# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class WebhookTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    url = db.Column(db.String(2048), nullable=False)


class HookFunction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=True)
    json_template = db.Column(db.Text, nullable=False, default="{}")


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(120), nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    action = db.Column(db.String(160), nullable=False)
    details = db.Column(db.Text, nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Helpers ---
def ensure_default_admin():
    """Create a default admin (admin/admin) if none exists. Change immediately in production!"""
    if User.query.count() == 0:
        admin = User(username="admin", is_admin=True)
        admin.set_password("admin")
        db.session.add(admin)
        db.session.commit()
        log_audit("bootstrap", "Default admin user created")

def is_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except Exception:
        return False

def log_audit(action: str, details: str = None, username: str = None):
    """Record an audit log entry. Works with/without request context."""
    uid = None
    uname = username
    ip = None
    try:
        if has_request_context() and current_user.is_authenticated:
            uid = current_user.id
            uname = current_user.username
    except Exception:
        pass
    try:
        if has_request_context():
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)  # type: ignore[name-defined]
    except Exception:
        ip = None

    entry = AuditLog(
        user_id=uid,
        username=uname,
        ip=ip,
        action=(action or "")[:160],
        details=(details or "")
    )
    try:
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


# Make csrf_token available in Jinja
@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)


# --- Error handling ---
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Security check failed (CSRF). Please try again.", "danger")
    return redirect(request.referrer or url_for("landing"))


# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def landing():
    """
    Landing page with authentication and an Enter button.
    If unauthenticated: show login form.
    If authenticated: show welcome + Enter button to /send.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            log_audit("login_success", f"User {username} signed in")
            flash("Welcome back!", "success")
            return redirect(url_for("landing"))
        else:
            log_audit("login_failed", f"Failed sign-in for {username}", username=username)
            flash("Invalid credentials.", "danger")

    if hasattr(current_user, "is_authenticated") and current_user.is_authenticated:
        return render_template("landing.html", authed=True)

    return render_template("landing.html", authed=False)


@app.route("/logout")
@login_required
def logout():
    uname = current_user.username
    logout_user()
    log_audit("logout", f"User {uname} signed out")
    flash("Logged out.", "info")
    return redirect(url_for("landing"))


@app.route("/send", methods=["GET", "POST"])
@login_required
def send_webhook():
    targets = WebhookTarget.query.order_by(WebhookTarget.name.asc()).all()
    functions = HookFunction.query.order_by(HookFunction.name.asc()).all()
    status = None
    response_text = None
    sent_payload = None

    if request.method == "POST":
        target_id = request.form.get("target_id")
        payload_text = request.form.get("payload", "").strip()
        if not target_id:
            flash("Please select a webhook target.", "warning")
        elif not payload_text:
            flash("Please provide a JSON payload.", "warning")
        elif not is_json(payload_text):
            flash("Payload is not valid JSON.", "danger")
        else:
            target = WebhookTarget.query.get(int(target_id))
            if not target:
                flash("Selected target not found.", "danger")
            else:
                try:
                    payload_json = json.loads(payload_text)
                    r = requests.post(target.url, json=payload_json, timeout=10)
                    status = r.status_code
                    response_text = r.text[:5000]  # cap display size
                    sent_payload = json.dumps(payload_json, indent=2)
                    log_audit("webhook_sent", f"Target={target.name} URL={target.url} HTTP={status}")
                    flash(f"Webhook sent to {target.name} (HTTP {status}).", "success")
                except requests.exceptions.RequestException as e:
                    status = "ERROR"
                    response_text = str(e)
                    sent_payload = payload_text
                    log_audit("webhook_error", f"TargetID={target_id} Error={e}")
                    flash("Failed to send webhook. See details below.", "danger")

    # Allow AJAX to fetch a function's JSON template
    if request.args.get("function_id") and request.headers.get("X-Requested-With") == "XMLHttpRequest":
        fobj = HookFunction.query.get(int(request.args["function_id"]))
        if fobj:
            return jsonify({"template": fobj.json_template})
        return jsonify({"error": "Function not found"}), 404

    return render_template(
        "send.html",
        targets=targets,
        functions=functions,
        status=status,
        response_text=response_text,
        sent_payload=sent_payload
    )


@app.route("/manage", methods=["GET", "POST"])
@login_required
def manage():
    if not current_user.is_admin:
        flash("You do not have access to the management page.", "warning")
        return redirect(url_for("landing"))

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        # --- Webhook target management ---
        if action == "add_target":
            name = request.form.get("target_name", "").strip()
            url = request.form.get("target_url", "").strip()
            if not name or not url:
                flash("Target name and URL are required.", "warning")
            else:
                if WebhookTarget.query.filter_by(name=name).first():
                    flash("A target with that name already exists.", "warning")
                else:
                    db.session.add(WebhookTarget(name=name, url=url))
                    db.session.commit()
                    log_audit("target_add", f"{name} -> {url}")
                    flash("Webhook target added.", "success")

        elif action == "delete_target":
            tid = request.form.get("target_id")
            tgt = WebhookTarget.query.get(int(tid)) if tid else None
            if tgt:
                log_audit("target_delete", f"{tgt.name} -> {tgt.url}")
                db.session.delete(tgt)
                db.session.commit()
                flash("Webhook target deleted.", "info")
            else:
                flash("Target not found.", "warning")

        # --- Function management (add/delete only here) ---
        elif action == "add_function":
            name = request.form.get("func_name", "").strip()
            desc = request.form.get("func_desc", "").strip()
            tmpl = request.form.get("func_template", "").strip() or "{}"
            if not name:
                flash("Function name is required.", "warning")
            elif not is_json(tmpl):
                flash("Function template must be valid JSON.", "warning")
            else:
                if HookFunction.query.filter_by(name=name).first():
                    flash("A function with that name already exists.", "warning")
                else:
                    db.session.add(HookFunction(name=name, description=desc, json_template=tmpl))
                    db.session.commit()
                    log_audit("function_add", f"{name}")
                    flash("Function added.", "success")

        elif action == "delete_function":
            fid = request.form.get("func_id")
            fobj = HookFunction.query.get(int(fid)) if fid else None
            if fobj:
                log_audit("function_delete", f"{fobj.name}")
                db.session.delete(fobj)
                db.session.commit()
                flash("Function deleted.", "info")
            else:
                flash("Function not found.", "warning")

        # --- User management ---
        elif action == "add_user":
            username = request.form.get("new_username", "").strip()
            password = request.form.get("new_password", "")
            is_admin = bool(request.form.get("new_is_admin"))
            if not username or not password:
                flash("Username and password are required.", "warning")
            elif User.query.filter_by(username=username).first():
                flash("Username already exists.", "warning")
            else:
                u = User(username=username, is_admin=is_admin)
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                log_audit("user_add", f"{username} admin={is_admin}")
                flash("User added.", "success")

        elif action == "delete_user":
            uid = request.form.get("user_id")
            if not uid:
                flash("Select a user to delete.", "warning")
            else:
                u = User.query.get(int(uid))
                if u:
                    if u.id == current_user.id:
                        flash("You cannot delete your own user.", "warning")
                    else:
                        log_audit("user_delete", f"{u.username}")
                        db.session.delete(u)
                        db.session.commit()
                        flash("User deleted.", "info")
                else:
                    flash("User not found.", "warning")

        elif action == "toggle_admin":
            uid = request.form.get("user_id")
            u = User.query.get(int(uid)) if uid else None
            if u:
                if u.id == current_user.id:
                    flash("You cannot change your own admin status.", "warning")
                else:
                    u.is_admin = not u.is_admin
                    db.session.commit()
                    log_audit("user_toggle_admin", f"{u.username} -> {u.is_admin}")
                    flash(f"Updated admin status for {u.username}.", "success")
            else:
                flash("User not found.", "warning")

        return redirect(url_for("manage"))

    targets = WebhookTarget.query.order_by(WebhookTarget.name.asc()).all()
    functions = HookFunction.query.order_by(HookFunction.name.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template("manage.html", targets=targets, functions=functions, users=users, logs=logs)


@app.route("/manage/function/update", methods=["POST"])
@login_required
def update_function():
    if not current_user.is_admin:
        flash("You do not have access to update functions.", "warning")
        return redirect(url_for("landing"))

    fid = request.form.get("func_id")
    new_name = request.form.get("func_name", "").strip()
    new_desc = request.form.get("func_desc", "").strip()
    new_tmpl = request.form.get("func_template", "").strip()

    if not fid:
        flash("Select a function to edit.", "warning")
        return redirect(url_for("manage"))

    fobj = HookFunction.query.get(int(fid))
    if not fobj:
        flash("Function not found.", "warning")
        return redirect(url_for("manage"))

    if not new_name:
        flash("Function name is required.", "warning")
        return redirect(url_for("manage"))

    if not is_json(new_tmpl or "{}"):
        flash("Function template must be valid JSON.", "warning")
        return redirect(url_for("manage"))

    if new_name != fobj.name and HookFunction.query.filter_by(name=new_name).first():
        flash("Another function with that name already exists.", "warning")
        return redirect(url_for("manage"))

    old_name = fobj.name
    fobj.name = new_name
    fobj.description = new_desc
    fobj.json_template = new_tmpl or "{}"
    db.session.commit()
    log_audit("function_update", f"{old_name} -> {fobj.name}")
    flash("Function updated.", "success")
    return redirect(url_for("manage"))


@app.route("/manage/function/duplicate", methods=["POST"])
@login_required
def duplicate_function():
    if not current_user.is_admin:
        flash("You do not have access to duplicate functions.", "warning")
        return redirect(url_for("landing"))

    fid = request.form.get("func_id")
    new_name = (request.form.get("new_name") or "").strip()

    if not fid:
        flash("Select a function to duplicate.", "warning")
        return redirect(url_for("manage"))

    fobj = HookFunction.query.get(int(fid))
    if not fobj:
        flash("Function not found.", "warning")
        return redirect(url_for("manage"))

    base = new_name or f"{fobj.name} Copy"
    candidate = base
    i = 2
    while HookFunction.query.filter_by(name=candidate).first():
        candidate = f"{base} ({i})"
        i += 1

    dup = HookFunction(
        name=candidate,
        description=fobj.description,
        json_template=fobj.json_template
    )
    db.session.add(dup)
    db.session.commit()
    log_audit("function_duplicate", f"{fobj.name} -> {dup.name}")
    flash(f"Function duplicated as '{dup.name}'.", "success")
    return redirect(url_for("manage"))


# --- CLI: init DB ---
@app.cli.command("init-db")
def init_db():
    """Initialize the database and create a default admin user."""
    db.create_all()
    ensure_default_admin()
    print("Database initialized. Default admin: admin / admin")


# --- App start (for 'python main.py') ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_default_admin()
    app.run(host="0.0.0.0", port=5001, debug=True)