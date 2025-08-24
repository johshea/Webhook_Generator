
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
    ("jsonschema", "jsonschema"),
    ("requests", "requests"),
]:
    ensure_pkg(p[0], p[1])

# --- Imports (safe after ensure_pkg) ---
import csv
import io
import json
import os
from datetime import timedelta, datetime

import requests
from jsonschema import validate as jsonschema_validate, ValidationError as JSONSchemaValidationError
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, has_request_context, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    current_user, logout_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf

# --- App / Config ---
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///webhooks.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)
# Inactivity + sessions
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
# Rate limiting (per-user)
app.config["RATE_LIMIT_MAX"] = int(os.environ.get("RATE_LIMIT_MAX", "30"))
app.config["RATE_LIMIT_WINDOW_SECONDS"] = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "300"))

csrf = CSRFProtect(app)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "landing"


# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # legacy flag for compatibility
    role = db.Column(db.String(20), default="sender")  # 'admin', 'sender', 'viewer'

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin_effective(self) -> bool:
        return bool(self.is_admin) or self.role == "admin"

    @property
    def can_send(self) -> bool:
        return self.is_admin_effective or self.role in ("sender",)


class WebhookTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    url = db.Column(db.String(2048), nullable=False)


class HeaderSet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.String(255))
    headers_json = db.Column(db.Text, nullable=False, default="{}")


class HookFunction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=True)
    json_template = db.Column(db.Text, nullable=False, default="{}")
    schema_json = db.Column(db.Text, nullable=True)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(120), nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    action = db.Column(db.String(160), nullable=False)
    details = db.Column(db.Text, nullable=True)


class SendAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Helpers & Migrations ---
def ensure_default_admin():
    if User.query.count() == 0:
        admin = User(username="admin", is_admin=True, role="admin")
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

def as_json_or_empty(s: str):
    try:
        return json.loads(s) if s else None
    except Exception:
        return None

def log_audit(action: str, details: str = None, username: str = None):
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

def migrate_schema():
    db.create_all()
    # add role to user if missing
    try:
        cols = [c["name"] for c in db.session.execute(db.text("PRAGMA table_info('user')")).mappings()]
        if "role" not in cols:
            db.session.execute(db.text("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'sender'"))
            db.session.commit()
    except Exception:
        pass
    # add schema_json
    try:
        cols = [c["name"] for c in db.session.execute(db.text("PRAGMA table_info('hook_function')")).mappings()]
        if "schema_json" not in cols:
            db.session.execute(db.text("ALTER TABLE hook_function ADD COLUMN schema_json TEXT"))
            db.session.commit()
    except Exception:
        pass
    # backfill roles for admins
    try:
        for u in User.query.all():
            if u.is_admin and u.role != "admin":
                u.role = "admin"
        db.session.commit()
    except Exception:
        db.session.rollback()


@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Security check failed (CSRF). Please try again.", "danger")
    return redirect(request.referrer or url_for("landing"))


# Inactivity timeout
@app.before_request
def enforce_idle_timeout():
    if hasattr(current_user, "is_authenticated") and current_user.is_authenticated:
        now = datetime.utcnow()
        last_ts = session.get("last_activity")
        if last_ts is not None:
            try:
                last_dt = datetime.utcfromtimestamp(float(last_ts))
                idle = now - last_dt
                if idle > timedelta(minutes=15):
                    try:
                        log_audit("auto_logout_inactive", f"Idle for {int(idle.total_seconds() // 60)}m {int(idle.total_seconds() % 60)}s")
                    except Exception:
                        pass
                    logout_user()
                    session.clear()
                    flash("You were signed out after 15 minutes of inactivity.", "warning")
                    return redirect(url_for("landing"))
            except Exception:
                pass
        session["last_activity"] = now.timestamp()
        session.permanent = True


# Routes
@app.route("/", methods=["GET", "POST"])
def landing():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=False)
            session.permanent = True
            session['last_activity'] = datetime.utcnow().timestamp()
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


def require_can_send():
    if not (hasattr(current_user, "is_authenticated") and current_user.is_authenticated and current_user.can_send):
        flash("You don't have permission to send webhooks.", "warning")
        return False
    return True


@app.route("/send", methods=["GET", "POST"])
@login_required
def send_webhook():
    if not require_can_send():
        return redirect(url_for("landing"))

    targets = WebhookTarget.query.order_by(WebhookTarget.name.asc()).all()
    functions = HookFunction.query.order_by(HookFunction.name.asc()).all()
    headersets = HeaderSet.query.order_by(HeaderSet.name.asc()).all()
    status = None
    response_text = None
    sent_payload = None
    send_blocked = None

    if request.method == "POST":
        # Rate limit
        window = timedelta(seconds=app.config["RATE_LIMIT_WINDOW_SECONDS"])
        cutoff = datetime.utcnow() - window
        count = SendAttempt.query.filter(
            SendAttempt.user_id == current_user.id,
            SendAttempt.timestamp >= cutoff
        ).count()
        if count >= app.config["RATE_LIMIT_MAX"]:
            send_blocked = f"Rate limit exceeded: max {app.config['RATE_LIMIT_MAX']} sends per {app.config['RATE_LIMIT_WINDOW_SECONDS']}s window."
            flash(send_blocked, "danger")
        else:
            db.session.add(SendAttempt(user_id=current_user.id))
            db.session.commit()

            target_id = request.form.get("target_id")
            payload_text = request.form.get("payload", "").strip()
            function_id = request.form.get("function_id")
            headerset_id = request.form.get("headerset_id")

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
                    # Optional JSON Schema validation
                    if function_id:
                        fobj = HookFunction.query.get(int(function_id))
                        if fobj and fobj.schema_json:
                            schema = as_json_or_empty(fobj.schema_json)
                            if schema:
                                try:
                                    jsonschema_validate(json.loads(payload_text), schema)
                                except JSONSchemaValidationError as e:
                                    flash(f"Schema validation failed: {str(e).splitlines()[0]}", "danger")
                                    return render_template(
                                        "send.html",
                                        targets=targets, functions=functions, headersets=headersets,
                                        status=None, response_text=None, sent_payload=payload_text
                                    )
                    # Prepare headers
                    headers = {}
                    if headerset_id:
                        hs = HeaderSet.query.get(int(headerset_id))
                        if hs:
                            try:
                                hdict = json.loads(hs.headers_json or "{}")
                                if not isinstance(hdict, dict):
                                    raise ValueError("Headers JSON must be an object")
                                headers = {str(k): str(v) for k, v in hdict.items()}
                            except Exception:
                                flash("Header set is invalid and was ignored.", "warning")

                    try:
                        payload_json = json.loads(payload_text)
                        r = requests.post(target.url, json=payload_json, headers=headers or None, timeout=10)
                        status = r.status_code
                        response_text = r.text[:5000]
                        sent_payload = json.dumps(payload_json, indent=2)
                        used_hdrs = ", ".join(headers.keys()) if headers else "none"
                        log_audit("webhook_sent", f"Target={target.name} URL={target.url} HTTP={status} Headers={used_hdrs}")
                        flash(f"Webhook sent to {target.name} (HTTP {status}).", "success")
                    except requests.exceptions.RequestException as e:
                        status = "ERROR"
                        response_text = str(e)
                        sent_payload = payload_text
                        log_audit("webhook_error", f"TargetID={target_id} Error={e}")
                        flash("Failed to send webhook. See details below.", "danger")

    # AJAX for template/schema
    if request.args.get("function_id") and request.headers.get("X-Requested-With") == "XMLHttpRequest":
        fobj = HookFunction.query.get(int(request.args["function_id"]))
        if fobj:
            return jsonify({"template": fobj.json_template, "schema": fobj.schema_json})
        return jsonify({"error": "Function not found"}), 404

    return render_template(
        "send.html",
        targets=targets,
        functions=functions,
        headersets=headersets,
        status=status,
        response_text=response_text,
        sent_payload=sent_payload
    )


@app.route("/manage", methods=["GET", "POST"])
@login_required
def manage():
    if not current_user.is_admin_effective:
        flash("You do not have access to the management page.", "warning")
        return redirect(url_for("landing"))

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        # Targets
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

        # Functions
        elif action == "add_function":
            name = request.form.get("func_name", "").strip()
            desc = request.form.get("func_desc", "").strip()
            tmpl = request.form.get("func_template", "").strip() or "{}"
            schema = request.form.get("func_schema", "").strip()
            if not name:
                flash("Function name is required.", "warning")
            elif not is_json(tmpl):
                flash("Function template must be valid JSON.", "warning")
            elif schema and not is_json(schema):
                flash("Function schema must be valid JSON.", "warning")
            else:
                if HookFunction.query.filter_by(name=name).first():
                    flash("A function with that name already exists.", "warning")
                else:
                    db.session.add(HookFunction(name=name, description=desc, json_template=tmpl, schema_json=(schema or None)))
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

        # Header Sets
        elif action == "add_headerset":
            name = request.form.get("hs_name", "").strip()
            desc = request.form.get("hs_desc", "").strip()
            hdrs = request.form.get("hs_json", "").strip() or "{}"
            if not name:
                flash("Header set name is required.", "warning")
            elif not is_json(hdrs):
                flash("Header set must be valid JSON.", "warning")
            else:
                if HeaderSet.query.filter_by(name=name).first():
                    flash("A header set with that name already exists.", "warning")
                else:
                    db.session.add(HeaderSet(name=name, description=desc, headers_json=hdrs))
                    db.session.commit()
                    log_audit("headerset_add", f"{name}")
                    flash("Header set added.", "success")

        elif action == "delete_headerset":
            hid = request.form.get("hs_id")
            hs = HeaderSet.query.get(int(hid)) if hid else None
            if hs:
                log_audit("headerset_delete", f"{hs.name}")
                db.session.delete(hs)
                db.session.commit()
                flash("Header set deleted.", "info")
            else:
                flash("Header set not found.", "warning")

        # Users & Roles
        elif action == "add_user":
            username = request.form.get("new_username", "").strip()
            password = request.form.get("new_password", "")
            role = request.form.get("new_role", "sender")
            if role not in ("admin", "sender", "viewer"):
                role = "sender"
            if not username or not password:
                flash("Username and password are required.", "warning")
            elif User.query.filter_by(username=username).first():
                flash("Username already exists.", "warning")
            else:
                u = User(username=username, role=role, is_admin=(role=="admin"))
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                log_audit("user_add", f"{username} role={role}")
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

        elif action == "set_role":
            uid = request.form.get("user_id")
            role = request.form.get("role_value", "sender")
            if role not in ("admin", "sender", "viewer"):
                role = "sender"
            u = User.query.get(int(uid)) if uid else None
            if u:
                if u.id == current_user.id and role != "admin":
                    flash("You cannot change your own role here.", "warning")
                else:
                    u.role = role
                    u.is_admin = (role == "admin")
                    db.session.commit()
                    log_audit("user_set_role", f"{u.username} -> {role}")
                    flash(f"Updated role for {u.username}.", "success")
            else:
                flash("User not found.", "warning")

        return redirect(url_for("manage"))

    targets = WebhookTarget.query.order_by(WebhookTarget.name.asc()).all()
    functions = HookFunction.query.order_by(HookFunction.name.asc()).all()
    users = User.query.order_by(User.username.asc()).all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    headersets = HeaderSet.query.order_by(HeaderSet.name.asc()).all()
    return render_template("manage.html", targets=targets, functions=functions, users=users, logs=logs, headersets=headersets)


@app.route("/manage/function/update", methods=["POST"])
@login_required
def update_function():
    if not current_user.is_admin_effective:
        flash("You do not have access to update functions.", "warning")
        return redirect(url_for("landing"))

    fid = request.form.get("func_id")
    new_name = request.form.get("func_name", "").strip()
    new_desc = request.form.get("func_desc", "").strip()
    new_tmpl = request.form.get("func_template", "").strip()
    new_schema = request.form.get("func_schema", "").strip()

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

    if new_schema and not is_json(new_schema):
        flash("Function schema must be valid JSON.", "warning")
        return redirect(url_for("manage"))

    if new_name != fobj.name and HookFunction.query.filter_by(name=new_name).first():
        flash("Another function with that name already exists.", "warning")
        return redirect(url_for("manage"))

    old_name = fobj.name
    fobj.name = new_name
    fobj.description = new_desc
    fobj.json_template = new_tmpl or "{}"
    fobj.schema_json = new_schema or None
    db.session.commit()
    log_audit("function_update", f"{old_name} -> {fobj.name}")
    flash("Function updated.", "success")
    return redirect(url_for("manage"))


@app.route("/manage/function/duplicate", methods=["POST"])
@login_required
def duplicate_function():
    if not current_user.is_admin_effective:
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
        json_template=fobj.json_template,
        schema_json=fobj.schema_json
    )
    db.session.add(dup)
    db.session.commit()
    log_audit("function_duplicate", f"{fobj.name} -> {dup.name}")
    flash(f"Function duplicated as '{dup.name}'.", "success")
    return redirect(url_for("manage"))


@app.route("/logs/export.csv")
@login_required
def export_logs_csv():
    if not current_user.is_admin_effective:
        flash("You do not have access to export logs.", "warning")
        return redirect(url_for("landing"))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp_utc", "user_id", "username", "ip", "action", "details"])
    for log in AuditLog.query.order_by(AuditLog.timestamp.asc()).all():
        writer.writerow([log.timestamp.isoformat(), log.user_id or "", log.username or "", log.ip or "", log.action, (log.details or "").replace("\n", " ").replace("\r", " ")])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv", as_attachment=True, download_name="audit_logs.csv")


# CLI
@app.cli.command("init-db")
def init_db():
    migrate_schema()
    ensure_default_admin()
    print("Database initialized. Default admin: admin / admin")


if __name__ == "__main__":
    with app.app_context():
        migrate_schema()
        ensure_default_admin()
    app.run(host="0.0.0.0", port=5001, debug=True)
