import os
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_

def utcnow():
    return datetime.now(timezone.utc)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db_url = os.environ.get("DATABASE_URL", "sqlite:///live_lion.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://") and "+psycopg" not in db_url:
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url

is_prod = os.environ.get("FLASK_ENV") == "production" or os.environ.get("RENDER") == "true"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_prod,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
)

db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["300 per hour"])

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(50))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="customer", index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class ServiceCall(db.Model):
    __tablename__ = "service_calls"
    id = db.Column(db.Integer, primary_key=True)
    call_number = db.Column(db.String(64), unique=True, nullable=False, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    technician_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    service_type = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    preferred_date = db.Column(db.String(20))
    preferred_time = db.Column(db.String(20))
    description = db.Column(db.Text)
    status = db.Column(db.String(40), nullable=False, default="New", index=True)
    price_cents = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    customer = db.relationship("User", foreign_keys=[customer_id])
    technician = db.relationship("User", foreign_keys=[technician_id])

class JobRecord(db.Model):
    __tablename__ = "job_records"
    id = db.Column(db.Integer, primary_key=True)
    service_call_id = db.Column(db.Integer, db.ForeignKey("service_calls.id", ondelete="CASCADE"), unique=True, nullable=False)
    notes = db.Column(db.Text)
    equipment = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    service_call = db.relationship("ServiceCall", backref=db.backref("job_record", uselist=False, cascade="all, delete-orphan"))

def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

def require_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.headers.get("X-CSRF-Token")
        if not token or not secrets.compare_digest(token, session.get("csrf", "")):
            return False
    return True

def auth_required(*roles):
    def outer(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u:
                return jsonify({"error": "Authentication required"}), 401
            if roles and u.role not in roles:
                return jsonify({"error": "Forbidden"}), 403
            if not require_csrf():
                return jsonify({"error": "Invalid CSRF token"}), 403
            request.current_user = u
            return fn(*args, **kwargs)
        return wrapper
    return outer

def serialize_call(c):
    jr = c.job_record
    return {
        "id": c.id,
        "call_number": c.call_number,
        "customer_id": c.customer_id,
        "customer_name": c.customer.name,
        "customer_email": c.customer.email,
        "customer_phone": c.customer.phone,
        "technician_id": c.technician_id,
        "technician_name": c.technician.name if c.technician else None,
        "service_type": c.service_type,
        "address": c.address,
        "preferred_date": c.preferred_date,
        "preferred_time": c.preferred_time,
        "description": c.description,
        "status": c.status,
        "price_cents": c.price_cents,
        "job_notes": jr.notes if jr else None,
        "job_equipment": jr.equipment if jr else None,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }

@app.get("/")
def home():
    csrf_token()
    return render_template("index.html")

@app.get("/api/csrf")
def get_csrf():
    return jsonify({"csrf_token": csrf_token()})

@app.post("/api/auth/register")
@limiter.limit("8 per hour")
def register():
    if not require_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""

    if not name or "@" not in email or len(password) < 10:
        return jsonify({"error": "Enter a name, valid email, and password of at least 10 characters"}), 400
    if User.query.filter(db.func.lower(User.email) == email).first():
        return jsonify({"error": "Email already registered"}), 409

    u = User(
        name=name,
        email=email,
        phone=phone,
        password_hash=generate_password_hash(password),
        role="customer",
    )
    db.session.add(u)
    db.session.commit()
    session.clear()
    session["uid"] = u.id
    session["csrf"] = secrets.token_urlsafe(32)
    return jsonify({"user": {"id": u.id, "name": u.name, "email": u.email, "role": u.role}, "csrf_token": session["csrf"]}), 201

@app.post("/api/auth/login")
@limiter.limit("10 per 15 minutes")
def login():
    if not require_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    u = User.query.filter(db.func.lower(User.email) == email).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401

    session.clear()
    session["uid"] = u.id
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True
    return jsonify({"user": {"id": u.id, "name": u.name, "email": u.email, "role": u.role}, "csrf_token": session["csrf"]})

@app.post("/api/auth/logout")
@auth_required()
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/me")
@auth_required()
def me():
    u = request.current_user
    return jsonify({"id": u.id, "name": u.name, "email": u.email, "phone": u.phone, "role": u.role})

@app.get("/api/technicians")
@auth_required("admin")
def technicians():
    rows = User.query.filter_by(role="technician").order_by(User.name).all()
    return jsonify([{"id": x.id, "name": x.name, "email": x.email, "phone": x.phone} for x in rows])

@app.post("/api/service-calls")
@auth_required("customer")
def create_service_call():
    data = request.get_json(silent=True) or {}
    service_type = (data.get("service_type") or "").strip()
    address = (data.get("address") or "").strip()
    if not service_type or not address:
        return jsonify({"error": "Service type and address are required"}), 400

    call_no = "SC-" + utcnow().strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(2).upper()
    c = ServiceCall(
        call_number=call_no,
        customer_id=request.current_user.id,
        service_type=service_type,
        address=address,
        preferred_date=data.get("preferred_date"),
        preferred_time=data.get("preferred_time"),
        description=(data.get("description") or "").strip(),
        status="New",
    )
    db.session.add(c)
    db.session.commit()
    return jsonify(serialize_call(c)), 201

@app.get("/api/service-calls")
@auth_required()
def list_calls():
    u = request.current_user
    q = ServiceCall.query.order_by(ServiceCall.created_at.desc())
    if u.role == "customer":
        q = q.filter(ServiceCall.customer_id == u.id)
    elif u.role == "technician":
        q = q.filter(or_(ServiceCall.technician_id == u.id, ServiceCall.technician_id.is_(None)))
    return jsonify([serialize_call(c) for c in q.all()])

@app.patch("/api/service-calls/<int:call_id>")
@auth_required()
def update_call(call_id):
    u = request.current_user
    c = db.session.get(ServiceCall, call_id)
    if not c:
        return jsonify({"error": "Service call not found"}), 404

    if u.role == "customer" and c.customer_id != u.id:
        return jsonify({"error": "Forbidden"}), 403
    if u.role == "technician" and c.technician_id not in (None, u.id):
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    valid_status = {"New", "Assigned", "On the way", "Working", "Completed", "Cancelled"}

    if u.role == "admin":
        if "technician_id" in data:
            tid = data["technician_id"]
            if tid is not None:
                tech = db.session.get(User, int(tid))
                if not tech or tech.role != "technician":
                    return jsonify({"error": "Invalid technician"}), 400
            c.technician_id = tid
            if tid and c.status == "New":
                c.status = "Assigned"
        if "status" in data:
            if data["status"] not in valid_status:
                return jsonify({"error": "Invalid status"}), 400
            c.status = data["status"]
        if "price_cents" in data:
            c.price_cents = max(0, int(data["price_cents"] or 0))
    elif u.role == "technician":
        if "status" not in data or data["status"] not in {"Assigned", "On the way", "Working", "Completed"}:
            return jsonify({"error": "Technician may only update workflow status"}), 400
        if c.technician_id is None:
            c.technician_id = u.id
        c.status = data["status"]
    else:
        for fld in ("preferred_date", "preferred_time", "description"):
            if fld in data:
                setattr(c, fld, data[fld])

    c.updated_at = utcnow()
    db.session.commit()
    return jsonify(serialize_call(c))

@app.post("/api/service-calls/<int:call_id>/record")
@auth_required("technician", "admin")
def save_record(call_id):
    u = request.current_user
    c = db.session.get(ServiceCall, call_id)
    if not c:
        return jsonify({"error": "Service call not found"}), 404
    if u.role == "technician" and c.technician_id != u.id:
        return jsonify({"error": "This call is not assigned to you"}), 403

    data = request.get_json(silent=True) or {}
    r = c.job_record or JobRecord(service_call=c)
    r.notes = (data.get("notes") or "").strip()
    r.equipment = (data.get("equipment") or "").strip()
    r.updated_at = utcnow()
    db.session.add(r)
    db.session.commit()
    return jsonify({"id": r.id, "service_call_id": r.service_call_id, "notes": r.notes, "equipment": r.equipment})

@app.get("/api/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"ok": True, "database": "connected"})
    except Exception:
        return jsonify({"ok": False, "database": "error"}), 503

def seed_if_needed():
    with app.app_context():
        db.create_all()
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@livelion.local").lower()
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if admin_password and not User.query.filter(db.func.lower(User.email) == admin_email).first():
            db.session.add(User(
                name="LIVE LION Admin",
                email=admin_email,
                password_hash=generate_password_hash(admin_password),
                role="admin"
            ))
        tech_password = os.environ.get("TECHNICIAN_PASSWORD")
        if tech_password:
            for name, email in [
                ("Carlos Ramirez", "carlos@livelion.local"),
                ("James Carter", "james@livelion.local"),
                ("David Kim", "david@livelion.local"),
            ]:
                if not User.query.filter(db.func.lower(User.email) == email).first():
                    db.session.add(User(
                        name=name,
                        email=email,
                        password_hash=generate_password_hash(tech_password),
                        role="technician"
                    ))
        db.session.commit()

seed_if_needed()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=not is_prod)
