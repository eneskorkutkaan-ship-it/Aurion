#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka - tek dosya uygulama (Flask + SQLite + Flask-Login)
- Güçlü oturum yönetimi için Flask-Login kullanılır (giriş formu çalışmama sorunları giderildi).
- Templates inline olarak DictLoader ile yüklendi -> TemplateNotFound riskini kaldırır.
- İlk admin: enes / enes1357924680 (DB oluşturulurken eklenir ve korunur).
- Groq/HF anahtarları ENV'den okunur (opsiyonel).
- Resim üretimi için HF endpoint hazır; admin/normal kullanıcı limitleri yönetilir.
"""

import os
import sqlite3
import json
import uuid
import functools
import base64
import logging
from datetime import datetime
from typing import Optional

from flask import (
    Flask, request, redirect, url_for, session, g,
    render_template, render_template_string, jsonify, abort, flash
)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

import requests

# ---------- AYARLAR ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("KRALZEKA_DB", os.path.join(BASE_DIR, "kralzeka.db"))

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
HF_API_KEY = os.environ.get("HF_API_KEY", "").strip()
SECRET_KEY = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or str(uuid.uuid4())

DEFAULT_GROQ_MODEL = "llama-3.1-70b"
DEFAULT_HF_TEXT_MODEL = "meta-llama/Llama-2-7b-chat-hf"
DEFAULT_HF_IMAGE_MODEL = "stabilityai/stable-diffusion-xl"

IMAGE_DAILY_LIMIT = 5
ADMIN_USERNAME = "enes"
ADMIN_PASSWORD = "enes1357924680"

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kralzeka")

# ---------- FLASK APP ----------
app = Flask(__name__)
app.secret_key = SECRET_KEY
# make sessions permanent so they survive short restarts if desired
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 24 * 7

# ---------- FLASK-LOGIN ----------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

# ---------- DB helpers ----------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        need_init = not os.path.exists(DB_PATH)
        db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
        g._db = db
        if need_init:
            init_db(db)
    return db

def init_db(db_conn=None):
    db = db_conn or sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = db.cursor()
    cur.executescript("""
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        sender TEXT,
        content TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        meta TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS image_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        usage_date TEXT,
        count INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    db.commit()
    # ensure initial admin exists
    try:
        cur.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), 1)
            )
            db.commit()
            logger.info("İlk admin oluşturuldu: %s", ADMIN_USERNAME)
    except Exception:
        logger.exception("init_db error")

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()
        g._db = None

# ---------- User wrapper for Flask-Login ----------
class User(UserMixin):
    def __init__(self, row):
        self._row = row
        self.id = int(row["id"])
        self.username = row["username"]
        self.password_hash = row["password_hash"]
        self.is_admin = bool(row["is_admin"])

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return True

# loader
@login_manager.user_loader
def load_user(user_id):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
        row = cur.fetchone()
        if row:
            return User(row)
    except Exception:
        logger.exception("load_user error")
    return None

# ---------- helper functions ----------
def log_event(level: str, message: str, meta: Optional[dict] = None):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO logs (level, message, meta) VALUES (?, ?, ?)", (level, message, json.dumps(meta or {})))
        db.commit()
    except Exception:
        logger.exception("log_event failed")

def get_user_by_username(username: str):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def create_user(username: str, password: str, is_admin: int = 0):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), is_admin))
        db.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None

def protected_admin_modify(target_username: str, acting_admin: str):
    if target_username == ADMIN_USERNAME:
        log_event("WARN", f"Admin değişikliği denemesi: {acting_admin} -> {target_username}", {"actor": acting_admin, "target": target_username})
        return False
    return True

# ---------- AI BACKENDS ----------
def call_groq_chat(prompt: str, model=DEFAULT_GROQ_MODEL):
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ key yok")
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    data = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 1024}
    r = requests.post(url, headers=headers, json=data, timeout=30)
    r.raise_for_status()
    resp = r.json()
    if "choices" in resp and resp["choices"]:
        return resp["choices"][0].get("message", {}).get("content") or resp["choices"][0].get("text")
    return resp.get("output_text") or json.dumps(resp)

def call_hf_text(prompt: str, model: str = DEFAULT_HF_TEXT_MODEL):
    if not HF_API_KEY:
        raise RuntimeError("HF key yok")
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    resp = r.json()
    if isinstance(resp, dict) and "error" in resp:
        raise RuntimeError(resp["error"])
    if isinstance(resp, list) and resp and "generated_text" in resp[0]:
        return resp[0]["generated_text"]
    if isinstance(resp, str):
        return resp
    return json.dumps(resp)

def generate_image_hf(prompt: str, model: str = DEFAULT_HF_IMAGE_MODEL):
    if not HF_API_KEY:
        raise RuntimeError("HF key yok")
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}", "Accept": "application/json"}
    payload = {"inputs": prompt, "options": {"wait_for_model": True}}
    r = requests.post(url, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    content_type = r.headers.get("Content-Type", "")
    if "application/json" in content_type:
        data = r.json()
        if isinstance(data, dict) and "image_base64" in data:
            return base64.b64decode(data["image_base64"])
        if isinstance(data, dict) and "generated_image" in data:
            return base64.b64decode(data["generated_image"])
        if "error" in data:
            raise RuntimeError(data["error"])
        raise RuntimeError("HF image model returned unexpected JSON")
    else:
        return r.content

def ai_chat(prompt: str) -> str:
    try:
        if GROQ_API_KEY:
            try:
                out = call_groq_chat(prompt)
                if out:
                    return out
            except Exception:
                logger.warning("Groq başarısız, HF'e düşülüyor.")
        if HF_API_KEY:
            return call_hf_text(prompt)
        raise RuntimeError("Hiçbir model yapılamıyor (GROQ/HF anahtarları yok veya hata).")
    except Exception as e:
        logger.exception("ai_chat exception")
        return f"KralZeka Hata: {str(e)}"

# ---------- Image usage helpers ----------
def get_image_usage_for_today(user_id: int):
    db = get_db()
    cur = db.cursor()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    cur.execute("SELECT count FROM image_usage WHERE user_id = ? AND usage_date = ?", (user_id, today))
    row = cur.fetchone()
    return row["count"] if row else 0

def increment_image_usage(user_id: int, amount: int = 1):
    db = get_db()
    cur = db.cursor()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    cur.execute("SELECT id, count FROM image_usage WHERE user_id = ? AND usage_date = ?", (user_id, today))
    r = cur.fetchone()
    if r:
        cur.execute("UPDATE image_usage SET count = count + ? WHERE id = ?", (amount, r["id"]))
    else:
        cur.execute("INSERT INTO image_usage (user_id, usage_date, count) VALUES (?, ?, ?)", (user_id, today, amount))
    db.commit()

# ---------- Templates (inline to avoid TemplateNotFound) ----------
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>{% block title %}KralZeka v1{% endblock %}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{background:#071018;color:#d8efe9;font-family:Inter,Segoe UI,Arial;padding:20px}
    .wrap{max-width:980px;margin:0 auto}
    header{display:flex;justify-content:space-between;align-items:center}
    h1{margin:0;font-size:28px}
    .card{background:rgba(0,0,0,0.45);padding:18px;border-radius:10px;box-shadow:0 6px 30px rgba(0,0,0,0.6);margin-top:18px}
    input,textarea,button,select{font-size:16px;padding:10px;border-radius:8px;border:1px solid #263238;background:#0b1517;color:#d8efe9;width:100%}
    .row{display:flex;gap:10px}
    .row > *{flex:1}
    .muted{color:#9cb8b8;font-size:14px}
    .msg{background:#042627;padding:12px;border-radius:8px;margin-bottom:8px}
    .admin-tag{color:#ffd54f;font-weight:bold}
    .top-buttons a{color:#d8efe9;margin-left:12px}
    footer{margin-top:40px;text-align:center;color:#6c9b9b}
    .small{font-size:13px;color:#9dbdbd}
    .danger{color:#ffd2d2}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);text-align:left}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>KralZeka v1</h1>
      <div class="top-buttons">
        {% if current_user.is_authenticated %}
          Merhaba, <strong>{{ current_user.username }}</strong> {% if current_user.is_admin %}<span class="admin-tag">[ADMIN]</span>{% endif %}
           | <a href="{{ url_for('logout') }}">Çıkış yap</a>
           {% if current_user.is_admin %} | <a href="{{ url_for('admin_panel') }}">Admin Panel</a>{% endif %}
        {% else %}
          <a href="{{ url_for('login') }}">Giriş</a> | <a href="{{ url_for('register') }}">Kayıt</a>
        {% endif %}
      </div>
    </header>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="card">
        {% for cat, msg in messages %}
          <div class="msg {% if cat=='error' or cat=='danger' %}danger{% endif %}">{{ msg }}</div>
        {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    {% block body %}{% endblock %}

    <footer>
      © KralZeka v1 — KralZeka, Enes'in zekasıyla hayat buldu. <div class="small">Tüm arayüz Türkçe. Gizli anahtarlar sadece ENV'de tutulur.</div>
    </footer>
  </div>
</body>
</html>
"""

INDEX_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <form method="post" action="{{ url_for('chat') }}">
      <label class="small">Sohbet (Groq öncelikli, Hugging Face yedek)</label>
      <div style="display:flex;gap:10px">
        <input name="prompt" placeholder="Bir şey yaz..." autocomplete="off" required>
        <button type="submit">Gönder</button>
      </div>
    </form>
  </div>

  <div class="card">
    <h3>Son mesajlar</h3>
    {% for m in messages %}
      <div class="msg">
        <div class="small muted">{{ m['created_at'] }} — <strong>{{ m['sender'] }}</strong></div>
        <div>{{ m['content'] }}</div>
      </div>
    {% endfor %}
  </div>

  <div class="card">
    <h3>Modlar</h3>
    <div class="small">Seçilebilir modlar (UI üzerinden gelecekte eklenecek):</div>
    <ul class="small">
      <li>Ödev Modu — Sınav/çalışma kağıtları oluşturma.</li>
      <li>Espri Modu — Şakalar.</li>
      <li>Sohbet Modu — Normal sohbet.</li>
      <li>Sunum Modu — Slayt/sunum oluşturma.</li>
      <li>Kalite Yükseltme — Görsel kalite yükseltme (admin sınırsız, kullanıcı günlük {{ image_limit }}).</li>
    </ul>
  </div>
{% endblock %}
"""

LOGIN_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Giriş</h3>
    <form method="post" action="{{ url_for('login') }}">
      <label>Kullanıcı adı</label>
      <input name="username" required>
      <label>Parola</label>
      <input name="password" type="password" required>
      <div style="margin-top:10px"><button>Giriş yap</button></div>
    </form>
  </div>
{% endblock %}
"""

REGISTER_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Kayıt ol</h3>
    <form method="post" action="{{ url_for('register') }}">
      <label>Kullanıcı adı</label>
      <input name="username" required>
      <label>Parola</label>
      <input name="password" type="password" required>
      <label>Parola tekrar</label>
      <input name="password2" type="password" required>
      <div style="margin-top:10px"><button>Kayıt ol</button></div>
    </form>
    <div class="small muted">İlk admin ({{ admin_username }}) silinemez veya demote edilemez.</div>
  </div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Admin Paneli</h3>
    <div class="small">Kullanıcı yönetimi, limitler, kod-yazma bölümü (sadece adminlere özel).</div>
    <hr>
    <h4>Kullanıcılar</h4>
    <table class="small">
      <tr><th>Kullanıcı</th><th>Admin</th><th>Oluşturma</th><th>İşlemler</th></tr>
      {% for u in users %}
        <tr>
          <td>{{ u['username'] }}</td>
          <td>{{ 'Evet' if u['is_admin'] else 'Hayır' }}</td>
          <td>{{ u['created_at'] }}</td>
          <td>
            {% if u['username'] != admin_username %}
              {% if not u['is_admin'] %}
                <form style="display:inline" method="post" action="{{ url_for('make_admin', user_id=u['id']) }}"><button>Admin yap</button></form>
              {% else %}
                <form style="display:inline" method="post" action="{{ url_for('revoke_admin', user_id=u['id']) }}"><button>Adminlığı kaldır</button></form>
              {% endif %}
              <form style="display:inline" method="post" action="{{ url_for('delete_user', user_id=u['id']) }}"><button class="danger">Sil</button></form>
            {% else %}
              (korunuyor)
            {% endif %}
          </td>
        </tr>
      {% endfor %}
    </table>

    <hr>
    <h4>Kod Yazma / Otomatik Yardımcı (Admin-only)</h4>
    <form method="post" action="{{ url_for('admin_code_tool') }}">
      <textarea name="prompt" rows="4" placeholder="Üretilecek kod veya talimat..." required></textarea>
      <div style="margin-top:8px"><button>Yaz</button></div>
    </form>

    <hr>
    <h4>Loglar (son 100)</h4>
    <div class="small">
      {% for l in logs %}
        <div class="msg small"><strong>{{ l['level'] }}</strong> — {{ l['message'] }} <div class="muted">{{ l['created_at'] }}</div></div>
      {% endfor %}
    </div>
  </div>
{% endblock %}
"""

ERROR_500 = """
{% extends "base" %}
{% block body %}
  <div class="card">
    <h3>Sunucu Hatası (500)</h3>
    <p>Bir hata oluştu. Admin'e bildirin veya logları kontrol edin.</p>
  </div>
{% endblock %}
"""

TEMPLATES = {
    "base": BASE_HTML,
    "index.html": INDEX_HTML,
    "login.html": LOGIN_HTML,
    "register.html": REGISTER_HTML,
    "admin.html": ADMIN_HTML,
    "500.html": ERROR_500
}
# set jinja loader to avoid TemplateNotFound
app.jinja_loader = DictLoader(TEMPLATES)

# ---------- ROUTES ----------
@app.route("/", methods=["GET"])
def index():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, sender, content, created_at FROM messages ORDER BY created_at DESC LIMIT 20")
    msgs = cur.fetchall()
    return render_template("index.html", messages=msgs, image_limit=IMAGE_DAILY_LIMIT)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        if not username or not password:
            flash("Alanları doldurun", "danger")
            return redirect(url_for("register"))
        if password != password2:
            flash("Parolalar eşleşmiyor", "danger")
            return redirect(url_for("register"))
        if get_user_by_username(username):
            flash("Kullanıcı adı alınmış", "danger")
            return redirect(url_for("register"))
        uid = create_user(username, password, 0)
        if not uid:
            flash("Kayıt başarısız", "danger")
            return redirect(url_for("register"))
        log_event("INFO", f"Kayıt: {username}")
        # auto login new user
        cur = get_db().cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
        row = cur.fetchone()
        if row:
            user = User(row)
            login_user(user)
            flash("Kayıt başarılı, giriş yapıldı.", "success")
            return redirect(url_for("index"))
        flash("Kayıt oldu ancak oturum açılamadı.", "warning")
        return redirect(url_for("login"))
    return render_template("register.html", admin_username=ADMIN_USERNAME)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # debug: print(request.form)  # (gerektiğinde logla)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Kullanıcı adı ve parola girin.", "danger")
            return redirect(url_for("login"))
        row = get_user_by_username(username)
        if not row:
            flash("Kullanıcı adı veya şifre hatalı.", "danger")
            return redirect(url_for("login"))
        # check password hash
        if not check_password_hash(row["password_hash"], password):
            flash("Kullanıcı adı veya şifre hatalı.", "danger")
            return redirect(url_for("login"))
        user = User(row)
        login_user(user)
        session.permanent = True
        log_event("INFO", f"Giriş: {username}")
        flash("Giriş başarılı.", "success")
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash("Çıkış yapıldı.", "info")
    log_event("INFO", f"Çıkış: {username}")
    return redirect(url_for("index"))

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    prompt = request.form.get("prompt", "").strip()
    if not prompt:
        flash("Boş mesaj gönderilemez.", "danger")
        return redirect(url_for("index"))
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)", (int(current_user.id), current_user.username, prompt))
        db.commit()
    except Exception:
        logger.exception("message insert failed")
    # get AI response (safe)
    try:
        response_text = ai_chat(prompt)
    except Exception as e:
        response_text = f"Hata: {str(e)}"
    try:
        cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)", (int(current_user.id), "KralZeka", response_text))
        db.commit()
    except Exception:
        logger.exception("assistant message insert failed")
    return redirect(url_for("index"))

@app.route("/feature_request", methods=["POST"])
@login_required
def feature_request():
    txt = request.form.get("request_text", "").strip()
    tag = request.form.get("tag", "").strip()
    if txt:
        log_event("FEATURE", txt, {"tag": tag, "user": current_user.username})
        flash("İstek kaydedildi.", "success")
    return redirect(url_for("index"))

# ---------- ADMIN ----------
def admin_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not getattr(current_user, "is_admin", False):
            return "Bu bölüm yalnızca adminlere özeldir.", 403
        return fn(*args, **kwargs)
    return wrapper

@app.route("/admin", methods=["GET"])
@admin_required
def admin_panel():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.execute("SELECT level, message, meta, created_at FROM logs ORDER BY id DESC LIMIT 100")
    logs = cur.fetchall()
    return render_template("admin.html", users=users, logs=logs, admin_username=ADMIN_USERNAME)

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
@admin_required
def make_admin(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        flash("Kullanıcı yok", "danger")
        return redirect(url_for("admin_panel"))
    target = row["username"]
    if not protected_admin_modify(target, current_user.username):
        flash(f"{ADMIN_USERNAME} üzerinde değişiklik yapılamaz.", "danger")
        return redirect(url_for("admin_panel"))
    cur.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{current_user.username} -> {target} admin yapıldı")
    flash("İşlem başarılı.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/revoke_admin/<int:user_id>", methods=["POST"])
@admin_required
def revoke_admin(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        flash("Kullanıcı yok", "danger")
        return redirect(url_for("admin_panel"))
    target = row["username"]
    if not protected_admin_modify(target, current_user.username):
        flash(f"{ADMIN_USERNAME} üzerinde değişiklik yapılamaz.", "danger")
        return redirect(url_for("admin_panel"))
    cur.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{current_user.username} -> {target} adminlığı kaldırdı")
    flash("İşlem başarılı.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    r = cur.fetchone()
    if not r:
        flash("Kullanıcı yok", "danger")
        return redirect(url_for("admin_panel"))
    target = r["username"]
    if not protected_admin_modify(target, current_user.username):
        flash(f"{ADMIN_USERNAME} üzerinde değişiklik yapılamaz.", "danger")
        return redirect(url_for("admin_panel"))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{current_user.username} -> {target} silindi")
    flash("Kullanıcı silindi.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/code_tool", methods=["POST"])
@admin_required
def admin_code_tool():
    prompt = request.form.get("prompt", "").strip()
    if not prompt:
        flash("Prompt boş olamaz.", "danger")
        return redirect(url_for("admin_panel"))
    try:
        ai_response = ai_chat(f"Admin kod üretme asistanı: {prompt}")
    except Exception as e:
        ai_response = f"Hata: {e}"
    log_event("CODE", ai_response, {"admin": current_user.username, "prompt": prompt})
    flash("Kod talebi işlendi (loglandı).", "success")
    return redirect(url_for("admin_panel"))

# ---------- Image API ----------
@app.route("/api/generate_image", methods=["POST"])
@login_required
def api_generate_image():
    data = request.get_json() or {}
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "prompt gerekli"}), 400
    if not current_user.is_admin:
        used = get_image_usage_for_today(int(current_user.id))
        if used >= IMAGE_DAILY_LIMIT:
            return jsonify({"error": f"Günlük limit aşıldı ({IMAGE_DAILY_LIMIT})"}), 403
    try:
        img_bytes = generate_image_hf(prompt)
        if not current_user.is_admin:
            increment_image_usage(int(current_user.id), 1)
        b64 = base64.b64encode(img_bytes).decode("utf-8")
        preview = f"data:image/png;base64,{b64[:180]}..."
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)",
                    (int(current_user.id), "KralZeka (görsel)", preview))
        db.commit()
        return jsonify({"image_base64": b64}), 200
    except Exception as e:
        logger.exception("image generation error")
        return jsonify({"error": f"Görsel üretilemedi: {str(e)}"}), 500

# ---------- Error handling ----------
@app.errorhandler(500)
def handle_500(e):
    try:
        log_event("ERROR", str(e), {"path": request.path})
    except Exception:
        logger.exception("log_event failed while handling 500")
    return render_template("500.html"), 500

# ---------- Start ----------
def start_app():
    init_db()
    logger.info("KralZeka v1 starting...")
    # local debug run if FLASK_RUN_LOCAL set
    if os.environ.get("FLASK_RUN_LOCAL", "").lower() in ("1", "true"):
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

if __name__ == "__main__":
    start_app()
