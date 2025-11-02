#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Tek dosya Flask uygulaması
- Ortam değişkenleri: HF_API_KEY, GROQ_API_KEY, FLASK_SECRET
- Tek dosyada hem sunucu hem html şablonları var (render_template_string).
- Kullanıcı kayıt/giriş, admin panel, sohbet (Groq), görsel üretme (Hugging Face), limitler, yükleme, basit hata/öneri mekanizması.
"""

import os
import re
import time
import json
import math
import base64
import sqlite3
import hashlib
import secrets
import tempfile
import traceback
from datetime import datetime, timedelta

import requests
from flask import (
    Flask, g, render_template_string, request, redirect, url_for, session,
    flash, send_from_directory, jsonify, abort
)
from werkzeug.utils import secure_filename

# -------------- CONFIG --------------
# Environment config
HF_API_KEY = os.environ.get("HF_API_KEY", None)   # HuggingFace token for image generation
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", None)  # Groq / model API token for chat
FLASK_SECRET = os.environ.get("FLASK_SECRET") or "please_set_FLASK_SECRET_in_env"

# Basic constants
DATABASE = os.environ.get("DATABASE_PATH", "kralzeka.db")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_IMG_SIZE_MB = 8

# Limits
DEFAULT_DAILY_QUALITY_UPGRADES = 5  # normal users per day
ADMIN_USERNAME = os.environ.get("ADMIN_FIRST_USERNAME", "enes")
ADMIN_PASSWORD = os.environ.get("ADMIN_FIRST_PASSWORD", "enes1357924680")

# Groq model to use (you can change environment var or keep this default)
GROQ_MODEL = os.environ.get("GROQ_MODEL", "grok-1")  # Change if you have a preferred model

# Flask app
app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------- DATABASE UTILITIES --------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DATABASE, check_same_thread=False)
        db.row_factory = sqlite3.Row
        g._db = db
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def init_db(force=False):
    """
    Initialize DB with tables: users, messages, admin_actions, quality_uses, image_jobs, suggestions
    Call within app.app_context()
    """
    db = get_db()
    if force:
        try:
            db.execute("DROP TABLE IF EXISTS users")
            db.execute("DROP TABLE IF EXISTS messages")
            db.execute("DROP TABLE IF EXISTS admin_actions")
            db.execute("DROP TABLE IF EXISTS quality_uses")
            db.execute("DROP TABLE IF EXISTS image_jobs")
            db.execute("DROP TABLE IF EXISTS suggestions")
            db.commit()
        except Exception:
            db.rollback()
    # Create tables if not exist
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT,
        daily_quality_limit INTEGER DEFAULT ?
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        role TEXT, -- 'user' or 'assistant'
        text TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS admin_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        action TEXT,
        meta TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS quality_uses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS image_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        prompt TEXT,
        status TEXT,
        result_url TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS suggestions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        text TEXT,
        status TEXT DEFAULT 'pending', -- pending/approved/rejected
        admin_id INTEGER,
        created_at TEXT
    );
    """, (DEFAULT_DAILY_QUALITY_UPGRADES,))
    db.commit()

def close_connection(exception):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_connection)

# -------------- SIMPLE AUTH HELPERS --------------
def hash_password(password: str) -> str:
    # use salt + sha256 (simple). For prod use bcrypt/argon2.
    salt = "KralZekaSalt_v1"  # fixed salt - fine for local dev. For prod, store per-user salt.
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def create_user(username: str, password: str, is_admin=False, daily_limit=None):
    db = get_db()
    try:
        created_at = datetime.utcnow().isoformat()
        limitval = daily_limit if daily_limit is not None else DEFAULT_DAILY_QUALITY_UPGRADES
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at, daily_quality_limit) VALUES (?, ?, ?, ?, ?)",
            (username, hash_password(password), 1 if is_admin else 0, created_at, limitval)
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_user(username, password):
    row = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
    if not row:
        return None
    if row["password_hash"] == hash_password(password):
        return dict(row)
    return None

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    row = query_db("SELECT * FROM users WHERE id = ?", (uid,), one=True)
    return dict(row) if row else None

def require_login(func):
    def wrapper(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return func(*a, **kw)
    wrapper.__name__ = func.__name__
    return wrapper

def require_admin(func):
    def wrapper(*a, **kw):
        user = current_user()
        if not user or not user.get("is_admin"):
            abort(403)
        return func(*a, **kw)
    wrapper.__name__ = func.__name__
    return wrapper

# -------------- UTILITIES --------------
def now_iso():
    return datetime.utcnow().isoformat()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXT

def save_upload(file_storage):
    filename = secure_filename(file_storage.filename)
    if not allowed_file(filename):
        raise ValueError("Dosya türü desteklenmiyor.")
    # limit size: check stream size (works with save to temp)
    tmp = tempfile.NamedTemporaryFile(delete=False)
    file_storage.save(tmp.name)
    tmp.close()
    size_mb = os.path.getsize(tmp.name) / (1024*1024)
    if size_mb > MAX_IMG_SIZE_MB:
        os.unlink(tmp.name)
        raise ValueError("Dosya çok büyük")
    dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    os.replace(tmp.name, dest)
    return dest

def record_message(user_id, role, text):
    db = get_db()
    db.execute("INSERT INTO messages (user_id, role, text, created_at) VALUES (?, ?, ?, ?)",
               (user_id, role, text, now_iso()))
    db.commit()

def record_admin_action(admin_id, action, meta=""):
    db = get_db()
    db.execute("INSERT INTO admin_actions (admin_id, action, meta, created_at) VALUES (?, ?, ?, ?)",
               (admin_id, action, meta, now_iso()))
    db.commit()

# ------------------ CHAT: Groq API helper ------------------
def call_groq_chat(user_prompt, conv_history=None, model=None, max_tokens=512):
    """
    Simple call to Groq-like API.
    This function expects GROQ_API_KEY environment variable to be set.
    Returns: dict {ok:bool, text:..., raw:...}
    """
    model = model or GROQ_MODEL
    if not GROQ_API_KEY:
        return {"ok": False, "error": "GROQ_API_KEY not set in environment"}
    url = f"https://api.groq.com/openai/v1/chat/completions"  # some deployments may differ
    # payload adjusted for OpenAI-like endpoint
    messages = [{"role": "system", "content": "KralZeka: Türkçe, samimi, yardımcı."}]
    if conv_history:
        messages.extend(conv_history)
    messages.append({"role": "user", "content": user_prompt})
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.6
    }
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=25)
        if r.status_code != 200:
            return {"ok": False, "error": f"{r.status_code} {r.text}"}
        data = r.json()
        # openai-like response parsing
        text = ""
        if "choices" in data and len(data["choices"])>0:
            text = data["choices"][0].get("message", {}).get("content", "")
        elif "output" in data and isinstance(data["output"], list) and data["output"]:
            text = " ".join([str(x) for x in data["output"]])
        return {"ok": True, "text": text, "raw": data}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ------------------ IMAGE: Hugging Face helper ------------------
def hf_generate_image(prompt, model="stabilityai/stable-diffusion-2-1", user_id=None):
    """
    Call HF inference to generate image from prompt.
    Requires HF_API_KEY.
    Returns (ok, url_or_error)
    """
    if not HF_API_KEY:
        return False, "HF_API_KEY not set"
    try:
        # Use HuggingFace Inference API: POST /api/models/{model}
        # Some models require 'inputs' text; we will set wait_for_model true
        url = f"https://api-inference.huggingface.co/models/{model}"
        headers = {"Authorization": f"Bearer {HF_API_KEY}"}
        payload = {"inputs": prompt}
        # stream=False: we expect binary image or JSON; request returns bytes for images
        r = requests.post(url, json=payload, headers=headers, timeout=60, stream=True)
        if r.status_code == 200:
            # try content-type
            ct = r.headers.get("content-type", "")
            if "image" in ct:
                # save image to uploads with timestamp
                ext = ct.split("/")[-1]
                filename = f"hf_{int(time.time())}.{ext}"
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                with open(path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                # record job
                db = get_db()
                db.execute("INSERT INTO image_jobs (user_id, prompt, status, result_url, created_at) VALUES (?, ?, ?, ?, ?)",
                           (user_id, prompt, "done", path, now_iso()))
                db.commit()
                return True, path
            else:
                # likely JSON with error
                text = r.content.decode("utf-8", errors="replace")
                return False, f"HF returned non-image: {text}"
        else:
            try:
                j = r.json()
                return False, f"HF error {r.status_code}: {j}"
            except Exception:
                return False, f"HF error {r.status_code}: {r.text}"
    except Exception as e:
        return False, str(e)

# ------------------ LIMITS: Quality upgrade usage ------------------
def user_daily_quality_used_count(user_id):
    since = datetime.utcnow().date().isoformat()
    rows = query_db("SELECT COUNT(*) as cnt FROM quality_uses WHERE user_id=? AND date(used_at)=date(?)", (user_id, since), one=True)
    return rows["cnt"] if rows else 0

def use_quality_upgrade(user_id):
    db = get_db()
    db.execute("INSERT INTO quality_uses (user_id, used_at) VALUES (?, ?)", (user_id, now_iso()))
    db.commit()

# ------------------ AUTO-FIX SUGGESTION MECHANISM ------------------
def record_suggestion(user_id, text):
    db = get_db()
    db.execute("INSERT INTO suggestions (user_id, text, status, created_at) VALUES (?, ?, 'pending', ?)", (user_id, text, now_iso()))
    db.commit()

# ------------------ ROUTES & TEMPLATES ------------------

BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KralZeka v1</title>
<style>
:root {
  --bg: #040404;
  --card: #062726;
  --muted: #9aa9a9;
  --accent: #1bb273;
  --danger: #d94b4b;
  --text: #e9fff6;
}
body { background: var(--bg); color: var(--text); font-family: Inter, Roboto, sans-serif; margin:0; padding:0;}
.container { max-width:1000px; margin:30px auto; padding:20px;}
.header { display:flex; justify-content:space-between; align-items:center; margin-bottom:18px;}
.card { background: linear-gradient(180deg, rgba(10,30,20,0.9), rgba(5,10,10,0.8)); padding:18px; border-radius:10px; box-shadow: 0 6px 20px rgba(0,0,0,0.6); }
.input { width:100%; padding:12px; border-radius:8px; border:1px solid rgba(255,255,255,0.06); background: rgba(0,0,0,0.2); color:var(--text);}
.btn { background:var(--accent); border:none; padding:10px 14px; color:#021; border-radius:8px; cursor:pointer; font-weight:600;}
.small { font-size:0.9rem; color:var(--muted); }
.msg { background: rgba(0,0,0,0.2); padding:12px; margin-top:12px; border-left:4px solid rgba(27,178,115,0.18); border-radius:6px;}
.bad { border-left-color: var(--danger); }
.topbar a { color:var(--muted); margin-left:12px; text-decoration:none }
.profile { font-weight:700; }
.footer { margin-top:30px; color:var(--muted); font-size:0.9rem;}
.adminbadge { color:gold; margin-left:8px; font-weight:700;}
.panel { display:flex; gap:20px; margin-top:14px;}
.left { flex:2; } .right { flex:1; }
.list { margin-top:12px; }
.row { padding:10px; background: rgba(0,0,0,0.15); margin-bottom:8px; border-radius:8px;}
.label { color:var(--muted); font-size:0.85rem; }
.field { margin-bottom:10px; }
.smallbtn { padding:6px 8px; border-radius:6px; background:rgba(255,255,255,0.04); color:var(--text); border:1px solid rgba(255,255,255,0.02); cursor:pointer;}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>KralZeka v1</h1>
      <div class="small">Gerçek zamanlı Türkçe zeka ve internet tabanlı bilgi - tek dosya demo</div>
    </div>
    <div class="topbar">
      {% if user %}
        <span class="profile">Merhaba, {{ user.username }}{% if user.is_admin %}<span class="adminbadge">[ADMIN]</span>{% endif %}</span>
        <a href="{{ url_for('logout') }}">Çıkış yap</a>
        {% if user.is_admin %}
          <a href="{{ url_for('admin_panel') }}">Admin Panel</a>
        {% endif %}
      {% else %}
        <a href="{{ url_for('login') }}">Giriş</a>
        <a href="{{ url_for('register') }}">Kayıt ol</a>
      {% endif %}
    </div>
  </div>
  <div class="card">
    {% block content %}{% endblock %}
  </div>
  <div class="footer">
    <div>KralZeka v1 — Bu uygulama demo amaçlıdır. Enes tarafından oluşturuldu.</div>
  </div>
</div>
</body>
</html>
"""

# ------------------ Home / Chat ------------------
@app.route("/", methods=["GET", "POST"])
def index():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    message = None
    error = None
    if request.method == "POST":
        q = request.form.get("q", "").strip()
        if q:
            # store user message
            record_message(user["id"], "user", q)
            # build recent conversation
            # fetch last 8 messages
            rows = query_db("SELECT role, text FROM messages WHERE user_id=? ORDER BY id DESC LIMIT 12", (user["id"],))
            conv = []
            for r in reversed(rows):
                conv.append({"role": r["role"], "content": r["text"]})
            # call groq
            res = call_groq_chat(q, conv_history=conv)
            if not res.get("ok"):
                error = f"Hata: {res.get('error')}"
                record_message(user["id"], "assistant", error)
            else:
                text = res.get("text")
                record_message(user["id"], "assistant", text)
                message = text
    # fetch last messages for display
    msgs = query_db("SELECT m.*, u.username FROM messages m LEFT JOIN users u ON m.user_id=u.id WHERE m.user_id=? ORDER BY m.id DESC LIMIT 10", (user["id"],))
    msgs = [dict(m) for m in msgs]
    return render_template_string(
        BASE_HTML,
        user=user,
        content_template="""
        {% block content %}
          <form method="post">
            <div class="field">
              <input class="input" name="q" placeholder="Bir şey yaz..." />
            </div>
            <div><button class="btn" type="submit">Gönder</button></div>
          </form>
          {% if error %}
            <div class="msg bad">KralZeka: {{ error }}</div>
          {% endif %}
          {% if message %}
            <div class="msg"><strong>KralZeka:</strong> {{ message }}</div>
          {% endif %}
          <div class="list">
            <h3>Son mesajlar</h3>
            {% for m in msgs %}
               <div class="row"><strong>{{ m['username'] or 'Sen' }}:</strong> {{ m['text'] }}</div>
            {% endfor %}
          </div>
        {% endblock %}
        """,
        message=message,
        error=error,
        msgs=msgs
    )

# ------------------ Register & Login ------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        pr = request.form.get("password_repeat", "")
        if not u or not p:
            flash("Kullanıcı adı ve şifre gerekli.")
            return redirect(url_for("register"))
        if p != pr:
            flash("Şifreler uyuşmuyor.")
            return redirect(url_for("register"))
        created = create_user(u, p, is_admin=False)
        if not created:
            flash("Bu kullanıcı adı alınmış.")
            return redirect(url_for("register"))
        flash("Kayıt başarılı. Giriş yapabilirsin.")
        return redirect(url_for("login"))
    return render_template_string(BASE_HTML, user=current_user(), content_template="""
    {% block content %}
      <h2>Kayıt ol</h2>
      <form method="post">
        <div class="field"><input class="input" name="username" placeholder="Kullanıcı adı" /></div>
        <div class="field"><input class="input" type="password" name="password" placeholder="Şifre" /></div>
        <div class="field"><input class="input" type="password" name="password_repeat" placeholder="Şifre tekrar" /></div>
        <div><button class="btn">Kayıt ol</button></div>
      </form>
    {% endblock %}
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        user = verify_user(u, p)
        if not user:
            flash("Kullanıcı adı veya şifre yanlış.")
            return redirect(url_for("login"))
        session["user_id"] = user["id"]
        flash("Giriş başarılı.")
        next_url = request.args.get("next") or url_for("index")
        return redirect(next_url)
    return render_template_string(BASE_HTML, user=current_user(), content_template="""
    {% block content %}
      <h2>Giriş</h2>
      <form method="post">
        <div class="field"><input class="input" name="username" placeholder="Kullanıcı adı" /></div>
        <div class="field"><input class="input" type="password" name="password" placeholder="Şifre" /></div>
        <div><button class="btn">Giriş</button></div>
      </form>
    {% endblock %}
    """)

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.")
    return redirect(url_for("login"))

# ------------------ Upload image route ------------------
@app.route("/upload", methods=["POST"])
@require_login
def upload():
    user = current_user()
    if "file" not in request.files:
        flash("Dosya bulunamadı.")
        return redirect(url_for("index"))
    f = request.files["file"]
    try:
        path = save_upload(f)
        record_message(user["id"], "user", f"[Görsel yüklendi: {path}]")
        flash("Yüklendi.")
    except Exception as e:
        flash(f"Hata: {e}")
    return redirect(url_for("index"))

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ------------------ Image generation endpoint ------------------
@app.route("/generate_image", methods=["POST"])
@require_login
def generate_image():
    user = current_user()
    prompt = request.form.get("prompt", "").strip()
    model = request.form.get("model", "stabilityai/stable-diffusion-2-1")
    if not prompt:
        flash("Prompt boş")
        return redirect(url_for("index"))
    ok, result = hf_generate_image(prompt, model=model, user_id=user["id"])
    if not ok:
        flash(f"Görsel oluşturulamadı: {result}")
    else:
        flash("Görsel oluşturuldu.")
    return redirect(url_for("index"))

# ------------------ Quality upgrade (admin-limited) ------------------
@app.route("/quality/upgrade", methods=["POST"])
@require_login
def quality_upgrade():
    user = current_user()
    # only allow limited times per day for non-admins
    if not user.get("is_admin"):
        used = user_daily_quality_used_count(user["id"])
        if used >= user["daily_quality_limit"]:
            flash("Bugün kalite yükseltme hakkın doldu.")
            return redirect(url_for("index"))
        use_quality_upgrade(user["id"])
        flash("Kalite yükseltme talebin kaydedildi.")
    else:
        flash("Admin için sınırsız kalite yükseltme uygulandı.")
    return redirect(url_for("index"))

# ------------------ Suggestions (auto-fix requests) ------------------
@app.route("/suggest", methods=["POST"])
@require_login
def suggest():
    user = current_user()
    text = request.form.get("text", "").strip()
    if not text:
        flash("Boş öneri gönderilemez.")
        return redirect(url_for("index"))
    record_suggestion(user["id"], text)
    flash("Önerin alındı. Admin onayı bekliyor.")
    return redirect(url_for("index"))

# ------------------ Admin Panel ------------------
@app.route("/admin", methods=["GET", "POST"])
@require_admin
def admin_panel():
    user = current_user()
    db = get_db()
    # handle admin actions
    if request.method == "POST":
        action = request.form.get("action")
        if action == "make_admin":
            uid = int(request.form.get("user_id"))
            if uid == user["id"]:
                flash("Kendinle oynamazsın dostum.")
            else:
                db.execute("UPDATE users SET is_admin=1 WHERE id=?", (uid,))
                db.commit()
                record_admin_action(user["id"], "make_admin", f"user:{uid}")
                flash("Admin yapıldı.")
        elif action == "remove_user":
            uid = int(request.form.get("user_id"))
            # prevent removing main enes admin
            main = query_db("SELECT * FROM users WHERE username=?", (ADMIN_USERNAME,), one=True)
            if main and uid == main["id"]:
                # record attempt
                record_admin_action(user["id"], "attempt_remove_main_admin", f"tried:{uid}")
                flash("Enes admini kaldırılamaz.")
            else:
                db.execute("DELETE FROM users WHERE id=?", (uid,))
                db.commit()
                record_admin_action(user["id"], "remove_user", f"user:{uid}")
                flash("Kullanıcı silindi.")
        elif action == "approve_suggestion":
            sid = int(request.form.get("suggestion_id"))
            db.execute("UPDATE suggestions SET status='approved', admin_id=? WHERE id=?", (user["id"], sid))
            db.commit()
            record_admin_action(user["id"], "approve_suggestion", f"s:{sid}")
            flash("Öneri onaylandı.")
        elif action == "reject_suggestion":
            sid = int(request.form.get("suggestion_id"))
            db.execute("UPDATE suggestions SET status='rejected', admin_id=? WHERE id=?", (user["id"], sid))
            db.commit()
            record_admin_action(user["id"], "reject_suggestion", f"s:{sid}")
            flash("Öneri reddedildi.")
    users = query_db("SELECT id, username, is_admin, created_at, daily_quality_limit FROM users ORDER BY id DESC")
    suggestions = query_db("SELECT s.*, u.username FROM suggestions s LEFT JOIN users u ON s.user_id=u.id ORDER BY s.id DESC")
    messages = query_db("SELECT m.*, u.username FROM messages m LEFT JOIN users u ON m.user_id=u.id ORDER BY m.id DESC LIMIT 50")
    images = query_db("SELECT * FROM image_jobs ORDER BY id DESC LIMIT 30")
    actions = query_db("SELECT a.*, u.username as adminname FROM admin_actions a LEFT JOIN users u ON a.admin_id=u.id ORDER BY a.id DESC LIMIT 50")
    return render_template_string(BASE_HTML, user=user, content_template="""
    {% block content %}
      <h2>Admin Panel</h2>
      <div class="panel">
        <div class="left">
          <div class="row">
            <h3>Kullanıcılar</h3>
            {% for u in users %}
              <div class="row">
                <strong>{{ u.username }}</strong> <span class="small"> - {{ u.created_at }}</span>
                {% if not u.is_admin %}
                  <form style="display:inline" method="post">
                    <input type="hidden" name="user_id" value="{{ u.id }}" />
                    <input type="hidden" name="action" value="make_admin">
                    <button class="smallbtn">Admin yap</button>
                  </form>
                {% endif %}
                <form style="display:inline" method="post">
                  <input type="hidden" name="user_id" value="{{ u.id }}" />
                  <input type="hidden" name="action" value="remove_user">
                  <button class="smallbtn">Sil</button>
                </form>
              </div>
            {% endfor %}
          </div>

          <div class="row">
            <h3>Öneriler</h3>
            {% for s in suggestions %}
              <div class="row">
                <div class="label">#{{ s.id }} - {{ s.username or 'Anon' }} - {{ s.created_at }} - <strong>{{ s.status }}</strong></div>
                <div>{{ s.text }}</div>
                {% if s.status == 'pending' %}
                  <form method="post" style="display:inline">
                    <input type="hidden" name="suggestion_id" value="{{ s.id }}">
                    <input type="hidden" name="action" value="approve_suggestion">
                    <button class="smallbtn">Onayla</button>
                  </form>
                  <form method="post" style="display:inline">
                    <input type="hidden" name="suggestion_id" value="{{ s.id }}">
                    <input type="hidden" name="action" value="reject_suggestion">
                    <button class="smallbtn">Reddet</button>
                  </form>
                {% endif %}
              </div>
            {% endfor %}
          </div>

        </div>

        <div class="right">
          <div class="row">
            <h3>Son mesajlar</h3>
            {% for m in messages %}
              <div class="row"><strong>{{ m.username or 'Anon' }}:</strong> {{ m.text }} <div class="small">{{ m.created_at }}</div></div>
            {% endfor %}
          </div>

          <div class="row">
            <h3>Görsel işleri</h3>
            {% for i in images %}
              <div class="row">
                #{{ i.id }} - {{ i.prompt }} - {{ i.status }} <br/>
                {% if i.result_url %}
                  <img src="{{ url_for('uploaded_file', filename=i.result_url.split('/')[-1]) }}" style="max-width:100%; height:auto; margin-top:6px;" />
                {% endif %}
              </div>
            {% endfor %}
          </div>

          <div class="row">
            <h3>Admin Eylemleri</h3>
            {% for a in actions %}
              <div class="row">{{ a.created_at }} - {{ a.adminname }} - {{ a.action }} - {{ a.meta }}</div>
            {% endfor %}
          </div>
        </div>
      </div>
    {% endblock %}
    """, users=users, suggestions=suggestions, messages=messages, images=images, actions=actions)

# ------------------ Initialization helper route (one-time) ------------------
@app.route("/__init", methods=["GET"])
def one_time_init():
    """
    One-time initialization: creates DB and first admin if not exists.
    Not protected (but safe): calling multiple times won't recreate admin.
    """
    with app.app_context():
        init_db(force=False)
        # create initial admin if not exists
        row = query_db("SELECT * FROM users WHERE username=?", (ADMIN_USERNAME,), one=True)
        if not row:
            create_user(ADMIN_USERNAME, ADMIN_PASSWORD, is_admin=True, daily_limit=9999)
    return "Initialized (if not already). First admin: {} (changeme)".format(ADMIN_USERNAME)

# ------------------ Simple health / debug ------------------
@app.route("/health")
def health():
    return jsonify({"status":"ok", "time": now_iso()})

# ------------------ Error handlers ------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template_string(BASE_HTML, user=current_user(), content_template="""
    {% block content %}
      <h2>Erişim reddedildi</h2>
      <div class="msg bad">Bu sayfaya erişim izniniz yok.</div>
    {% endblock %}
    """), 403

@app.errorhandler(404)
def not_found(e):
    return render_template_string(BASE_HTML, user=current_user(), content_template="""
    {% block content %}
      <h2>Bulunamadı</h2>
      <div class="msg bad">Aradığın sayfa bulunamadı.</div>
    {% endblock %}
    """), 404

# ------------------ Start app ------------------
def start_app():
    # ensure DB exists and admin created
    with app.app_context():
        init_db(force=False)
        main_admin = query_db("SELECT * FROM users WHERE username=?", (ADMIN_USERNAME,), one=True)
        if not main_admin:
            create_user(ADMIN_USERNAME, ADMIN_PASSWORD, is_admin=True, daily_limit=9999)
    # Run Flask (for production use WSGI)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

if __name__ == "__main__":
    start_app()
