#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KralZeka v1 - Tam sürüm Flask uygulaması (tek dosya).
- Groq öncelikli, Hugging Face fallback olarak kullanılır.
- DB: SQLite (local file: kralzeka.db)
- Start with gunicorn: gunicorn kralzeka_app:app
- Env vars:
    - FLASK_SECRET (string)  -> flask secret key
    - HF_API_KEY (string)    -> Hugging Face token (opsiyonel ama gerekli özellikler için)
    - GROQ_API_KEY (string)  -> Groq token (opsiyonel)
    - INITIAL_ADMIN_PASSWORD (optional) -> override default admin password
"""

import os
import sqlite3
import json
import time
import uuid
import base64
import traceback
from datetime import datetime, timedelta, date
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, send_from_directory, flash, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

import requests

# --- CONFIG ---
APP_NAME = "KralZeka v1"
DB_PATH = os.environ.get("KRALZEKA_DB", "kralzeka.db")
UPLOAD_FOLDER = os.environ.get("KRALZEKA_UPLOADS", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HF_API_KEY = os.environ.get("HF_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
FLASK_SECRET = os.environ.get("FLASK_SECRET", "please-set-a-secret")
# initial admin password override
INITIAL_ADMIN_PASSWORD = os.environ.get("INITIAL_ADMIN_PASSWORD", "enes1357924680")

# daily image upscale limit for normal users
DEFAULT_DAILY_UPSCALE_LIMIT = 5

# Allowed image extensions
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}

# --- flask app ---
app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit

# --- Utilities ---
def log(msg):
    ts = datetime.utcnow().isoformat()
    print(f"[{ts}] {msg}", flush=True)

def get_db_conn():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force=False):
    """Initialize the database. Safe to call multiple times."""
    conn = get_db_conn()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        daily_upscale_count INTEGER DEFAULT 0,
        daily_upscale_date DATE
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        role TEXT, -- 'user' or 'assistant' or 'system'
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS admin_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        action TEXT,
        meta TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS features (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """)
    conn.commit()
    # ensure initial admin exists
    cur.execute("SELECT id FROM users WHERE username = ?", ("enes",))
    r = cur.fetchone()
    if not r or force:
        pwd = INITIAL_ADMIN_PASSWORD or "enes1357924680"
        phash = generate_password_hash(pwd)
        try:
            cur.execute("INSERT OR REPLACE INTO users (username, password_hash, is_admin, daily_upscale_count, daily_upscale_date) VALUES (?,?,?,?,?)",
                        ("enes", phash, 1, 0, date.today().isoformat()))
            conn.commit()
            log("Initial admin 'enes' created/updated.")
        except Exception as e:
            log("Could not insert admin user: " + str(e))
    conn.close()

# call init at import time safely
try:
    init_db()
except Exception:
    log("DB init error:\n" + traceback.format_exc())

# --- Auth helpers ---
def login_user(username):
    session['username'] = username

def logout_user():
    session.pop('username', None)

def get_current_user():
    username = session.get('username')
    if not username:
        return None
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def login_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if not session.get('username'):
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return _wrap

def admin_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        user = get_current_user()
        if not user or not user.get('is_admin'):
            flash("Bu bölüm yalnızca adminlere özeldir.", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return _wrap

# --- Simple feature store ---
def set_feature(key, value):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO features (key, value) VALUES (?,?)", (key, json.dumps(value)))
    conn.commit()
    conn.close()

def get_feature(key, default=None):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT value FROM features WHERE key = ?", (key,))
    r = cur.fetchone()
    conn.close()
    if r:
        try:
            return json.loads(r[0])
        except Exception:
            return r[0]
    return default

# default features
if get_feature("modes") is None:
    set_feature("modes", {
        "sohbet": True,
        "odev": True,
        "espri": True,
        "sunum": True,
        "gorsel": True
    })

# --- Helpers for messages ---
def add_message(user_id, role, content):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO messages (user_id, role, content) VALUES (?,?,?)", (user_id, role, content))
    conn.commit()
    conn.close()

def get_recent_messages(limit=50):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT m.*, u.username FROM messages m LEFT JOIN users u ON u.id = m.user_id ORDER BY m.created_at DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Image helpers ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def hf_image_inference(file_path, task="image-to-image", model="stabilityai/stable-diffusion-2", params=None):
    """
    Sends image to HF inference API (simple wrapper).
    Returns dict with {ok:bool, data:...}
    """
    if not HF_API_KEY:
        return {"ok": False, "error": "HF_API_KEY yok"}
    # read file
    try:
        url = f"https://api-inference.huggingface.co/models/{model}"
        headers = {"Authorization": f"Bearer {HF_API_KEY}"}
        with open(file_path, "rb") as f:
            data = f.read()
        # For many HF endpoints, we can POST raw bytes
        r = requests.post(url, headers=headers, data=data, timeout=60)
        if r.status_code == 200:
            # response might be image bytes or json
            content_type = r.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return {"ok": True, "data": r.json()}
            else:
                return {"ok": True, "data": r.content}
        else:
            return {"ok": False, "error": f"HF status {r.status_code}: {r.text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def groq_chat_completion(prompt, model="gpt-4o-mini", temperature=0.2):
    """
    Try to call Groq API (pseudo). If fails, return error dict.
    We assume user will set GROQ_API_KEY in env. Endpoint unknown in some environments,
    so this function is defensive.
    """
    if not GROQ_API_KEY:
        return {"ok": False, "error": "No GROQ_API_KEY"}
    try:
        # Example Groq API format (may differ); adapt as needed by user.
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": 800
        }
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        if r.status_code in (200, 201):
            return {"ok": True, "data": r.json()}
        else:
            return {"ok": False, "error": f"GROQ {r.status_code}: {r.text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def hf_chat_completion(prompt, model="gpt2", temperature=0.2):
    """Fallback: use Hugging Face text-generation inference if Groq not available."""
    if not HF_API_KEY:
        return {"ok": False, "error": "No HF_API_KEY"}
    try:
        url = f"https://api-inference.huggingface.co/models/google/flan-t5-small"  # example; user may change
        headers = {"Authorization": f"Bearer {HF_API_KEY}"}
        payload = {"inputs": prompt}
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        if r.status_code == 200:
            data = r.json()
            # HF often returns list of dicts
            if isinstance(data, list) and data:
                return {"ok": True, "data": data}
            return {"ok": True, "data": data}
        else:
            return {"ok": False, "error": f"HF chat status {r.status_code}: {r.text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def call_ai_chat(prompt):
    """Try Groq first; if fails, fallback to HF. Return text."""
    g = groq_chat_completion(prompt)
    if g.get("ok"):
        try:
            # parse typical response structure
            choices = g["data"].get("choices")
            if choices and len(choices) > 0:
                txt = choices[0].get("message", {}).get("content") or choices[0].get("text") or str(choices[0])
                return {"ok": True, "data": txt}
            # if entire json contains text
            return {"ok": True, "data": json.dumps(g["data"])}
        except Exception:
            return {"ok": True, "data": json.dumps(g["data"])}
    else:
        # try HF
        h = hf_chat_completion(prompt)
        if h.get("ok"):
            try:
                # convert HF output to string
                if isinstance(h["data"], list):
                    return {"ok": True, "data": h["data"][0].get("generated_text", str(h["data"]))}
                if isinstance(h["data"], dict):
                    return {"ok": True, "data": h["data"].get("generated_text", json.dumps(h["data"]))}
                return {"ok": True, "data": str(h["data"])}
            except Exception:
                return {"ok": True, "data": str(h["data"])}
        else:
            # both failed
            return {"ok": False, "error": f"GROQ: {g.get('error')}; HF: {h.get('error')}"}

# --- TEMPLATES ---
# Use render_template_string with safe defaults to minimize Jinja errors.
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>{{ app_name|default('KralZeka') }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{background:#050607;color:#d9f7ee;font-family:Inter,Arial;margin:0;padding:0}
    header{background:#06282a;padding:18px 30px}
    .container{max-width:980px;margin:30px auto;padding:20px;background:#041416;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,0.6)}
    input[type=text], input[type=password], textarea, select{width:100%;padding:10px;margin:6px 0;border-radius:8px;border:1px solid #2b524f;background:#0b2b2a;color:#dff}
    button{background:#0e8e4a;color:white;padding:10px 18px;border:none;border-radius:8px;cursor:pointer}
    .btn-ghost{background:transparent;border:1px solid #0e8e4a;color:#0e8e4a}
    .row{display:flex;gap:12px}
    .col{flex:1}
    .message{background:#062c2b;padding:12px;border-radius:10px;margin:8px 0}
    .small{font-size:0.9em;color:#a9e7d8}
    .danger{color:#ff7b7b}
    nav a{color:#cfeee1;margin-right:12px}
    footer{padding:16px;text-align:center;color:#8fbfb4}
    .panel{background:#082d2c;padding:12px;border-radius:10px}
    .muted{color:#6ea79f}
  </style>
</head>
<body>
  <header>
    <div style="max-width:980px;margin:0 auto;color:#fff;">
      <h2 style="margin:0">{{ app_name|default('KralZeka') }}</h2>
    </div>
  </header>
  <div class="container">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat,msg in messages %}
          <div class="message"><strong class="{{ cat }}">{{ msg }}</strong></div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </div>
  <footer>© {{ app_name|default('KralZeka') }} — KralZeka, Enes'in zekasıyla hayat buldu.</footer>
</body>
</html>
"""

INDEX_HTML = """
{% extends base %}
{% block content %}
  <div style="display:flex;gap:18px;flex-wrap:wrap">
    <div style="flex:1;min-width:320px">
      <div class="panel">
        {% if user %}
          <div><strong>Merhaba, {{ user.username|default('') }} {% if user.is_admin %}<span style="color:#e9cf3a">[ADMIN]</span>{% endif %}</strong></div>
          <div class="small">Hoşgeldin! Modlar: {% for k,v in modes.items() %}{{ k }}{% if not loop.last %}, {% endif %}{% endfor %}</div>
          <div style="margin-top:8px;">
            <form method="post" action="{{ url_for('send_message') }}">
              <textarea name="message" rows="3" placeholder="Bir şey yaz..." required></textarea>
              <div style="display:flex;gap:10px;margin-top:6px">
                <select name="mode">
                  <option value="sohbet">Sohbet</option>
                  <option value="odev">Ödev</option>
                  <option value="espri">Espri</option>
                  <option value="sunum">Sunum</option>
                </select>
                <button type="submit">Gönder</button>
                <a href="{{ url_for('upload_view') }}" class="btn-ghost" style="padding:8px;text-decoration:none">Fotoğraf Yükle</a>
                {% if user.is_admin %}
                  <a href="{{ url_for('admin_panel') }}" style="padding:8px;text-decoration:none;color:#ffd27a">Admin Panel</a>
                {% endif %}
              </div>
            </form>
          </div>
        {% else %}
          <div class="small">Giriş yap veya kayıt ol.</div>
          <div style="display:flex;gap:8px;margin-top:8px">
            <a href="{{ url_for('login') }}" class="btn-ghost" style="padding:8px;text-decoration:none">Giriş</a>
            <a href="{{ url_for('register') }}" class="btn-ghost" style="padding:8px;text-decoration:none">Kayıt</a>
          </div>
        {% endif %}
      </div>

      <div style="margin-top:18px">
        <h3>Son Mesajlar</h3>
        {% for msg in messages %}
          <div class="message">
            <div><strong>{{ msg.username|default('Anon') }}:</strong> {{ msg.content|default('') }}</div>
            <div class="small muted">{{ msg.created_at }}</div>
          </div>
        {% else %}
          <div class="small muted">Henüz mesaj yok.</div>
        {% endfor %}
      </div>
    </div>

    <div style="width:320px;min-width:260px">
      <div class="panel">
        <h4>Durum</h4>
        <div class="small">Groq hazır: <strong>{{ groq_ok|default(false) }}</strong></div>
        <div class="small">HuggingFace hazır: <strong>{{ hf_ok|default(false) }}</strong></div>
        <hr/>
        <h4>Modlar</h4>
        <ul class="small">
          {% for k,v in modes.items() %}
            <li>{{ k }} — {{ 'Açık' if v else 'Kapalı' }}</li>
          {% endfor %}
        </ul>
        <hr/>
        <h4>Hızlı Aksiyonlar</h4>
        <div class="small">
          <form method="post" action="{{ url_for('self_diagnose') }}">
            <button type="submit" class="btn-ghost">Sistemi Kontrol Et</button>
          </form>
        </div>
      </div>

      <div style="margin-top:12px" class="panel">
        <h4>Yenilik Talebi</h4>
        <form method="post" action="{{ url_for('feature_request') }}">
          <input type="text" name="title" placeholder="Talep başlığı" required/>
          <textarea name="desc" rows="3" placeholder="Detay" required></textarea>
          <button type="submit">Gönder</button>
        </form>
      </div>
    </div>
  </div>
{% endblock %}
"""

LOGIN_HTML = """
{% extends base %}
{% block content %}
  <h3>Giriş Yap</h3>
  <form method="post">
    <input type="text" name="username" placeholder="Kullanıcı adı" required/>
    <input type="password" name="password" placeholder="Şifre" required/>
    <button type="submit">Giriş</button>
  </form>
{% endblock %}
"""

REGISTER_HTML = """
{% extends base %}
{% block content %}
  <h3>Kayıt Ol</h3>
  <form method="post">
    <input type="text" name="username" placeholder="Kullanıcı adı" required/>
    <input type="password" name="password" placeholder="Şifre" required/>
    <input type="password" name="password2" placeholder="Şifre (tekrar)" required/>
    <button type="submit">Kayıt</button>
  </form>
{% endblock %}
"""

UPLOAD_HTML = """
{% extends base %}
{% block content %}
  <h3>Fotoğraf Yükle</h3>
  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file" accept="image/*" required/>
    <select name="action">
      <option value="describe">Fotoğrafı Açıkla</option>
      <option value="upscale">Kalite Yükselt (günlük limit uygulanır)</option>
    </select>
    <button type="submit">Yükle ve İşle</button>
  </form>
{% endblock %}
"""

ADMIN_HTML = """
{% extends base %}
{% block content %}
  <h3>Admin Paneli</h3>
  <div style="display:flex;gap:12px">
    <div style="flex:1">
      <h4>Kullanıcılar</h4>
      {% for u in users %}
        <div class="panel small">
          <strong>{{ u.username }}</strong> {% if u.is_admin %}<span style="color:#ffd27a">[ADMIN]</span>{% endif %}
          <div class="small muted">Oluşturulma: {{ u.created_at }}</div>
          <div style="margin-top:6px">
            {% if not (u.username == 'enes') %}
              <form method="post" style="display:inline" action="{{ url_for('admin_make_admin') }}">
                <input type="hidden" name="username" value="{{ u.username }}">
                <button type="submit">Admin Yap</button>
              </form>
              <form method="post" style="display:inline" action="{{ url_for('admin_delete_user') }}">
                <input type="hidden" name="username" value="{{ u.username }}">
                <button type="submit" class="danger">Sil</button>
              </form>
            {% else %}
              <div class="small muted">İlk admin (enes) korumalıdır.</div>
            {% endif %}
          </div>
        </div>
      {% endfor %}
    </div>

    <div style="width:360px">
      <h4>Admin Araçları</h4>
      <div class="panel small">
        <form method="post" action="{{ url_for('admin_broadcast') }}">
          <textarea name="text" rows="3" placeholder="Tüm kullanıcılara duyuru..."></textarea>
          <button type="submit">Duyur</button>
        </form>
      </div>

      <h4>Log / Son İşlemler</h4>
      <div class="panel small">
        {% for a in actions %}
          <div class="small"><strong>{{ a.action }}</strong> — {{ a.created_at }} (admin_id: {{ a.admin_id }})</div>
        {% else %}
          <div class="small muted">Henüz admin işlemi yok.</div>
        {% endfor %}
      </div>
    </div>
  </div>
{% endblock %}
"""

# --- ROUTES ---
@app.route("/", methods=["GET"])
def index():
    try:
        user = get_current_user()
        msgs = get_recent_messages(20)
        modes = get_feature("modes", {})
        groq_ok = bool(GROQ_API_KEY)
        hf_ok = bool(HF_API_KEY)
        return render_template_string(
            INDEX_HTML,
            base=BASE_HTML, app_name=APP_NAME, user=user, messages=msgs,
            modes=modes, groq_ok=groq_ok, hf_ok=hf_ok
        )
    except Exception as e:
        log("Index render error: " + str(e))
        # render a minimal fallback page to avoid 500
        return render_template_string(BASE_HTML, app_name=APP_NAME, base=BASE_HTML, content=f"<div class='message danger'>Sunucu hata verdi: {str(e)}</div>")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")
        if not username or not password:
            flash("Kullanıcı adı ve şifre gerekli.", "error")
            return redirect(url_for('login'))
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row["password_hash"], password):
            login_user(username)
            flash("Giriş başarılı.", "info")
            return redirect(url_for('index'))
        else:
            flash("Giriş başarısız.", "error")
            return redirect(url_for('login'))
    return render_template_string(LOGIN_HTML, base=BASE_HTML, app_name=APP_NAME)

@app.route("/logout")
def logout():
    logout_user()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for('index'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if not username or not password or not password2:
            flash("Tüm alanlar gerekli.", "error")
            return redirect(url_for('register'))
        if password != password2:
            flash("Şifreler eşleşmiyor.", "error")
            return redirect(url_for('register'))
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            phash = generate_password_hash(password)
            cur.execute("INSERT INTO users (username, password_hash, is_admin, daily_upscale_count, daily_upscale_date) VALUES (?,?,?,?,?)",
                        (username, phash, 0, 0, date.today().isoformat()))
            conn.commit()
            flash("Kayıt başarılı. Giriş yapabilirsiniz.", "info")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Kullanıcı adı alınmış.", "error")
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template_string(REGISTER_HTML, base=BASE_HTML, app_name=APP_NAME)

@app.route("/send_message", methods=["POST"])
@login_required
def send_message():
    try:
        user = get_current_user()
        text = (request.form.get("message") or "").strip()
        mode = (request.form.get("mode") or "sohbet")
        if not text:
            flash("Boş mesaj gönderilemez.", "error")
            return redirect(url_for('index'))
        # store user message
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (user['username'],))
        row = cur.fetchone()
        user_id = row[0] if row else None
        add_message(user_id, "user", text)
        # Prepare AI prompt depending on mode
        prompt = f"[MOD:{mode}] {text}\nLütfen Türkçe cevap ver ve kısaca özetle."
        # Call AI (groq -> hf)
        res = call_ai_chat(prompt)
        if res.get("ok"):
            ai_text = res.get("data")
            add_message(user_id, "assistant", ai_text)
            flash("Cevap hazır.", "info")
        else:
            add_message(user_id, "assistant", "Üzgünüm, model çağrılamadı: " + str(res.get("error")))
            flash("AI çağrısında sorun: " + str(res.get("error")), "error")
    except Exception as e:
        log("send_message error: " + traceback.format_exc())
        flash("Mesaj gönderilirken hata oluştu.", "error")
    return redirect(url_for('index'))

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_view():
    user = get_current_user()
    if request.method == "POST":
        if 'file' not in request.files:
            flash("Dosya yok.", "error")
            return redirect(url_for('upload_view'))
        f = request.files['file']
        if f.filename == '':
            flash("Dosya adı boş.", "error")
            return redirect(url_for('upload_view'))
        if not allowed_file(f.filename):
            flash("Geçersiz dosya uzantısı.", "error")
            return redirect(url_for('upload_view'))
        action = request.form.get("action", "describe")
        filename = secure_filename(f.filename)
        unique = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
        f.save(path)
        # If upscale action, check daily limit
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            cur.execute("SELECT id, daily_upscale_count, daily_upscale_date FROM users WHERE username = ?", (user['username'],))
            r = cur.fetchone()
            if r:
                uid = r["id"]
                count = r["daily_upscale_count"] or 0
                ddate = r["daily_upscale_date"] or date.today().isoformat()
                if ddate != date.today().isoformat():
                    count = 0
                    ddate = date.today().isoformat()
                if action == "upscale" and not user.get('is_admin'):
                    if count >= DEFAULT_DAILY_UPSCALE_LIMIT:
                        flash("Günlük kalite yükseltme limiti doldu.", "error")
                        return redirect(url_for('upload_view'))
            else:
                flash("Kullanıcı bulunamadı.", "error")
                return redirect(url_for('upload_view'))
            # Call HF image inference
            if GROQ_API_KEY:
                # prefer Groq? Not all Groq endpoints support images; keep HF as main for images
                pass
            hf_res = hf_image_inference(path)
            if hf_res.get("ok"):
                data = hf_res.get("data")
                # if bytes -> save returned image
                if isinstance(data, (bytes, bytearray)):
                    outname = unique + "_out.png"
                    outpath = os.path.join(app.config['UPLOAD_FOLDER'], outname)
                    with open(outpath, "wb") as out:
                        out.write(data)
                    flash("İşlem tamamlandi. Görsel kaydedildi.", "info")
                else:
                    flash("İşlem tamamlandı (metin).", "info")
                # increment daily count if upscale
                if action == "upscale":
                    new_count = (count or 0) + 1
                    cur.execute("UPDATE users SET daily_upscale_count = ?, daily_upscale_date = ? WHERE id = ?", (new_count, date.today().isoformat(), uid))
                    conn.commit()
            else:
                flash("Görsel işlem hatası: " + str(hf_res.get("error")), "error")
            conn.close()
        except Exception as e:
            log("upload error: " + traceback.format_exc())
            flash("Yükleme sırasında hata: " + str(e), "error")
        return redirect(url_for('upload_view'))
    return render_template_string(UPLOAD_HTML, base=BASE_HTML, app_name=APP_NAME)

@app.route("/admin", methods=["GET"])
@admin_required
def admin_panel():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC")
    users = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM admin_actions ORDER BY created_at DESC LIMIT 50")
    actions = [dict(r) for r in cur.fetchall()]
    conn.close()
    return render_template_string(ADMIN_HTML, base=BASE_HTML, app_name=APP_NAME, users=users, actions=actions)

@app.route("/admin/make_admin", methods=["POST"])
@admin_required
def admin_make_admin():
    target = (request.form.get("username") or "").strip()
    current = get_current_user()
    if not target:
        flash("Hedef kullanıcı yok.", "error")
        return redirect(url_for('admin_panel'))
    if target == "enes":
        flash("enes hesabına müdahale edilemez.", "error")
        return redirect(url_for('admin_panel'))
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (target,))
    conn.commit()
    cur.execute("INSERT INTO admin_actions (admin_id, action, meta) VALUES (?,?,?)", (current['id'], "make_admin", target))
    conn.commit()
    conn.close()
    flash(f"{target} artık admin.", "info")
    return redirect(url_for('admin_panel'))

@app.route("/admin/delete_user", methods=["POST"])
@admin_required
def admin_delete_user():
    target = (request.form.get("username") or "").strip()
    current = get_current_user()
    if not target:
        flash("Hedef kullanıcı yok.", "error")
        return redirect(url_for('admin_panel'))
    if target == "enes":
        # log attempt
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO admin_actions (admin_id, action, meta) VALUES (?,?,?)", (current['id'], "delete_attempt_on_enes", target))
        conn.commit()
        conn.close()
        flash("Bu kullanıcı silinemez. Enes'e bildirildi.", "error")
        return redirect(url_for('admin_panel'))
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (target,))
    conn.commit()
    cur.execute("INSERT INTO admin_actions (admin_id, action, meta) VALUES (?,?,?)", (current['id'], "delete_user", target))
    conn.commit()
    conn.close()
    flash(f"{target} silindi.", "info")
    return redirect(url_for('admin_panel'))

@app.route("/admin/broadcast", methods=["POST"])
@admin_required
def admin_broadcast():
    text = (request.form.get("text") or "").strip()
    current = get_current_user()
    if not text:
        flash("Mesaj boş.", "error")
        return redirect(url_for('admin_panel'))
    conn = get_db_conn()
    cur = conn.cursor()
    # attach broadcast as system messages for visibility
    cur.execute("INSERT INTO messages (user_id, role, content) VALUES (?,?,?)", (current['id'], 'system', text))
    conn.commit()
    cur.execute("INSERT INTO admin_actions (admin_id, action, meta) VALUES (?,?,?)", (current['id'], "broadcast", text))
    conn.commit()
    conn.close()
    flash("Duyuru gönderildi.", "info")
    return redirect(url_for('admin_panel'))

@app.route("/feature_request", methods=["POST"])
@login_required
def feature_request():
    title = (request.form.get("title") or "").strip()
    desc = (request.form.get("desc") or "").strip()
    user = get_current_user()
    if not title or not desc:
        flash("Başlık ve açıklama gerekli.", "error")
        return redirect(url_for('index'))
    # store as admin_action for review
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO admin_actions (admin_id, action, meta) VALUES (?,?,?)", (user['id'], "feature_request", json.dumps({"title": title, "desc": desc})))
    conn.commit()
    conn.close()
    flash("Talebiniz gönderildi. Teşekkürler!", "info")
    return redirect(url_for('index'))

@app.route("/self_diagnose", methods=["POST"])
@login_required
def self_diagnose():
    # run a small diagnostic and report to user
    try:
        groq_ok = bool(GROQ_API_KEY)
        hf_ok = bool(HF_API_KEY)
        resp = {
            "groq": groq_ok,
            "hf": hf_ok,
            "db_exists": os.path.exists(DB_PATH),
            "uploads_dir": os.path.exists(app.config['UPLOAD_FOLDER']),
            "timestamp": datetime.utcnow().isoformat()
        }
        flash("Sistem tanılama yapıldı. Sonuç: " + json.dumps(resp), "info")
    except Exception as e:
        flash("Tanılama hatası: " + str(e), "error")
    return redirect(url_for('index'))


# --- API endpoint for admin-only "kod yaz" feature ---
@app.route("/admin/code_writer", methods=["POST"])
@admin_required
def admin_code_writer():
    """
    Bu endpoint adminlerin kod talep etmesine izin verir.
    Güvenlik nedeniyle bu sadece metin üretir ve dosya sistemi üzerinde otomatik çalıştırmaz.
    """
    prompt = (request.form.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"ok": False, "error": "prompt boş"}), 400
    # ask AI for a code snippet
    res = call_ai_chat("Kod üret: " + prompt)
    if res.get("ok"):
        return jsonify({"ok": True, "code": res.get("data")})
    else:
        return jsonify({"ok": False, "error": res.get("error")}), 500

# --- Static send for uploaded files (safe) ---
@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    # only allow serving from uploads folder
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

# --- Start helper for gunicorn ---
def start_app():
    # any startup tasks
    log(f"{APP_NAME} starting... (Groq: {bool(GROQ_API_KEY)}, HF: {bool(HF_API_KEY)})")

# run when module imported by gunicorn
start_app()

# Expose app for gunicorn
# `gunicorn kralzeka_app:app`
