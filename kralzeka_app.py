#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Tek dosyalık Flask uygulaması
- Groq öncelikli, HF fallback chat
- Görsel üretme/kalite yükseltme (HF)
- Kullanıcı / Admin yönetimi
- Modlar: Ödev, Espri, Sohbet, Sunum, Admin Panel
- İlk admin otomatik: enes / enes1357924680
Çalıştırma (Render): gunicorn kralzeka_app:app
"""

from flask import Flask, g, render_template_string, request, redirect, url_for, session, flash, jsonify, send_from_directory
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import requests
import time
import datetime
import uuid
import traceback

# ---------- Ayarlar ----------
DATABASE = os.environ.get("DATABASE_PATH", "kralzeka.db")
FLASK_SECRET = os.environ.get("FLASK_SECRET", "please_set_FLASK_SECRET_env_to_secure_value")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")   # tercihen Render env'e koy
HF_API_KEY = os.environ.get("HF_API_KEY", "")       # huggingface token
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
# Kullanıcı başına günlük görsel hakkı (normal kullanıcı)
DAILY_IMAGE_LIMIT = 5
# -----------------------------

# Ensure upload folder
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Simple Flask app
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = FLASK_SECRET

# ---------- DB yardımcıları ----------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

def close_db(e=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

def init_db(force=False):
    """Create tables if needed. If force True, re-create."""
    db = get_db()
    cur = db.cursor()
    # Create tables
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        image_quota_reset DATE DEFAULT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        role TEXT, -- 'user' or 'assistant' or 'system'
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS admin_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        actor_username TEXT,
        target_username TEXT,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        feature TEXT, -- e.g. "image_upscale"
        count INTEGER DEFAULT 0,
        last_used DATE
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        traceback TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.commit()

    # Ensure first admin exists: username enes, password enes1357924680
    cur.execute("SELECT id FROM users WHERE username = ?", ("enes",))
    if not cur.fetchone():
        pw = generate_password_hash("enes1357924680")
        cur.execute("INSERT INTO users (username, password_hash, is_admin, image_quota_reset) VALUES (?, ?, 1, ?)",
                    ("enes", pw, datetime.date.today().isoformat()))
        db.commit()
        app.logger.info("İlk admin account (enes) oluşturuldu.")

# initialize DB at startup (if not exists)
with app.app_context():
    init_db()

# ---------- Utility / Decorators ----------
def log_event(level, message, tb=None):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO logs (level, message, traceback) VALUES (?, ?, ?)", (level, message, tb or ""))
        db.commit()
    except Exception:
        app.logger.exception("log_event hata")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Lütfen giriş yapın.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Admin yetkisi için giriş yapın.", "warning")
            return redirect(url_for("login", next=request.path))
        uid = session["user_id"]
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT is_admin FROM users WHERE id = ?", (uid,))
        r = cur.fetchone()
        if not r or r["is_admin"] != 1:
            flash("Bu alan sadece adminlere özeldir.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

def current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (session["user_id"],))
    r = cur.fetchone()
    return r

# Reset daily quotas if needed
def ensure_daily_quotas(user_id):
    db = get_db()
    cur = db.cursor()
    today = datetime.date.today().isoformat()
    cur.execute("SELECT image_quota_reset FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        reset = row["image_quota_reset"]
        if reset != today:
            # reset usage table entries for images
            cur.execute("DELETE FROM usage WHERE user_id = ? AND feature = ?", (user_id, "image_upscale"))
            cur.execute("UPDATE users SET image_quota_reset = ? WHERE id = ?", (today, user_id))
            db.commit()

def increment_usage(user_id, feature):
    db = get_db()
    cur = db.cursor()
    today = datetime.date.today().isoformat()
    cur.execute("SELECT id, count FROM usage WHERE user_id = ? AND feature = ?", (user_id, feature))
    r = cur.fetchone()
    if r:
        cur.execute("UPDATE usage SET count = count + 1, last_used = ? WHERE id = ?", (today, r["id"]))
    else:
        cur.execute("INSERT INTO usage (user_id, feature, count, last_used) VALUES (?, ?, 1, ?)", (user_id, feature, today))
    db.commit()

def get_usage_count(user_id, feature):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT count FROM usage WHERE user_id = ? AND feature = ?", (user_id, feature))
    r = cur.fetchone()
    return r["count"] if r else 0

# ---------- External AI helpers ----------
def call_groq_chat(prompt, model="openai/groq-1", max_tokens=512):
    """
    Sends prompt to Groq (primary). Expects GROQ_API_KEY env variable.
    Returns (success_bool, text_or_error)
    """
    if not GROQ_API_KEY:
        return False, "Groq API anahtarı bulunamadı."
    url = "https://api.groq.com/v1/chat/completions"  # example; adjust if different
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens
    }
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=25)
        if r.status_code == 200:
            j = r.json()
            # groq response structure may vary; try to extract possible fields
            if "choices" in j and len(j["choices"])>0:
                txt = j["choices"][0].get("message", {}).get("content", "") or j["choices"][0].get("text", "")
                return True, txt
            return True, j.get("text") or str(j)
        else:
            return False, f"Groq Hata {r.status_code}: {r.text}"
    except Exception as e:
        tb = traceback.format_exc()
        log_event("error", "Groq çağrısı başarısız", tb)
        return False, f"Groq isteği sırasında hata: {str(e)}"

def call_hf_chat(prompt, model_repo="tiiuae/falcon-7b-instruct", max_length=512):
    """
    Fallback chat using Hugging Face Inference API.
    HF_API_KEY must be present.
    """
    if not HF_API_KEY:
        return False, "Hugging Face API anahtarı bulunamadı."
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    # HF text generation endpoint
    url = f"https://api-inference.huggingface.co/models/{model_repo}"
    payload = {"inputs": prompt, "parameters": {"max_new_tokens": max_length, "return_full_text": False}}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=40)
        if r.status_code == 200:
            j = r.json()
            # j usually list of dict with 'generated_text'
            if isinstance(j, dict) and "error" in j:
                return False, f"HF hata: {j.get('error')}"
            if isinstance(j, list) and len(j)>0 and "generated_text" in j[0]:
                return True, j[0]["generated_text"]
            # Sometimes response is dict with 'generated_text'
            if isinstance(j, dict) and "generated_text" in j:
                return True, j["generated_text"]
            return True, str(j)
        else:
            return False, f"Hugging Face Hata {r.status_code}: {r.text}"
    except Exception as e:
        tb = traceback.format_exc()
        log_event("error", "HF chat çağrısı başarısız", tb)
        return False, f"HF isteği sırasında hata: {str(e)}"

def generate_image_hf(prompt, model_repo="stabilityai/stable-diffusion-2", size=None):
    """
    Uses Hugging Face image generation. Returns (success, bytes_or_error, mime)
    """
    if not HF_API_KEY:
        return False, "HF API anahtarı bulunamadı.", None
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    url = f"https://api-inference.huggingface.co/models/{model_repo}"
    data = {"inputs": prompt}
    if size:
        data["parameters"] = {"width": size[0], "height": size[1]}
    try:
        r = requests.post(url, headers=headers, json=data, timeout=60)
        if r.status_code == 200:
            # binary image returned sometimes; if JSON, check
            content_type = r.headers.get("content-type", "")
            if "application/json" in content_type:
                j = r.json()
                if "error" in j:
                    return False, f"HF image hata: {j['error']}", None
                return False, f"Beklenmedik HF yanıtı: {j}", None
            else:
                return True, r.content, content_type
        else:
            return False, f"Hugging Face image hata {r.status_code}: {r.text}", None
    except Exception as e:
        tb = traceback.format_exc()
        log_event("error", "HF image çağrısı başarısız", tb)
        return False, f"HF image isteği sırasında hata: {str(e)}", None

# ---------- Routes / Views ----------
# Simple base template (turkish)
BASE_HTML = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>KralZeka v1</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{background:#071019;color:#e6f3ee;font-family:Inter,Segoe UI,Arial;padding:24px}
    .container{max-width:980px;margin:20px auto}
    header{display:flex;justify-content:space-between;align-items:center}
    a{color:#8be08b;text-decoration:none}
    .box{background:#071a1a;padding:18px;border-radius:10px;box-shadow:0 4px 14px rgba(0,0,0,0.6)}
    input,textarea,select{width:100%;padding:10px;border-radius:8px;border:1px solid #153; background:#022; color:#fff}
    button{background:#0fa34a;color:#fff;padding:8px 14px;border-radius:8px;border:0;cursor:pointer}
    .msgs{margin-top:10px}
    .msg{padding:12px;margin:8px 0;border-radius:8px;background:#0b2a2a}
    .muted{color:#9aa7a7;font-size:14px}
    nav a{margin-left:12px}
    .admin-tag{color:#f6bd3b;font-weight:700}
    footer{margin-top:36px;text-align:center;color:#83a0a0}
    .danger{background:#2a0b0b}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>KralZeka v1</h1>
      <div>
        {% if user %}
          <span>Merhaba, <strong>{{ user['username'] }}</strong>{% if user['is_admin'] %} <span class="admin-tag">[ADMIN]</span>{% endif %}</span>
          <nav><a href="{{ url_for('logout') }}">Çıkış yap</a> | <a href="{{ url_for('admin_panel') }}">Admin Panel</a></nav>
        {% else %}
          <a href="{{ url_for('login') }}"><button>Giriş</button></a>
          <a href="{{ url_for('register') }}"><button>Kayıt</button></a>
        {% endif %}
      </div>
    </header>

    <section class="box">
      {% block content %}{% endblock %}
    </section>

    <footer>
      © KralZeka v1 — KralZeka, Enes'in zekasıyla hayat buldu.
    </footer>
  </div>
</body>
</html>
"""

@app.route("/")
def index():
    user = current_user()
    # show simple chat input
    content = """
    <h2>Ana Sohbet</h2>
    <p class="muted">Buradan sorularınızı yazın. Önce Groq, yoksa Hugging Face üzerinden cevap alınır.</p>
    {% if user %}
      <form method="post" action="{{ url_for('chat') }}">
        <select name="mode" style="width:220px;margin-bottom:8px;">
          <option value="chat">Sohbet Modu</option>
          <option value="homework">Ödev Yardımcısı</option>
          <option value="joke">Espri Modu</option>
          <option value="presentation">Sunum Modu</option>
        </select>
        <textarea name="prompt" rows="4" placeholder="Nasılsın? Ne yapmak istersin?" required></textarea>
        <div style="margin-top:8px"><button type="submit">Gönder</button></div>
      </form>
      <div class="msgs">
        <h3>Son mesajlar</h3>
        {% for m in messages %}
          <div class="msg"><strong>{{ m['username'] }}:</strong> {{ m['content'] }} <div class="muted">{{ m['created_at'] }}</div></div>
        {% endfor %}
      </div>
    {% else %}
      <p>Devam etmek için giriş yapın veya kayıt olun.</p>
    {% endif %}
    """
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username, content, created_at FROM messages ORDER BY created_at DESC LIMIT 6")
    messages = cur.fetchall()
    return render_template_string(BASE_HTML, user=user, messages=messages, content=content, )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, password_hash, is_admin FROM users WHERE username = ?", (username,))
        r = cur.fetchone()
        if not r:
            flash("Kullanıcı bulunamadı.", "danger")
            return redirect(url_for("login"))
        if check_password_hash(r["password_hash"], password):
            session["user_id"] = r["id"]
            flash("Giriş başarılı.", "success")
            return redirect(url_for("index"))
        else:
            flash("Parola hatalı.", "danger")
            return redirect(url_for("login"))
    # GET
    form_html = """
    <h2>Giriş</h2>
    <form method="post">
      <label>Kullanıcı adı</label>
      <input name="username" required>
      <label>Parola</label>
      <input name="password" type="password" required>
      <div style="margin-top:8px"><button>Giriş yap</button></div>
    </form>
    <p class="muted">İlk admin: enes / enes1357924680</p>
    """
    return render_template_string(BASE_HTML, user=current_user(), messages=[], content=form_html)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        password2 = request.form.get("password2","").strip()
        if password != password2:
            flash("Parolalar eşleşmiyor.", "danger")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Parola en az 6 karakter olmalı.", "danger")
            return redirect(url_for("register"))
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute("INSERT INTO users (username, password_hash, image_quota_reset) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password), datetime.date.today().isoformat()))
            db.commit()
            flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Bu kullanıcı adı zaten alınmış.", "danger")
            return redirect(url_for("register"))
    # GET
    form_html = """
    <h2>Kayıt Ol</h2>
    <form method="post">
      <label>Kullanıcı adı</label><input name="username" required>
      <label>Parola</label><input name="password" type="password" required>
      <label>Parola (tekrar)</label><input name="password2" type="password" required>
      <div style="margin-top:8px"><button>Kayıt ol</button></div>
    </form>
    """
    return render_template_string(BASE_HTML, user=current_user(), messages=[], content=form_html)

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("index"))

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    user = current_user()
    prompt = request.form.get("prompt","").strip()
    mode = request.form.get("mode","chat")
    if not prompt:
        flash("Boş mesaj gönderemezsiniz.", "warning")
        return redirect(url_for("index"))
    # Save user message
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO messages (user_id, username, role, content) VALUES (?, ?, 'user', ?)",
                (user["id"], user["username"], prompt))
    db.commit()

    # Build a system prompt based on mode
    system_prompt = ""
    if mode == "homework":
        system_prompt = "Sen bir yardımsever ödev asistanısın. Adımlar açık, örneklerle çöz."
    elif mode == "joke":
        system_prompt = "Sen espri yapmaktan hoşlanan bir yapay zekasın. Kısa ve komik ol."
    elif mode == "presentation":
        system_prompt = "Sunum hazırlanmasında yardımcı ol. Başlık, madde madde slayt önerileri ver."
    else:
        system_prompt = "Nazik, doğru ve yardımcı bir asistan ol."

    full_prompt = f"{system_prompt}\n\nKullanıcının sorusu:\n{prompt}"

    # Try Groq first
    success, resp = call_groq_chat(full_prompt)
    if not success:
        # fallback HF
        success2, resp2 = call_hf_chat(full_prompt)
        if success2:
            resp = resp2
            success = True

    if not success:
        resp_text = f"KralZeka: Üzgünüm cevap alınamadı. Ayrıntı: {resp}"
    else:
        resp_text = resp

    # Save assistant message
    try:
        cur.execute("INSERT INTO messages (user_id, username, role, content) VALUES (?, ?, 'assistant', ?)",
                    (user["id"], "KralZeka", resp_text))
        db.commit()
    except Exception:
        log_event("error", "mesaj DB kaydı başarısız", traceback.format_exc())

    flash("Cevap hazırlandı.", "success")
    return redirect(url_for("index"))

# Image generation endpoint
@app.route("/generate_image", methods=["POST"])
@login_required
def generate_image():
    user = current_user()
    prompt = request.form.get("prompt","").strip()
    size_w = int(request.form.get("width", 512))
    size_h = int(request.form.get("height", 512))
    # quota check
    ensure_daily_quotas(user["id"])
    if not user["is_admin"]:
        used = get_usage_count(user["id"], "image_upscale")
        if used >= DAILY_IMAGE_LIMIT:
            return jsonify({"ok": False, "error": "Günlük görsel oluşturma limitiniz doldu."}), 403

    # call HF image gen
    ok, payload, mime = generate_image_hf(prompt, size=(size_w, size_h))
    if not ok:
        return jsonify({"ok": False, "error": payload}), 500
    # save image
    fname = f"{int(time.time())}_{uuid.uuid4().hex}.png"
    path = os.path.join(UPLOAD_DIR, fname)
    try:
        with open(path, "wb") as f:
            f.write(payload)
        # increment usage
        increment_usage(user["id"], "image_upscale")
        return jsonify({"ok": True, "url": url_for("uploaded_file", filename=fname)})
    except Exception as e:
        log_event("error", "Resim kaydetme hatası", traceback.format_exc())
        return jsonify({"ok": False, "error": "Resim kaydetme hatası"}), 500

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# Admin panel
@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_panel():
    me = current_user()
    db = get_db()
    cur = db.cursor()
    if request.method == "POST":
        action = request.form.get("action")
        target = request.form.get("target")
        # Protect initial admin
        if target == "enes" and action in ("remove_admin","delete_user"):
            # log the attempt
            cur.execute("INSERT INTO admin_events (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)",
                        (action, me["username"], target, "İlk admin koruması: yapılamaz"))
            db.commit()
            flash("Enes hesabına bu işlem yapılamaz. Deneme loglandı.", "danger")
            return redirect(url_for("admin_panel"))

        try:
            if action == "promote":
                cur.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (target,))
                cur.execute("INSERT INTO admin_events (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)",
                            ("promote", me["username"], target, "yönetici atandı"))
                db.commit()
                flash(f"{target} admin yapıldı.", "success")
            elif action == "demote":
                cur.execute("UPDATE users SET is_admin = 0 WHERE username = ?", (target,))
                cur.execute("INSERT INTO admin_events (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)",
                            ("demote", me["username"], target, "adminlıktan düşürüldü"))
                db.commit()
                flash(f"{target} adminlikten alındı.", "success")
            elif action == "delete_user":
                cur.execute("DELETE FROM users WHERE username = ?", (target,))
                cur.execute("INSERT INTO admin_events (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)",
                            ("delete", me["username"], target, "kullanıcı silindi"))
                db.commit()
                flash(f"{target} silindi.", "success")
            elif action == "view_logs":
                # handled below
                pass
        except Exception:
            log_event("error", "admin action hata", traceback.format_exc())
            flash("Admin işlemi sırasında hata oluştu.", "danger")
    # get users and events
    cur.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.execute("SELECT * FROM admin_events ORDER BY created_at DESC LIMIT 50")
    events = cur.fetchall()
    cur.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 60")
    logs = cur.fetchall()
    # For initial admin notification: if earlier admin attempted to change enes, show it
    cur.execute("SELECT * FROM admin_events WHERE target_username = 'enes' ORDER BY created_at DESC LIMIT 5")
    enes_attempts = cur.fetchall()
    # Render admin panel
    admin_html = """
    <h2>Admin Panel</h2>
    <div>
      <h3>Kullanıcılar</h3>
      <form method="post">
        <select name="target">
          {% for u in users %}
            <option value="{{ u['username'] }}">{{ u['username'] }} {% if u['is_admin'] %}(admin){% endif %}</option>
          {% endfor %}
        </select>
        <select name="action">
          <option value="promote">Admin yap</option>
          <option value="demote">Adminlikten al</option>
          <option value="delete_user">Kullanıcıyı sil</option>
        </select>
        <button>Uygula</button>
      </form>
      <h3>Admin olayları (son 50)</h3>
      {% for e in events %}
        <div class="msg"><strong>{{ e['action'] }}</strong> - {{ e['actor_username'] }} -> {{ e['target_username'] }} <div class="muted">{{ e['details'] }} / {{ e['created_at'] }}</div></div>
      {% endfor %}
      <h3>Hata Logları (son 60)</h3>
      {% for l in logs %}
        <div class="msg danger"><strong>{{ l['level'] }}</strong>: {{ l['message'] }} <div class="muted">{{ l['created_at'] }}</div></div>
      {% endfor %}
      {% if enes_attempts %}
        <h3>Enes hesabına yönelik son denemeler</h3>
        {% for a in enes_attempts %}
          <div class="msg"><strong>{{ a['action'] }}</strong> - {{ a['actor_username'] }} <div class="muted">{{ a['details'] }} / {{ a['created_at'] }}</div></div>
        {% endfor %}
      {% endif %}
    </div>
    """
    return render_template_string(BASE_HTML, user=me, messages=[], content=admin_html, users=users, events=events, logs=logs, enes_attempts=enes_attempts)

# Health / debug (admin-only)
@app.route("/_health")
def health():
    return jsonify({"ok": True, "time": time.time()})

# Error handlers
@app.errorhandler(500)
def handle_500(e):
    tb = traceback.format_exc()
    log_event("error", "Internal Server Error", tb)
    return render_template_string(BASE_HTML, user=current_user(),
                                  messages=[], content=f"<h2>Sunucu Hatası</h2><pre>{str(e)}</pre>"), 500

# ---------- Run block (for local dev) ----------
if __name__ == "__main__":
    # Ensure DB is set in app context and init done
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 10000))
    print("KralZeka v1 starting on port", port)
    app.run(host="0.0.0.0", port=port, debug=False)
