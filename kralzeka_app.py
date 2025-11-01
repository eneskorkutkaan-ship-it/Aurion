#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka — Tek dosya tam sürüm (Render hazır)
Özellikler:
- Groq API entegre (KEY başa kondu)
- Kayıt / Giriş (SQLite)
- Modlar: Sohbet, Espri, Ödev, Sunum, Görsel
- Görsel yükleme (＋ butonu), kalite yükseltme (admin sınırsız, kullanıcı günlük limit)
- Admin panel: kullanıcı liste/promo/demote/delete, limit yönetimi, log
- Hatırlatıcı, tema seçimi, basit araçlar
- Tek dosya: kralzeka_app.py
"""

import os
import sqlite3
import uuid
import datetime
from functools import wraps
from flask import Flask, g, render_template_string, request, redirect, url_for, session, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from PIL import Image

# ----------------- AYARLAR -----------------
# <--- GROQ KEY: SENİN SAĞLADIĞIN KEY AŞAĞIDA -->
GROQ_API_KEY = "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"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"

# Uygulama ayarları
DB_FILE = "kralzeka.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXT = {"png", "jpg", "jpeg"}
PORT = int(os.environ.get("PORT", 5000))
SECRET_KEY = os.environ.get("KZ_SECRET") or os.urandom(24)
MAX_DAILY_QUALITY = 5  # normal kullanıcılar için günlük kalite hakkı
# --------------------------------------------

# Dosya klasörleri
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------- Veritabanı yardımcıları ----------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_FILE, check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    # users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT,
        theme TEXT DEFAULT 'dark'
    )""")
    # messages
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT,
        mode TEXT,
        created_at TEXT
    )""")
    # uploads
    cur.execute("""
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        created_at TEXT
    )""")
    # limits
    cur.execute("""
    CREATE TABLE IF NOT EXISTS limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        date TEXT,
        quality_used INTEGER DEFAULT 0
    )""")
    # logs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        by_user_id INTEGER,
        target_user_id INTEGER,
        created_at TEXT,
        meta TEXT
    )""")
    # reminders
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        text TEXT,
        remind_at TEXT,
        created_at TEXT
    )""")
    db.commit()

    # Create default admin enes if not exists
    cur.execute("SELECT * FROM users WHERE username = ?", ("enes",))
    if not cur.fetchone():
        pw_hash = generate_password_hash("enes1357924680")
        cur.execute("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
                    ("enes", pw_hash, 1, datetime.datetime.utcnow().isoformat()))
        db.commit()

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# ---------- Auth & session ----------
def login_user(row):
    session["user_id"] = row["id"]
    session["username"] = row["username"]
    session["is_admin"] = bool(row["is_admin"])

def logout_user():
    session.clear()

def current_user():
    if "user_id" in session:
        return {"id": session["user_id"], "username": session["username"], "is_admin": session.get("is_admin", False)}
    return None

def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if not current_user():
            return redirect(url_for("index"))
        return f(*a, **k)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        u = current_user()
        if not u or not u.get("is_admin"):
            return "Erişim reddedildi", 403
        return f(*a, **k)
    return wrapper

# ---------- yardımcı fonksiyonlar ----------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def log_action(action, by_user_id=None, target_user_id=None, meta=None):
    db = get_db()
    db.execute("INSERT INTO logs (action, by_user_id, target_user_id, created_at, meta) VALUES (?, ?, ?, ?, ?)",
               (action, by_user_id, target_user_id, datetime.datetime.utcnow().isoformat(), meta))
    db.commit()

def get_today_date():
    return datetime.datetime.utcnow().date().isoformat()

def increment_quality_usage(user_id, amount=1):
    db = get_db()
    today = get_today_date()
    cur = db.execute("SELECT * FROM limits WHERE user_id = ? AND date = ?", (user_id, today))
    row = cur.fetchone()
    if row:
        used = row["quality_used"] + amount
        db.execute("UPDATE limits SET quality_used = ? WHERE id = ?", (used, row["id"]))
    else:
        used = amount
        db.execute("INSERT INTO limits (user_id, date, quality_used) VALUES (?, ?, ?)", (user_id, today, used))
    db.commit()
    return used

def get_quality_used(user_id):
    db = get_db()
    today = get_today_date()
    cur = db.execute("SELECT quality_used FROM limits WHERE user_id = ? AND date = ?", (user_id, today))
    row = cur.fetchone()
    return row["quality_used"] if row else 0

# ---------- Groq query ----------
def groq_query(prompt):
    if not GROQ_API_KEY:
        return "Model anahtarı ayarlı değil."
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": "Sen KralZeka'sın, Türkçe konuşan yardımsever bir asistansın."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7
    }
    try:
        r = requests.post(GROQ_API_URL, headers=headers, json=body, timeout=30)
        if r.status_code == 200:
            data = r.json()
            # extract safely
            try:
                return data.get("choices", [{}])[0].get("message", {}).get("content", "Model cevap vermedi.")
            except:
                return str(data)
        else:
            return f"Model hata {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"Model isteğinde hata: {e}"

# ---------- FRONTEND HTML (tek dosya) ----------
INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>KralZeka 👑</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{
      --bg:#070812; --panel:#0d1725; --accent:#7b61ff; --muted:#9fb0d0; --card:#0c2333;
    }
    body{margin:0;font-family:Inter,Arial;background:linear-gradient(180deg,var(--bg),#0a0f1a);color:#e9f2ff}
    .top{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 18px;background:rgba(0,0,0,0.15)}
    .brand{font-weight:700}
    .container{display:flex;height:calc(100vh - 64px)}
    .sidebar{width:280px;background:var(--panel);padding:16px;box-sizing:border-box}
    .main{flex:1;padding:16px;display:flex;flex-direction:column}
    .mod{padding:10px;border-radius:8px;margin:8px 0;cursor:pointer;color:var(--muted)}
    .mod.active{background:linear-gradient(90deg,var(--accent),#5aa0ff);color:white}
    .chatbox{flex:1;background:var(--card);padding:12px;border-radius:10px;overflow:auto}
    .inputbar{display:flex;margin-top:12px}
    input[type=text]{flex:1;padding:10px;border-radius:8px;border:none;background:rgba(255,255,255,0.03);color:white}
    .btn{padding:10px 12px;border-radius:8px;border:none;background:var(--accent);color:white;margin-left:8px;cursor:pointer}
    .plus{display:inline-block;padding:8px;border-radius:8px;background:rgba(255,255,255,0.03);cursor:pointer;margin-right:8px}
    .small{font-size:13px;color:var(--muted)}
    .msg.user{background:rgba(11,85,120,0.25);padding:8px;border-radius:8px;margin:8px 0;text-align:right}
    .msg.bot{background:rgba(255,255,255,0.03);padding:8px;border-radius:8px;margin:8px 0;text-align:left}
    .adminpanel{background:rgba(255,255,255,0.02);padding:8px;border-radius:8px;margin-top:12px;color:var(--muted)}
    .file-preview{max-width:220px;border-radius:8px;margin-top:8px;display:block}
    .tools{margin-top:12px}
    .note{font-size:12px;color:#bcd3ff;margin-top:6px}
  </style>
</head>
<body>
  <div class="top">
    <div class="brand">KralZeka 👑</div>
    <div class="small">
      {% if user %}
        Hoşgeldin, <b>{{ user }}</b> {% if is_admin %}(Admin){% endif %} | <a href="/logout" style="color:#bfe1ff">Çıkış</a>
      {% else %}
        <a href="/login" style="color:#bfe1ff">Giriş / Kayıt</a>
      {% endif %}
    </div>
  </div>

  <div class="container">
    <div class="sidebar">
      <div style="font-weight:700;margin-bottom:8px">Modlar</div>
      <div id="mods">
        <div class="mod active" data-mode="chat">💬 Sohbet Modu</div>
        <div class="mod" data-mode="home2">🎓 Ödeve Yardım</div>
        <div class="mod" data-mode="fun">😂 Espri Modu</div>
        <div class="mod" data-mode="present">📊 Sunum Modu</div>
        <div class="mod" data-mode="images">🖼️ Görsel İşleme</div>
        {% if is_admin %}
        <div class="mod" data-mode="admin">🛠️ Admin Paneli</div>
        {% endif %}
      </div>

      <div class="tools">
        <div class="small">Araçlar</div>
        <div style="margin-top:6px">
          <button class="btn" onclick="openTool('calculator')">Hesap Makinesi</button>
        </div>
      </div>

      <div style="margin-top:12px" class="adminpanel">
        <div class="small"><b>Yönetim</b></div>
        {% if is_admin %}
          <div class="small">Admin erişimi etkin</div>
        {% else %}
          <div class="small">Admin değilsin</div>
        {% endif %}
      </div>
    </div>

    <div class="main">
      <div id="content-area">
        <div class="chatbox" id="chatbox">
          <div class="small">Hoşgeldin! Mod seçerek başlayabilirsin.</div>
        </div>

        <div class="inputbar">
          <div class="plus" title="Fotoğraf yükle" onclick="document.getElementById('fileInput').click()">＋</div>
          <input type="file" id="fileInput" style="display:none" accept=".png,.jpg,.jpeg" onchange="uploadFile(event)">
          <input type="text" id="userInput" placeholder="KralZeka'ya bir şey sor...">
          <button class="btn" onclick="sendMessage()">Gönder</button>
        </div>
        <div id="previewArea"></div>
        <div class="note">Not: Görsel kalite yükseltme günlük 5 kullanım (admin sınırsız).</div>
      </div>
    </div>
  </div>

<script>
let currentMode = "chat";
const chatbox = document.getElementById('chatbox');
document.querySelectorAll('.mod').forEach(el=>{
  el.addEventListener('click', ()=> {
    document.querySelectorAll('.mod').forEach(m=>m.classList.remove('active'));
    el.classList.add('active');
    currentMode = el.getAttribute('data-mode');
    appendBot('Mod değişti: ' + el.textContent.trim());
    if(currentMode === 'admin') loadAdmin();
  });
});

function appendUser(msg){ chatbox.innerHTML += `<div class="msg user">${msg}</div>`; chatbox.scrollTop = chatbox.scrollHeight; }
function appendBot(msg){ chatbox.innerHTML += `<div class="msg bot">${msg}</div>`; chatbox.scrollTop = chatbox.scrollHeight; }

async function sendMessage(){
  const v = document.getElementById('userInput').value.trim();
  if(!v) return;
  appendUser(v);
  document.getElementById('userInput').value = '';
  appendBot('...');

  const res = await fetch('/api/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message:v,mode:currentMode})});
  const data = await res.json();
  // replace last bot '...' with actual
  const nodes = document.querySelectorAll('.msg.bot');
  nodes[nodes.length-1].outerHTML = `<div class="msg bot">${data.reply}</div>`;
}

async function uploadFile(e){
  const f = e.target.files[0];
  if(!f) return;
  const form = new FormData();
  form.append('file', f);
  const res = await fetch('/upload', {method:'POST', body: form});
  const data = await res.json();
  if(data.ok){
    document.getElementById('previewArea').innerHTML = `<img src="/uploads/${encodeURIComponent(data.filename)}" class="file-preview">`;
    appendBot('Görsel yüklendi; "kalite" veya "çöz" yaz veya ilgili moda geç.');
  } else {
    appendBot('Yükleme hatası: '+data.error);
  }
}

function openTool(tool){
  if(tool==='calculator') {
    appendBot('Hesap makinesi: bir işlem yazıp gönder (ör: 2+2)');
  }
}

// admin load
async function loadAdmin(){
  const res = await fetch('/admin/info');
  if(res.status===200){
    const d = await res.json();
    if(d.is_admin){
      appendBot('Admin paneline erişim hazır.');
    } else {
      appendBot('Admin erişimi yok.');
    }
  }
}
</script>
</body>
</html>
"""

# ---------- ROUTES ----------

@app.route("/")
def index():
    user = session.get("username")
    is_admin = session.get("is_admin", False)
    return render_template_string(INDEX_HTML, user=user, is_admin=is_admin)

# Login & Register forms (GET for forms, POST for actions)
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="GET":
        return """
        <h3>Giriş</h3>
        <form method="post">
          Kullanıcı: <input name="username"><br>
          Şifre: <input name="password" type="password"><br>
          <button>Giriş</button>
        </form>
        <p>Yeni misin? <a href="/register">Kayıt ol</a></p>
        """
    username = request.form.get("username","").strip()
    password = request.form.get("password","").strip()
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return "Kullanıcı veya şifre hatalı", 400
    login_user(row)
    log_action("login", by_user_id=row["id"])
    return redirect(url_for("index"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="GET":
        return """
        <h3>Kayıt</h3>
        <form method="post">
          Kullanıcı: <input name="username"><br>
          Şifre: <input name="password" type="password"><br>
          Şifre tekrar: <input name="confirm" type="password"><br>
          <button>Kayıt Ol</button>
        </form>
        """
    username = request.form.get("username","").strip()
    password = request.form.get("password","").strip()
    confirm = request.form.get("confirm","").strip()
    if not username or not password or password!=confirm:
        return "Eksik alan veya şifreler uyuşmuyor",400
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        return "Kullanıcı zaten var",400
    pw_hash = generate_password_hash(password)
    is_admin = 1 if username == "enes" and check_password_hash(generate_password_hash("enes1357924680"), generate_password_hash("enes1357924680")) else 0
    # note: we already created enes at init_db, so register won't create duplicate
    db.execute("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
               (username, pw_hash, is_admin, datetime.datetime.utcnow().isoformat()))
    db.commit()
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))

# Upload endpoint
@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if 'file' not in request.files:
        return jsonify({"ok":False,"error":"Dosya bulunamadı"})
    f = request.files['file']
    if f.filename == "":
        return jsonify({"ok":False,"error":"Boş dosya"})
    if not allowed_file(f.filename):
        return jsonify({"ok":False,"error":"Geçersiz uzantı"})
    filename = secure_filename(f"{uuid.uuid4().hex}_{f.filename}")
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    f.save(path)
    db = get_db()
    u = current_user()
    db.execute("INSERT INTO uploads (user_id, filename, created_at) VALUES (?, ?, ?)",
               (u["id"], filename, datetime.datetime.utcnow().isoformat()))
    db.commit()
    log_action("upload", by_user_id=u["id"], meta=filename)
    return jsonify({"ok":True,"filename":filename})

@app.route("/uploads/<path:filename>")
def serve_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# Chat API
@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json()
    msg = data.get("message","")
    mode = data.get("mode","chat")
    user = current_user()
    db = get_db()
    # store user message
    db.execute("INSERT INTO messages (user_id, content, mode, created_at) VALUES (?, ?, ?, ?)",
               (user["id"], msg, mode, datetime.datetime.utcnow().isoformat()))
    db.commit()

    # routing by mode
    if mode == "chat":
        reply = groq_query(msg)
    elif mode == "fun":
        reply = groq_query("Espri modu: " + msg)
    elif mode == "home2":  # ödev modu
        reply = groq_query("Ödev yardım modu. Soru: " + msg)
    elif mode == "present":
        reply = groq_query("Sunum modu: " + msg + " için kısa slayt başlıkları hazırla.")
    elif mode == "images":
        reply = "Görsel modu: Görsel yükleyin veya 'kalite <dosyaadı>' yazın."
    elif mode == "admin":
        if not user["is_admin"]:
            return jsonify({"reply":"Erişim reddedildi"}), 403
        reply = "Admin alanına hoşgeldin."
    else:
        reply = groq_query(msg)

    # store bot reply
    db.execute("INSERT INTO messages (user_id, content, mode, created_at) VALUES (?, ?, ?, ?)",
               (None, reply, mode, datetime.datetime.utcnow().isoformat()))
    db.commit()
    return jsonify({"reply": reply})

# Quality upgrade endpoint
@app.route("/api/quality", methods=["POST"])
@login_required
def api_quality():
    data = request.get_json()
    filename = data.get("filename")
    if not filename:
        return jsonify({"ok":False,"msg":"filename required"}),400
    user = current_user()
    db = get_db()
    if not user["is_admin"]:
        used = get_quality_used(user["id"])
        if used >= MAX_DAILY_QUALITY:
            return jsonify({"ok":False,"msg":"Günlük kalite hakkınız doldu."}), 403
    # increment usage
    increment_quality_usage(user["id"],1)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.exists(path):
        return jsonify({"ok":False,"msg":"file not found"}),404
    try:
        im = Image.open(path)
        w,h = im.size
        im2 = im.resize((w*2, h*2), Image.LANCZOS)
        newname = f"q_{uuid.uuid4().hex}_{filename}"
        newpath = os.path.join(app.config["UPLOAD_FOLDER"], newname)
        im2.save(newpath)
        db.execute("INSERT INTO uploads (user_id, filename, created_at) VALUES (?, ?, ?)",
                   (user["id"], newname, datetime.datetime.utcnow().isoformat()))
        db.commit()
        log_action("quality_upgrade", by_user_id=user["id"], meta=newname)
        return jsonify({"ok":True,"filename":newname})
    except Exception as e:
        return jsonify({"ok":False,"msg":str(e)}),500

# Admin endpoints
@app.route("/admin/info")
@login_required
def admin_info():
    u = current_user()
    return jsonify({"is_admin": bool(u.get("is_admin", False)), "username": u.get("username")})

@app.route("/admin/users", methods=["GET","POST"])
@admin_required
def admin_users():
    db = get_db()
    if request.method=="GET":
        rows = db.execute("SELECT id, username, is_admin, created_at FROM users").fetchall()
        return jsonify([dict(r) for r in rows])
    data = request.get_json()
    action = data.get("action")
    target = data.get("username")
    byu = current_user()
    if action=="promote":
        if target == "enes":
            return jsonify({"ok":False,"msg":"enes zaten kral admin"}),400
        db.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (target,))
        db.commit()
        log_action("promote", by_user_id=byu["id"], meta=target)
        return jsonify({"ok":True})
    if action=="demote":
        if target == "enes":
            log_action("demote_attempt", by_user_id=byu["id"], meta=target)
            return jsonify({"ok":False,"msg":"enes demote edilemez"}),400
        db.execute("UPDATE users SET is_admin = 0 WHERE username = ?", (target,))
        db.commit()
        log_action("demote", by_user_id=byu["id"], meta=target)
        return jsonify({"ok":True})
    if action=="delete":
        if target == "enes":
            log_action("delete_attempt", by_user_id=byu["id"], meta=target)
            return jsonify({"ok":False,"msg":"enes silinemez"}),400
        cur = db.execute("SELECT id FROM users WHERE username = ?", (target,))
        row = cur.fetchone()
        if row:
            db.execute("DELETE FROM users WHERE id = ?", (row["id"],))
            db.commit()
            log_action("delete", by_user_id=byu["id"], meta=target)
            return jsonify({"ok":True})
        return jsonify({"ok":False,"msg":"kullanıcı yok"}),404
    return jsonify({"ok":False})

@app.route("/admin/limits", methods=["GET","POST"])
@admin_required
def admin_limits():
    db = get_db()
    if request.method=="GET":
        rows = db.execute("SELECT l.id, u.username, l.date, l.quality_used FROM limits l LEFT JOIN users u ON u.id = l.user_id ORDER BY l.date DESC").fetchall()
        return jsonify([dict(r) for r in rows])
    data = request.get_json()
    username = data.get("username")
    action = data.get("action")
    value = int(data.get("quality",0))
    cur = db.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        return jsonify({"ok":False,"msg":"user not found"}),404
    uid = row["id"]
    today = get_today_date()
    cur2 = db.execute("SELECT * FROM limits WHERE user_id = ? AND date = ?", (uid,today)).fetchone()
    if action=="set":
        if cur2:
            db.execute("UPDATE limits SET quality_used = ? WHERE id = ?", (value, cur2["id"]))
        else:
            db.execute("INSERT INTO limits (user_id, date, quality_used) VALUES (?, ?, ?)", (uid,today,value))
        db.commit()
        log_action("limits_set", by_user_id=current_user()["id"], target_user_id=uid, meta=str(value))
        return jsonify({"ok":True})
    return jsonify({"ok":False})

@app.route("/admin/logs")
@admin_required
def admin_logs():
    db = get_db()
    rows = db.execute("SELECT l.*, u.username as byname FROM logs l LEFT JOIN users u ON u.id = l.by_user_id ORDER BY created_at DESC LIMIT 300").fetchall()
    return jsonify([dict(r) for r in rows])

# Reminders
@app.route("/api/reminder", methods=["POST"])
@login_required
def api_reminder():
    data = request.get_json()
    text = data.get("text")
    when = data.get("when")  # ISO datetime
    db = get_db()
    u = current_user()
    db.execute("INSERT INTO reminders (user_id, text, remind_at, created_at) VALUES (?, ?, ?, ?)",
               (u["id"], text, when, datetime.datetime.utcnow().isoformat()))
    db.commit()
    return jsonify({"ok":True})

# tools endpoints (placeholder)
@app.route("/api/tools/calc", methods=["POST"])
@login_required
def api_calc():
    data = request.get_json()
    expr = data.get("expr","")
    try:
        # very simple safe eval: allow digits and ops only
        import re
        if not re.match(r'^[0-9+\-*/(). ]+$', expr):
            return jsonify({"ok":False,"msg":"İzinsiz karakter"}),400
        result = eval(expr)
        return jsonify({"ok":True,"result":result})
    except Exception as e:
        return jsonify({"ok":False,"msg":str(e)}),400

# ---------- Başlat ----------
if __name__ == "__main__":
    init_db()
    print("KralZeka başlatılıyor — http://0.0.0.0:%s" % PORT)
    app.run(host="0.0.0.0", port=PORT)
