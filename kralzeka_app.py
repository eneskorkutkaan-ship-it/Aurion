#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v2 Full — tek dosya
Kullanım:
  - Ortam değişkenleri:
      GROQ_API_KEY  ( Groq chat api key )
      HF_API_KEY    ( Hugging Face api key )
      FLASK_SECRET  ( rastgele uzun string )
  - Çalıştır: python3 kralzeka_app.py
Not: PROD için ek güvenlik (HTTPS, rate limit, stronger PW hashing) önerilir.
"""
import os
import sqlite3
import json
import time
import traceback
from datetime import datetime, date
from functools import wraps
from io import BytesIO
import base64
import uuid

import requests
from flask import (
    Flask, g, render_template_string, request, redirect, url_for, session,
    flash, send_from_directory, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Optional pillow for local image ops
try:
    from PIL import Image, ImageFilter
    PIL_OK = True
except Exception:
    PIL_OK = False

# ---------------- CONFIG ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "kralzeka.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")  # required for chat
HF_API_KEY = os.environ.get("HF_API_KEY")      # required for images
FLASK_SECRET = os.environ.get("FLASK_SECRET", "change_this_in_env")

# Groq model hardcoded into code as requested
GROQ_MODEL = "llama-3.1-8b-instant"

# Limits
USER_DAILY_QUALITY_LIMIT = 5  # normal users
ADMIN_QUALITY_LIMIT = 999999

ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}
MAX_UPLOAD_MB = 15

# Flask app
app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024

# ---------------- DB HELPERS ----------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT,
        last_reset DATE,
        image_used_today INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        role TEXT,
        content TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        title TEXT,
        details TEXT,
        status TEXT DEFAULT 'open',
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT,
        action TEXT,
        target TEXT,
        meta TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        kind TEXT,
        content TEXT,
        created_at TEXT
    );
    """)
    db.commit()
    # initial admin
    row = db.execute("SELECT id FROM users WHERE username = ?", ("enes",)).fetchone()
    if not row:
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at, last_reset, image_used_today) VALUES (?,?,?,?,?,?)",
            ("enes", generate_password_hash("enes1357924680"), 1, datetime.utcnow().isoformat(), date.today().isoformat(), 0)
        )
        db.commit()

# ---------------- AUTH DECORATORS ----------------
def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        u = get_db().execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if not u or not u['is_admin']:
            flash("Bu sayfaya erişim için admin olmalısın.", "danger")
            return redirect(url_for('index'))
        return f(*a, **kw)
    return wrapped

# ---------------- UTIL ----------------
def add_message(user_id, username, role, content):
    db = get_db()
    db.execute("INSERT INTO messages (user_id, username, role, content, created_at) VALUES (?,?,?,?,?)",
               (user_id, username, role, content, datetime.utcnow().isoformat()))
    db.commit()

def log_admin(actor, action, target=None, meta=None):
    db = get_db()
    db.execute("INSERT INTO admin_logs (actor, action, target, meta, created_at) VALUES (?,?,?,?,?)",
               (actor, action, target, json.dumps(meta, ensure_ascii=False) if meta else None, datetime.utcnow().isoformat()))
    db.commit()

def add_request(uid, username, title, details):
    db = get_db()
    db.execute("INSERT INTO requests (user_id, username, title, details, created_at) VALUES (?,?,?,?,?)",
               (uid, username, title, details, datetime.utcnow().isoformat()))
    db.commit()

def add_memory(uid, username, kind, content):
    db = get_db()
    db.execute("INSERT INTO memories (user_id, username, kind, content, created_at) VALUES (?,?,?,?,?)",
               (uid, username, kind, content, datetime.utcnow().isoformat()))
    db.commit()

def reset_daily_if_needed(user_row):
    if not user_row:
        return
    last = user_row['last_reset']
    today = date.today().isoformat()
    if last != today:
        db = get_db()
        db.execute("UPDATE users SET image_used_today = 0, last_reset = ? WHERE id = ?", (today, user_row['id']))
        db.commit()

# ---------------- GROQ CHAT ----------------
def call_groq_chat(prompt, system=None):
    if not GROQ_API_KEY:
        return False, "GROQ_API_KEY yok. Ortam değişkenine ekle."
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    body = {
        "model": GROQ_MODEL,
        "messages": messages,
        "max_tokens": 800,
        "temperature": 0.2
    }
    try:
        r = requests.post(url, headers=headers, json=body, timeout=30)
        r.raise_for_status()
        j = r.json()
        if isinstance(j, dict) and "choices" in j and j["choices"]:
            ch = j["choices"][0]
            text = None
            if isinstance(ch.get("message"), dict):
                text = ch["message"].get("content")
            if not text:
                text = ch.get("text") or str(ch)
            return True, text
        return False, "Model beklenmedik format döndü."
    except Exception as e:
        return False, str(e)

# ---------------- HUGGINGFACE IMAGE ----------------
def hf_generate_image(prompt):
    if not HF_API_KEY:
        return False, "HF_API_KEY yok."
    # model can be changed in config table later; default:
    model = "stabilityai/stable-diffusion-xl-base-1.0"
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    try:
        r = requests.post(url, headers=headers, json={"inputs": prompt}, timeout=60)
        r.raise_for_status()
        ct = r.headers.get("content-type","")
        if ct.startswith("image/"):
            return True, r.content
        # sometimes HF returns json with base64 or url
        try:
            jr = r.json()
            # search for base64 in keys
            if isinstance(jr, dict):
                for v in jr.values():
                    if isinstance(v, str) and v.startswith("data:image"):
                        return True, base64.b64decode(v.split(",",1)[1])
            return False, json.dumps(jr)[:1000]
        except Exception:
            return False, r.text[:1000]
    except Exception as e:
        return False, str(e)

def save_image_bytes(bytes_data, prefix="gen"):
    fn = f"{prefix}_{int(time.time())}_{uuid.uuid4().hex[:8]}.png"
    path = os.path.join(app.config['UPLOAD_FOLDER'], fn)
    with open(path, "wb") as f:
        f.write(bytes_data)
    return fn, path

def pil_upscale(img_bytes):
    if not PIL_OK:
        return False, "Pillow yüklü değil."
    try:
        im = Image.open(BytesIO(img_bytes)).convert("RGB")
        w,h = im.size
        im2 = im.resize((w*2, h*2), Image.LANCZOS).filter(ImageFilter.SHARPEN)
        buf = BytesIO()
        im2.save(buf, format="PNG", quality=90)
        return True, buf.getvalue()
    except Exception as e:
        return False, str(e)

# ---------------- HEALTH & AUTO-FIX ----------------
def system_health_checks():
    issues = []
    # db file and tables
    try:
        db = get_db()
        db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    except Exception as e:
        issues.append("DB hatası: " + str(e))
    if not os.path.isdir(app.config['UPLOAD_FOLDER']):
        issues.append("Upload klasörü yok.")
    if not GROQ_API_KEY:
        issues.append("GROQ_API_KEY eksik (chat çalışmaz).")
    if not HF_API_KEY:
        issues.append("HF_API_KEY eksik (görsel fonksiyonları sınırlı).")
    return issues

def perform_auto_fix(action):
    # admin-only actions executed via API with admin check
    try:
        if action == "recreate_db":
            init_db()
            return True, "DB yeniden init edildi."
        if action == "create_upload":
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            return True, "Upload klasörü oluşturuldu."
        return False, "Bilinmeyen eylem."
    except Exception as e:
        return False, str(e)

# ---------------- ROUTES & TEMPLATES ----------------
# Sade tek sayfa arayüz, admin panel aynı sayfada sol menü
INDEX_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>KralZeka</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#071018;--card:#0b1b1b;--accent:#16a085;--muted:#98bfb6;--text:#e6f2f1}
body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Arial}
.container{display:flex;min-height:100vh}
.sidebar{width:260px;background:var(--card);padding:18px;box-sizing:border-box}
.main{flex:1;padding:18px}
h1{margin:0;font-size:20px}
.btn{background:var(--accent);padding:8px 12px;border-radius:8px;border:none;color:#fff;cursor:pointer}
.mode{padding:8px;border-radius:6px;margin:6px 0;background:#072d2b;cursor:pointer}
.mode.active{background:var(--accent)}
.card{background:#081c1b;padding:12px;border-radius:8px;margin-bottom:12px}
.small{color:var(--muted);font-size:13px}
.chatbox{height:360px;overflow:auto;padding:10px;background:#051717;border-radius:8px}
.msg.user{text-align:right;color:#9fe6c9;margin:8px 0}
.msg.bot{text-align:left;color:#fff2b3;margin:8px 0}
.upload-preview{max-width:120px;border-radius:8px;margin-top:8px}
.link{color:#9fd;text-decoration:underline;cursor:pointer}
.admin-badge{background:#ffc107;color:#111;padding:4px 6px;border-radius:6px;font-weight:700}
</style>
</head><body>
<div class="container">
  <div class="sidebar">
    <h1>KralZeka 👑</h1>
    <div class="small">Kullanıcı: <strong>{{ username }}</strong> {% if is_admin %}<span class="admin-badge">ADMIN</span>{% endif %}</div>
    <hr style="border-color:#072a29">
    <div><strong>Modlar</strong></div>
    <div id="mod_chat" class="mode active" onclick="setMode('chat')">💬 Sohbet</div>
    <div id="mod_homework" class="mode" onclick="setMode('homework')">📘 Ödev Yardımı</div>
    <div id="mod_joke" class="mode" onclick="setMode('joke')">😂 Espri</div>
    <div id="mod_slides" class="mode" onclick="setMode('slides')">📊 Sunum</div>
    <div id="mod_image" class="mode" onclick="setMode('image')">🖼 Görsel</div>
    <hr style="border-color:#072a29">
    <div><button class="btn" onclick="openRequests()">📩 İstek Gönder</button></div>
    <div style="margin-top:10px">
      <form id="uploadForm" enctype="multipart/form-data" method="post" action="/upload">
        <label class="small">Fotoğraf yükle</label><br>
        <input type="file" name="file" id="fileInput"><br>
        <button type="submit" class="btn" style="margin-top:8px">Yükle</button>
      </form>
    </div>
    <hr style="border-color:#072a29">
    <div style="margin-top:8px">
      <a class="link" href="/about">Hakkında</a><br>
      <a class="link" href="/logout">Çıkış</a><br>
      {% if is_admin %}
        <div style="margin-top:10px"><a class="link" href="#" onclick="openAdmin()">Admin Panel</a></div>
      {% endif %}
    </div>
  </div>

  <div class="main">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div><strong id="modeLabel">Sohbet</strong> <span class="small"> - Modu seç</span></div>
        <div class="small">Model: <strong>Groq — {{ groq_model }}</strong></div>
      </div>
    </div>

    <div class="card">
      <div id="chatbox" class="chatbox">
        {% for m in messages %}
          {% if m.role == 'user' %}
            <div class="msg user"><strong>Sen:</strong> {{ m.content }} <div class="small">{{ m.created_at }}</div></div>
          {% else %}
            <div class="msg bot"><strong>KralZeka:</strong> {{ m.content }} <div class="small">{{ m.created_at }}</div></div>
          {% endif %}
        {% endfor %}
      </div>

      <div style="display:flex;gap:8px;margin-top:10px">
        <input id="prompt" type="text" placeholder="Bir şey yaz..." style="flex:1;padding:10px;border-radius:8px;border:none;background:#0b2b29;color:#fff">
        <button class="btn" onclick="sendPrompt()">Gönder</button>
      </div>
      <div id="uploadPreview"></div>
    </div>

    <div id="panelArea"></div>

  </div>
</div>

<script>
let curMode = 'chat';
function setMode(m){
  curMode = m;
  document.getElementById('modeLabel').innerText = ({
    chat:'Sohbet', homework:'Ödev Yardımı', joke:'Espri', slides:'Sunum', image:'Görsel'
  }[m]||m);
  document.querySelectorAll('.mode').forEach(x=>x.classList.remove('active'));
  document.getElementById('mod_'+m).classList.add('active');
}
async function sendPrompt(){
  const p = document.getElementById('prompt').value.trim();
  if(!p) return;
  const box = document.getElementById('chatbox');
  box.innerHTML += `<div class="msg user"><strong>Sen:</strong> ${p}</div>`;
  document.getElementById('prompt').value='';
  const res = await fetch('/api/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({prompt:p, mode:curMode})});
  const j = await res.json();
  if(j.ok){
    if(j.type === 'image'){
      box.innerHTML += `<div class="msg bot"><strong>KralZeka:</strong><br><img src="${j.url}" style="max-width:260px;border-radius:8px"></div>`;
    } else {
      box.innerHTML += `<div class="msg bot"><strong>KralZeka:</strong> ${j.answer}</div>`;
    }
  } else {
    box.innerHTML += `<div class="msg bot"><strong>KralZeka:</strong> Hata: ${j.error || 'bilinmeyen'}</div>`;
  }
  box.scrollTop = box.scrollHeight;
}

function openRequests(){
  fetch('/requests').then(r=>r.text()).then(html=>{ document.getElementById('panelArea').innerHTML = html; window.scrollTo(0,document.body.scrollHeight); });
}
function openAdmin(){
  fetch('/admin').then(r=>r.text()).then(html=>{ document.getElementById('panelArea').innerHTML = html; window.scrollTo(0,0); });
}
</script>
</body></html>
"""

# small HTML fragments returned into panelArea
REQUESTS_HTML = """
<div class="card">
  <h3>Yeni Özellik İsteği Gönder</h3>
  <form method="post" action="/requests">
    <input name="title" placeholder="Kısa başlık" style="width:80%;padding:8px;border-radius:6px"><br><br>
    <textarea name="details" placeholder="Detay..." style="width:90%;height:100px;padding:8px;border-radius:6px"></textarea><br>
    <button class="btn" type="submit">Gönder</button>
  </form>
</div>
"""

ADMIN_PANEL_HTML = """
<div class="card">
  <h3>Admin Panel</h3>
  <div style="display:flex;gap:12px">
    <div style="flex:1">
      <h4>Kullanıcılar</h4>
      <ul>
      {% for u in users %}
        <li>{{ u.username }} {% if u.is_admin %}(admin){% endif %} 
          {% if u.username != 'enes' %}
            - <a href="/admin/make_admin/{{u.id}}">Admin Yap</a> 
            - <a href="/admin/delete/{{u.id}}">Sil</a>
          {% else %}
            - <em>korunan</em>
          {% endif %}
        </li>
      {% endfor %}
      </ul>
    </div>
    <div style="flex:1">
      <h4>İstekler</h4>
      <ul>
      {% for r in reqs %}
        <li><strong>{{ r.title }}</strong> — {{ r.username }} — {{ r.created_at }} <br>{{ r.details }} <br>
          <a href="/admin/resolve/{{ r.id }}">Tamamlandı</a>
        </li>
      {% endfor %}
      </ul>
    </div>
  </div>
  <h4>Admin Log</h4>
  <ul>
  {% for a in logs %}
    <li>{{ a.created_at }} — {{ a.actor }} — {{ a.action }} — {{ a.target }} — {{ a.meta }}</li>
  {% endfor %}
  </ul>
  <div style="margin-top:8px">
    <form method="post" action="/admin/autofix">
      <label>Otomatik düzeltme eylemi:</label>
      <select name="action"><option value="recreate_db">DB Yeniden Oluştur</option><option value="create_upload">Upload Klasörü Oluştur</option></select>
      <button class="btn" type="submit">Uygula (onaylı)</button>
    </form>
  </div>
</div>
"""

ABOUT_HTML = """
<div class="card">
  <h3>Hakkında</h3>
  <p>KralZeka — Yapay zeka asistanı.</p>
  <p><strong>Seni kim kurdu/yarattı:</strong> Enes</p>
  <p>Versiyon: v2 (Full)</p>
  <p>Not: Model (chat): Groq ({{ groq_model }}). Görsel: HuggingFace.</p>
</div>
"""

# ---------------- ROUTES ----------------
@app.before_request
def before():
    init_db()
    g.user = None
    if 'user_id' in session:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        reset_daily_if_needed(g.user)

@app.route("/about")
@login_required
def about():
    return render_template_string(ABOUT_HTML, groq_model=GROQ_MODEL)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        uname = request.form.get("username","").strip()
        pwd = request.form.get("password","")
        row = get_db().execute("SELECT * FROM users WHERE username = ?", (uname,)).fetchone()
        if not row or not check_password_hash(row['password_hash'], pwd):
            flash("Geçersiz kullanıcı veya şifre.", "danger")
            return redirect(url_for('login'))
        session['user_id'] = row['id']
        session['username'] = row['username']
        flash("Giriş başarılı.", "success")
        return redirect(url_for('index'))
    # simple login form
    return """
    <h2>Giriş</h2>
    <form method="post">
      <input name="username" placeholder="Kullanıcı"><br><br>
      <input name="password" type="password" placeholder="Şifre"><br><br>
      <button>Giriş</button>
    </form>
    <p>Hesabın yok mu? <a href="/register">Kayıt ol</a></p>
    """

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        uname = request.form.get("username","").strip()
        pwd = request.form.get("password","")
        pwd2 = request.form.get("password2","")
        if not uname or not pwd or pwd != pwd2:
            flash("Bilgiler hatalı veya şifreler eşleşmiyor.", "danger")
            return redirect(url_for('register'))
        try:
            get_db().execute("INSERT INTO users (username, password_hash, created_at, last_reset, image_used_today) VALUES (?,?,?,?,?)",
                             (uname, generate_password_hash(pwd), datetime.utcnow().isoformat(), date.today().isoformat(), 0))
            get_db().commit()
            flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Kayıt hatası: Kullanıcı adı zaten var.", "danger")
            return redirect(url_for('register'))
    return """
    <h2>Kayıt</h2>
    <form method="post">
      <input name="username" placeholder="Kullanıcı"><br><br>
      <input name="password" type="password" placeholder="Şifre"><br><br>
      <input name="password2" type="password" placeholder="Şifre tekrar"><br><br>
      <button>Kayıt ol</button>
    </form>
    <p>Zaten üye misin? <a href="/login">Giriş yap</a></p>
    """

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for('login'))

@app.route("/")
@login_required
def index():
    # load latest messages
    msgs = get_db().execute("SELECT * FROM messages ORDER BY id DESC LIMIT 40").fetchall()
    msgs = [dict(m) for m in msgs][::-1]
    return render_template_string(INDEX_HTML, username=session.get('username'), is_admin=bool(g.user['is_admin']), messages=msgs, groq_model=GROQ_MODEL)

# Chat API used by front-end
@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json() or {}
    prompt = data.get("prompt","").strip()
    mode = data.get("mode","chat")
    if not prompt:
        return jsonify({"ok": False, "error": "Boş prompt"}), 400
    # store user message
    add_message(session['user_id'], session['username'], 'user', prompt)
    # build system prompt by mode
    if mode == "homework":
        system = "Ödev yardımcısı: adım adım açıkla, örnek ver, kısa test ver. Türkçe."
    elif mode == "joke":
        system = "Kısa ve etik espriler yap. Türkçe."
    elif mode == "slides":
        system = "Sunum taslağı hazırla: başlıklar ve kısa maddeler."
    elif mode == "image":
        # generate image
        ok, res = hf_generate_image(prompt)
        if not ok:
            # fallback to web synth if possible
            return jsonify({"ok": False, "error": res})
        fn, path = save_image_bytes(res, prefix=session['username'])
        # record memory and usage
        add_memory(session['user_id'], session['username'], 'image', fn)
        # increment usage count
        db = get_db()
        db.execute("UPDATE users SET image_used_today = image_used_today + 1 WHERE id = ?", (session['user_id'],))
        db.commit()
        return jsonify({"ok": True, "type": "image", "url": url_for('uploaded_file', filename=fn)})
    else:
        system = "Türkçe, yardımcı ve kısa cevap ver."
    # call Groq
    ok, out = call_groq_chat(prompt, system=system)
    if not ok:
        # fallback: web-based synth
        fallback = synthesize_fallback(prompt)
        add_message(session['user_id'], "KralZeka", "assistant", fallback)
        return jsonify({"ok": True, "type":"text", "answer": fallback})
    # store assistant response
    add_message(session['user_id'], "KralZeka", "assistant", out)
    return jsonify({"ok": True, "type":"text", "answer": out})

def synthesize_fallback(query):
    # minimal web search + extract : keep short and safe
    try:
        r = requests.post("https://html.duckduckgo.com/html/", data={"q": query}, timeout=8)
        r.raise_for_status()
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "lxml")
        snippet = soup.select_one(".result__snippet")
        if snippet:
            return snippet.get_text(strip=True)
    except Exception:
        pass
    return "Bu konuda doğrudan güvenilir kaynak bulamadım; daha detaylı bir soru sorar mısın?"

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if 'file' not in request.files:
        flash("Dosya yok.", "danger")
        return redirect(url_for('index'))
    f = request.files['file']
    if f.filename == '':
        flash("Dosya adı boş.", "danger")
        return redirect(url_for('index'))
    ext = f.filename.rsplit('.',1)[-1].lower()
    if ext not in ALLOWED_EXT:
        flash("Geçersiz dosya türü.", "danger")
        return redirect(url_for('index'))
    fn = secure_filename(f"{session.get('username')}_{int(time.time())}_{f.filename}")
    path = os.path.join(app.config['UPLOAD_FOLDER'], fn)
    f.save(path)
    add_memory(session['user_id'], session['username'], 'uploaded_image', fn)
    flash("Yüklendi.", "success")
    return redirect(url_for('uploaded_file', filename=fn))

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Requests (feature suggestions)
@app.route("/requests", methods=["GET","POST"])
@login_required
def requests_page():
    if request.method == "POST":
        title = request.form.get("title","").strip()
        details = request.form.get("details","").strip()
        if title:
            add_request(session['user_id'], session['username'], title, details)
            flash("İstek gönderildi.", "success")
        return redirect(url_for('index'))
    # GET used by front-end to inject panel HTML
    reqs = get_db().execute("SELECT * FROM requests ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(REQUESTS_HTML, reqs=reqs)

# Admin panel (same page loaded into panelArea)
@app.route("/admin")
@admin_required
def admin_panel():
    users = get_db().execute("SELECT id, username, is_admin, created_at, image_used_today FROM users ORDER BY id DESC").fetchall()
    reqs = get_db().execute("SELECT * FROM requests ORDER BY id DESC LIMIT 50").fetchall()
    logs = get_db().execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 200").fetchall()
    return render_template_string(ADMIN_PANEL_HTML, users=users, reqs=reqs, logs=logs)

@app.route("/admin/make_admin/<int:uid>")
@admin_required
def admin_make_admin(uid):
    target = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not target:
        flash("Kullanıcı yok.", "danger")
        return redirect(url_for('admin_panel'))
    if target['username'] == 'enes':
        flash("Enes adminliği korunur.", "danger")
        log_admin(session.get('username'), 'attempt_demote_enes', target['username'])
        return redirect(url_for('admin_panel'))
    get_db().execute("UPDATE users SET is_admin = 1 WHERE id = ?", (uid,))
    get_db().commit()
    log_admin(session.get('username'), 'make_admin', target['username'])
    flash(f"{target['username']} artık admin.", "success")
    return redirect(url_for('admin_panel'))

@app.route("/admin/delete/<int:uid>")
@admin_required
def admin_delete(uid):
    target = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not target:
        flash("Kullanıcı yok.", "danger")
        return redirect(url_for('admin_panel'))
    if target['username'] == 'enes':
        log_admin(session.get('username'), 'attempt_delete_enes', target['username'])
        flash("Enes silinemez.", "danger")
        return redirect(url_for('admin_panel'))
    get_db().execute("DELETE FROM users WHERE id = ?", (uid,))
    get_db().commit()
    log_admin(session.get('username'), 'delete_user', target['username'])
    flash("Kullanıcı silindi.", "info")
    return redirect(url_for('admin_panel'))

@app.route("/admin/resolve/<int:reqid>")
@admin_required
def admin_resolve(reqid):
    get_db().execute("UPDATE requests SET status = 'done' WHERE id = ?", (reqid,))
    get_db().commit()
    flash("İstek kapandı.", "success")
    return redirect(url_for('admin_panel'))

@app.route("/admin/autofix", methods=["POST"])
@admin_required
def admin_autofix():
    action = request.form.get("action")
    ok, msg = perform_auto_fix(action)
    log_admin(session.get('username'), 'autofix', action, {"ok":ok, "msg":msg})
    flash(msg if ok else ("Hata: "+msg), "info" if ok else "danger")
    return redirect(url_for('admin_panel'))

@app.route("/api/health")
@login_required
def api_health():
    return jsonify({"issues": system_health_checks()})

# Image quality up (upscale)
@app.route("/api/quality_up", methods=["POST"])
@login_required
def api_quality_up():
    data = request.get_json() or {}
    filename = data.get("filename")
    if not filename:
        return jsonify({"ok": False, "error": "filename gerekir"}), 400
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": "dosya yok"}), 404
    user = g.user
    if not user['is_admin']:
        # check limit
        if user['image_used_today'] >= USER_DAILY_QUALITY_LIMIT:
            return jsonify({"ok": False, "error": "günlük limit dolu"}), 403
    # try HF upscaler (not implemented directly) -> fallback PIL
    with open(path, "rb") as f:
        img_bytes = f.read()
    ok, out = pil_upscale(img_bytes) if PIL_OK else (False, "Pillow yok")
    if not ok:
        return jsonify({"ok": False, "error": out}), 500
    new_fn, new_path = save_image_bytes(out, prefix="up")
    # increment usage
    if not user['is_admin']:
        get_db().execute("UPDATE users SET image_used_today = image_used_today + 1 WHERE id = ?", (user['id'],))
        get_db().commit()
    return jsonify({"ok": True, "url": url_for('uploaded_file', filename=new_fn)})

# health check simple route
@app.route("/health")
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()})

# ----------------- START -----------------
if __name__ == "__main__":
    print("KralZeka v2 starting...")
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
