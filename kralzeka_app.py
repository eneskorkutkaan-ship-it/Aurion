#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v2 — Full single-file Flask application
Features:
- User registration / login / admin (initial admin: enes / enes1357924680)
- Modes: Chat (Groq), Homework, Joke, Presentation, Image generation (HuggingFace), Requests
- Image upload, image generate (HF), image quality upscaling (HF or PIL fallback)
- Admin panel: manage users, toggle admin, increase limits, view requests, logs
- Auto-detect issues and propose fixes (admin-only auto-fix on confirmation)
- "About" shows created-by line: "Seni enes yarattı" (in Turkish)
- Uses SQLite DB (kralzeka.db)
- Only required env vars: GROQ_API_KEY, HF_API_KEY (both optional; system will fallback)
"""
import os
import re
import json
import time
import sqlite3
import traceback
from functools import wraps
from datetime import datetime, timedelta
from io import BytesIO

from flask import (
    Flask, g, render_template_string, request, redirect, url_for, session, jsonify,
    send_from_directory, flash
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

import requests
from bs4 import BeautifulSoup

# Optional imaging
try:
    from PIL import Image, ImageFilter, ImageFont, ImageDraw
    PIL_OK = True
except Exception:
    PIL_OK = False

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# -----------------------
# Config
# -----------------------
APP_SECRET = os.environ.get("APP_SECRET", "kralzeka_dev_secret_change_me")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")  # for chat (Groq)
HF_API_KEY = os.environ.get("HF_API_KEY")      # for images (Hugging Face)
DB_PATH = os.environ.get("KZ_DB", "kralzeka.db")
UPLOAD_FOLDER = os.environ.get("KZ_UPLOAD_FOLDER", "uploads")
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}
USER_DAILY_IMAGE_LIMIT = int(os.environ.get("KZ_USER_DAILY_LIMIT", "5"))
INITIAL_ADMIN = ("enes", "enes1357924680")
PORT = int(os.environ.get("PORT", 5000))

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024  # 30MB max upload

# -----------------------
# DB helpers
# -----------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

def close_db(e=None):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

@app.teardown_appcontext
def _close_db(e=None):
    close_db(e)

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        image_used_today INTEGER DEFAULT 0,
        image_limit INTEGER DEFAULT %d,
        last_reset DATE
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        role TEXT,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT,
        action TEXT,
        target TEXT,
        meta TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS config (
        k TEXT PRIMARY KEY,
        v TEXT
    );
    """ % USER_DAILY_IMAGE_LIMIT)
    db.commit()
    # ensure initial admin
    cur.execute("SELECT id FROM users WHERE username = ?", (INITIAL_ADMIN[0],))
    if not cur.fetchone():
        ph = generate_password_hash(INITIAL_ADMIN[1])
        cur.execute("INSERT INTO users (username, password_hash, is_admin, image_limit, last_reset) VALUES (?, ?, ?, ?, ?)",
                    (INITIAL_ADMIN[0], ph, 1, 9999, datetime.utcnow().date().isoformat()))
        db.commit()
    cur.close()

def user_by_username(u):
    return get_db().execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()

def user_by_id(uid):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def create_user(username, password):
    ph = generate_password_hash(password)
    db = get_db()
    try:
        db.execute("INSERT INTO users (username, password_hash, last_reset) VALUES (?, ?, ?)",
                   (username, ph, datetime.utcnow().date().isoformat()))
        db.commit()
        return True, None
    except Exception as e:
        return False, str(e)

def log_admin(actor, action, target=None, meta=None):
    get_db().execute("INSERT INTO admin_logs (actor, action, target, meta) VALUES (?, ?, ?, ?)",
                     (actor, action, target, json.dumps(meta, ensure_ascii=False) if meta else None))
    get_db().commit()

# -----------------------
# Auth decorators
# -----------------------
def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*a, **kw)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        user = user_by_id(session['user_id'])
        if not user or not user['is_admin']:
            flash("Yönetici yetkisi gerekli.")
            return redirect(url_for('index'))
        return f(*a, **kw)
    return wrapped

# -----------------------
# Utilities: reset daily image counters
# -----------------------
def reset_daily_counters_if_needed(user_row):
    today = datetime.utcnow().date()
    last = user_row['last_reset']
    if not last or last != today.isoformat():
        db = get_db()
        db.execute("UPDATE users SET image_used_today = 0, last_reset = ? WHERE id = ?", (today.isoformat(), user_row['id']))
        db.commit()

# -----------------------
# Internet search fallback (DuckDuckGo HTML)
# -----------------------
HEADERS = {"User-Agent":"Mozilla/5.0 (KralZeka/1.0)"}
def duckduckgo_search(query, max_results=5):
    try:
        r = requests.post("https://html.duckduckgo.com/html/", data={"q": query}, headers=HEADERS, timeout=12)
        r.raise_for_status()
    except Exception:
        return []
    soup = BeautifulSoup(r.text, "lxml")
    out = []
    for res in soup.select(".result")[:max_results]:
        a = res.select_one(".result__a")
        sn = res.select_one(".result__snippet")
        if a:
            out.append((a.get_text(strip=True), a.get('href'), sn.get_text(strip=True) if sn else ""))
    return out

def fetch_page_text(url, max_chars=12000):
    if not url or not url.startswith("http"):
        return ""
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        r.raise_for_status()
    except Exception:
        return ""
    soup = BeautifulSoup(r.text, "lxml")
    for tag in soup(["script","style","nav","header","footer","noscript","svg"]):
        tag.decompose()
    texts = []
    for p in soup.find_all(['p','li','h1','h2','h3']):
        t = p.get_text(" ", strip=True)
        if t:
            texts.append(t)
    text = " ".join(texts)
    return text[:max_chars]

def synthesize_from_web(query):
    hits = duckduckgo_search(query, max_results=5)
    urls = [h[1] for h in hits if h[1]]
    texts = []
    for u in urls:
        t = fetch_page_text(u)
        if t:
            texts.append(t)
    # pick sentences with overlap
    qtokens = [t for t in re.findall(r'\w+', query.lower()) if len(t) > 2]
    cand = []
    for t in texts:
        parts = re.split(r'(?<=[\.\?\!])\s+', t)
        for s in parts:
            if len(s) < 60: continue
            score = sum(1 for q in qtokens if q in s.lower())
            if score>0:
                cand.append((score, s))
    cand.sort(key=lambda x: x[0], reverse=True)
    if cand:
        ans = " ".join([s for _, s in cand[:4]])
        return ans[:1500]
    # fallback
    return "Bu konuda güvenilir bir kaynak bulamadım; daha spesifik sorar mısın?"

# -----------------------
# Groq chat call (for chat)
# -----------------------
def call_groq_chat(user_prompt, system_prompt=None):
    """
    Attempts to call Groq Chat completions endpoint using env key.
    If GROQ_API_KEY not provided, returns (False, msg)
    """
    if not GROQ_API_KEY:
        return False, "GROQ API anahtarı sunucuda tanımlı değil."
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    messages = []
    if system_prompt:
        messages.append({"role":"system","content":system_prompt})
    messages.append({"role":"user","content":user_prompt})
    body = {"model":"llama-3.1-8b-instant","messages":messages,"temperature":0.2,"max_tokens":800}
    try:
        r = requests.post(url, json=body, headers=headers, timeout=30)
        r.raise_for_status()
        jr = r.json()
        # extract typical structure
        if 'choices' in jr and jr['choices']:
            ch = jr['choices'][0]
            if isinstance(ch, dict):
                msg = ch.get('message', {}).get('content') or ch.get('text')
                return True, msg
        # fallback
        return True, str(jr)[:1500]
    except Exception as e:
        return False, str(e)

# -----------------------
# Hugging Face image generation & upscaler
# -----------------------
def hf_generate_image(prompt):
    if not HF_API_KEY:
        return False, "HF API key yok."
    # model configured in config table or default
    model = get_db().execute("SELECT v FROM config WHERE k='hf_image_model'").fetchone()
    model = model['v'] if model else "stabilityai/stable-diffusion-xl-base-1.0"
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    try:
        r = requests.post(url, headers=headers, json={"inputs": prompt}, timeout=60)
        r.raise_for_status()
        ct = r.headers.get("content-type","")
        if ct.startswith("image/"):
            return True, r.content
        # sometimes model returns json with images (base64) or with URL
        try:
            jr = r.json()
            # try find base64
            if isinstance(jr, dict) and 'generated_image' in jr:
                import base64
                b = base64.b64decode(jr['generated_image'])
                return True, b
            if isinstance(jr, list) and jr and 'generated_text' in jr[0]:
                return True, jr[0]['generated_text'].encode('utf-8')
            return False, json.dumps(jr)[:800]
        except Exception:
            return False, r.text[:800]
    except Exception as e:
        return False, str(e)

def pil_upscale_bytes(img_bytes):
    if not PIL_OK:
        return False, "Pillow yok."
    try:
        im = Image.open(BytesIO(img_bytes)).convert("RGB")
        w,h = im.size
        im2 = im.resize((w*2, h*2), Image.LANCZOS).filter(ImageFilter.SHARPEN)
        buf = BytesIO()
        im2.save(buf, format="JPEG", quality=90)
        return True, buf.getvalue()
    except Exception as e:
        return False, str(e)

def hf_upscale_image_bytes(img_bytes):
    if not HF_API_KEY:
        return False, "HF API key yok."
    # use a HF upscaler model if configured
    model = get_db().execute("SELECT v FROM config WHERE k='hf_upscaler_model'").fetchone()
    model = model['v'] if model else "fiduswriter/real-esrgan-animevideov3"
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    # send as files
    try:
        r = requests.post(url, headers=headers, files={"file": ("img.jpg", img_bytes)}, timeout=60)
        r.raise_for_status()
        ct = r.headers.get("content-type","")
        if ct.startswith("image/"):
            return True, r.content
        # json fallback
        try:
            jr = r.json()
            return False, json.dumps(jr)[:800]
        except:
            return False, r.text[:800]
    except Exception as e:
        return False, str(e)

# -----------------------
# Auto health check & fix suggestions
# -----------------------
def system_health_checks():
    issues = []
    # DB exists?
    try:
        db = get_db()
        db.execute("SELECT 1 FROM users LIMIT 1")
    except Exception as e:
        issues.append("DB erişim hatası: " + str(e))
    # Upload folder
    if not os.path.isdir(UPLOAD_FOLDER):
        issues.append("Upload klasörü eksik.")
    # Keys
    if not GROQ_API_KEY:
        issues.append("GROQ_API_KEY eksik (chat Groq çalışmaz).")
    if not HF_API_KEY:
        issues.append("HF_API_KEY eksik (görsel fonksiyonları sınırlı).")
    return issues

def perform_auto_fix(action):
    actor = session.get('username','<unknown>')
    try:
        if action == "recreate_db":
            init_db()
            log_admin(actor, "auto_fix", "recreate_db", {"ok":True})
            return True, "DB yeniden init edildi."
        if action == "create_upload":
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            log_admin(actor, "auto_fix", "create_upload", {"ok":True})
            return True, "Upload klasörü oluşturuldu."
        return False, "Bilinmeyen eylem."
    except Exception as e:
        return False, str(e)

# -----------------------
# Templates (single-file)
# -----------------------
# Keep templates relatively compact but functional.
INDEX_HTML = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>KralZeka</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body{background:#071018;color:#e6f7f1;font-family:Inter,Arial;}
.app{display:flex;height:100vh}
.sidebar{width:260px;background:#0b1b1b;padding:12px;box-sizing:border-box}
.main{flex:1;padding:18px;overflow:auto}
.mod{padding:10px;border-radius:8px;margin:6px 0;cursor:pointer;color:#c9eae3}
.mod.active{background:linear-gradient(90deg,#6c63ff,#4aa0ff);color:#fff}
.chatbox{background:#061a18;padding:12px;border-radius:10px;height:60vh;overflow:auto}
.inputrow{display:flex;margin-top:12px;gap:8px}
.inputrow input{flex:1;padding:10px;border-radius:8px;border:none;background:#072a29;color:#e6f7f4}
.btn-accent{background:#6c63ff;border:none;color:white;padding:10px 14px;border-radius:8px}
.small-muted{color:#9fbfb6;font-size:13px}
.card-slim{background:#071b19;padding:10px;border-radius:8px}
.footer-note{font-size:12px;color:#9fbfb6;margin-top:10px}
.upload-preview{max-width:140px;border-radius:8px;margin-top:8px}
</style>
</head><body>
<div class="app">
  <div class="sidebar">
    <h3>KralZeka 👑</h3>
    <div class="small-muted">Kullanıcı: <strong>{{ username }}</strong> {% if is_admin %}<span class="badge bg-warning text-dark">ADMIN</span>{% endif %}</div>
    <hr style="border-color:#072a29">
    <div style="font-weight:700;margin-top:8px">Modlar</div>
    <div id="mods">
      <div class="mod active" data-mode="chat" onclick="setMode('chat')">💬 Sohbet</div>
      <div class="mod" data-mode="homework" onclick="setMode('homework')">📘 Ödev Yardımı</div>
      <div class="mod" data-mode="joke" onclick="setMode('joke')">😂 Espri</div>
      <div class="mod" data-mode="slides" onclick="setMode('slides')">📊 Sunum</div>
      <div class="mod" data-mode="image" onclick="setMode('image')">🖼 Görsel</div>
    </div>
    <hr style="border-color:#072a29">
    <div style="margin-top:8px">
      <button class="btn btn-sm btn-secondary w-100" onclick="document.getElementById('fileInput').click()">＋ Görsel Yükle</button>
      <input id="fileInput" type="file" accept="image/*" style="display:none" onchange="uploadFile(event)">
      <div id="uploadPreview"></div>
    </div>
    <hr style="border-color:#072a29">
    <div>
      <a href="/requests" class="small-muted">📩 Yeni Güncelleme İstekleri</a><br>
      <a href="/about" class="small-muted">ℹ️ Hakkında</a><br>
      <a href="/logout" class="small-muted">Çıkış</a>
    </div>
  </div>

  <div class="main">
    <div class="d-flex justify-content-between mb-2">
      <div><strong id="modeLabel">Sohbet</strong></div>
      <div class="small-muted">Model (chat): {{ model_label }}</div>
    </div>

    <div class="card p-3 mb-3 chatbox" id="chatBox">
      {% for m in messages %}
        {% if m['role']=='user' %}
          <div style="text-align:right"><div class="card-slim d-inline-block" style="max-width:80%"><strong>Sen:</strong><div>{{ m['content'] }}</div><div class="small-muted">{{ m['created_at'] }}</div></div></div>
        {% else %}
          <div style="text-align:left"><div class="card-slim d-inline-block" style="max-width:80%"><strong>KralZeka:</strong><div>{{ m['content'] }}</div><div class="small-muted">{{ m['created_at'] }}</div></div></div>
        {% endif %}
      {% endfor %}
    </div>

    <div class="inputrow">
      <input id="userInput" placeholder="KralZeka'ya sor..." autocomplete="off">
      <button class="btn-accent" onclick="sendMessage()">Gönder</button>
    </div>

    <div class="mt-3" id="autoFixArea"></div>
  </div>
</div>

<script>
let curMode = "chat";
function setMode(m){
  curMode = m;
  document.getElementById('modeLabel').innerText = ({chat:'Sohbet',homework:'Ödev',joke:'Espri',slides:'Sunum',image:'Görsel'}[m]||m);
}
async function sendMessage(){
  const input = document.getElementById('userInput');
  const text = input.value.trim();
  if(!text) return;
  input.value = '';
  const res = await fetch('/api/chat', {method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({prompt:text, mode:curMode})});
  const j = await res.json();
  if(j.ok){
    location.reload();
  } else {
    alert('Hata: ' + (j.error||'Bilinmeyen'));
  }
}
async function uploadFile(e){
  const f = e.target.files[0];
  if(!f) return;
  const fd = new FormData();
  fd.append('file', f);
  const res = await fetch('/api/upload', {method:'POST', body: fd});
  const j = await res.json();
  if(j.ok){
    document.getElementById('uploadPreview').innerHTML = `<img src="${j.url}" class="upload-preview">`;
    location.reload();
  } else {
    alert('Yükleme hatası: ' + (j.error||'hata'));
  }
}
// on load, check system health
window.addEventListener('load', async ()=>{
  const r = await fetch('/api/health');
  const j = await r.json();
  if(j.issues && j.issues.length>0){
    const area = document.getElementById('autoFixArea');
    let html = '<div class="card p-2" style="background:#2b1b1a;color:#ffd;">';
    html += '<strong>Sistem bir sorun tespit etti:</strong><ul>';
    j.issues.forEach(i => html += '<li>'+i+'</li>');
    html += '</ul>';
    html += '<div>Onay verirsen KralZeka otomatik düzeltme uygulayabilir (admin onayı gerekir).</div>';
    html += '<button class="btn btn-sm btn-accent" onclick="autoFix()">Düzelt</button> ';
    html += '<button class="btn btn-sm btn-secondary" onclick="dismissFix()">Kapat</button>';
    html += '</div>';
    area.innerHTML = html;
  }
});
async function autoFix(){
  if(!confirm("Otomatik düzeltme çalıştırılsın mı? (admin girişi gerekir)")) return;
  const res = await fetch('/api/auto_fix', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({action:'recreate_db'})});
  const j = await res.json();
  alert(j.msg||'Tamam');
  location.reload();
}
function dismissFix(){ document.getElementById('autoFixArea').innerHTML=''; }
</script>
</body></html>
"""

ABOUT_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Hakkında — KralZeka</title></head><body style="background:#071018;color:#e6f7f1;font-family:Inter,Arial;padding:20px">
<h2>KralZeka — Hakkında</h2>
<p>Bu yapay zeka asistanı <strong>Enes</strong> tarafından oluşturulmuştur. (Seni Enes yarattı.)</p>
<ul>
<li>Versiyon: KralZeka v2 (Full)</li>
<li>Geliştirici: Enes</li>
<li>Model (chat): Groq (env: GROQ_API_KEY)</li>
<li>Görsel: Hugging Face (env: HF_API_KEY)</li>
</ul>
<p><a href="/">Geri</a></p>
</body></html>
"""

REQUESTS_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Özellik İstekleri</title></head><body style="background:#071018;color:#e6f7f1;font-family:Inter,Arial;padding:20px">
<h2>Yeni Güncelleme İstekleri</h2>
<form method="post" action="/requests">
  <input name="title" placeholder="Başlık" style="width:60%;padding:8px"><br><br>
  <textarea name="description" placeholder="İstek detayları" style="width:80%;height:120px;padding:8px"></textarea><br>
  <button type="submit">Gönder</button>
</form>
<hr>
<h3>Son İstekler</h3>
<ul>
{% for r in reqs %}
  <li><strong>{{ r['title'] }}</strong> — {{ r['username'] }} — {{ r['created_at'] }} — ({{ r['status'] }})</li>
{% endfor %}
</ul>
<p><a href="/">Geri</a></p>
</body></html>
"""

ADMIN_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Admin Panel</title></head><body style="background:#071018;color:#e6f7f1;font-family:Inter,Arial;padding:20px">
<h2>Admin Panel</h2>
<p>Hoşgeldin, <strong>{{ admin_name }}</strong></p>

<h3>Kullanıcılar</h3>
<table border=0 cellpadding=6 style="background:#0b1b1b;padding:8px">
<tr><th>id</th><th>username</th><th>is_admin</th><th>image_used_today</th><th>image_limit</th><th>actions</th></tr>
{% for u in users %}
<tr>
<td>{{ u['id'] }}</td>
<td>{{ u['username'] }}</td>
<td>{{ u['is_admin'] }}</td>
<td>{{ u['image_used_today'] }}</td>
<td>{{ u['image_limit'] }}</td>
<td>
{% if u['username'] != 'enes' %}
  <a href="/admin/toggle_admin/{{u['id']}}">Toggle Admin</a> |
  <a href="/admin/delete/{{u['id']}}">Delete</a> |
  <a href="/admin/set_limit/{{u['id']}}?n=9999">Limit Sınırsız</a>
{% else %}
  <em>Korunan</em>
{% endif %}
</td>
</tr>
{% endfor %}
</table>

<h3>İstekler</h3>
<ul>
{% for r in reqs %}
  <li>{{ r['id'] }} - <strong>{{ r['title'] }}</strong> by {{ r['username'] }} — {{ r['created_at'] }} — {{ r['status'] }} 
      {% if r['status']!='done' %} - <a href="/admin/resolve/{{ r['id'] }}">Tamamlandı</a> {% endif %}
  </li>
{% endfor %}
</ul>

<h3>Admin Log</h3>
<ul>
{% for l in logs %}
  <li>{{ l['created_at'] }} — {{ l['actor'] }} — {{ l['action'] }} — {{ l['target'] }} — {{ l['meta'] }}</li>
{% endfor %}
</ul>

<p><a href="/">Geri</a></p>
</body></html>
"""

# -----------------------
# Routes
# -----------------------
@app.before_request
def ensure_db_and_reset_counters():
    init_db()
    # if logged-in, reset daily counters if day changed
    if 'user_id' in session:
        user = user_by_id(session['user_id'])
        if user:
            reset_daily_counters_if_needed(user)

@app.route("/about")
@login_required
def about():
    return render_template_string(ABOUT_HTML)

@app.route("/requests", methods=["GET","POST"])
@login_required
def requests_page():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title","").strip()
        desc = request.form.get("description","").strip()
        if title:
            db.execute("INSERT INTO requests (user_id, username, title, description) VALUES (?, ?, ?, ?)",
                       (session['user_id'], session.get('username'), title, desc))
            db.commit()
            flash("İstek kaydedildi.")
        return redirect(url_for('requests_page'))
    reqs = db.execute("SELECT * FROM requests ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(REQUESTS_HTML, reqs=reqs)

@app.route("/")
@login_required
def index():
    db = get_db()
    # show last 20 messages
    msgs = db.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 40").fetchall()
    msgs = [dict(m) for m in msgs][::-1]
    model_label = "Groq (chat) — env:GROQ_API_KEY" if GROQ_API_KEY else "Web fallback (no GROQ key)"
    return render_template_string(INDEX_HTML, username=session.get('username'), is_admin=bool(session.get('is_admin')),
                                  messages=msgs, model_label=model_label)

# auth routes
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        if not u or not p:
            flash("Eksik bilgi.")
            return redirect(url_for('register'))
        ok, err = create_user(u, p)
        if not ok:
            flash("Kayıt hatası: " + str(err))
            return redirect(url_for('register'))
        flash("Kayıt başarılı, giriş yapabilirsiniz.")
        return redirect(url_for('login'))
    # simple form
    return """
    <h3>Kayıt Ol</h3>
    <form method="post">
      <input name="username" placeholder="Kullanıcı"><br><br>
      <input name="password" type="password" placeholder="Şifre"><br><br>
      <button>Kayıt</button>
    </form>
    """

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        row = user_by_username(u)
        if not row or not check_password_hash(row['password_hash'], p):
            flash("Geçersiz kullanıcı veya şifre.")
            return redirect(url_for('login'))
        session['user_id'] = row['id']
        session['username'] = row['username']
        session['is_admin'] = bool(row['is_admin'])
        flash("Giriş başarılı.")
        return redirect(url_for('index'))
    return """
    <h3>Giriş</h3>
    <form method="post">
      <input name="username" placeholder="Kullanıcı"><br><br>
      <input name="password" type="password" placeholder="Şifre"><br><br>
      <button>Giriş</button>
    </form>
    """

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.")
    return redirect(url_for('login'))

# admin panel
@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    reqs = db.execute("SELECT * FROM requests ORDER BY id DESC LIMIT 50").fetchall()
    logs = db.execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 200").fetchall()
    return render_template_string(ADMIN_HTML, admin_name=session.get('username'), users=users, reqs=reqs, logs=logs)

@app.route("/admin/toggle_admin/<int:uid>")
@admin_required
def admin_toggle(uid):
    target = user_by_id(uid)
    if not target:
        flash("Kullanıcı yok.")
        return redirect(url_for('admin_panel'))
    if target['username'] == INITIAL_ADMIN[0]:
        # log attempt
        log_admin(session.get('username'), 'attempt_demote_enes', target['username'])
        flash("Enes admin olarak korunur.")
        return redirect(url_for('admin_panel'))
    new = 0 if target['is_admin'] else 1
    get_db().execute("UPDATE users SET is_admin = ? WHERE id = ?", (new, uid))
    get_db().commit()
    log_admin(session.get('username'), 'toggle_admin', target['username'], {"new":new})
    return redirect(url_for('admin_panel'))

@app.route("/admin/delete/<int:uid>")
@admin_required
def admin_delete(uid):
    target = user_by_id(uid)
    if not target:
        flash("Kullanıcı yok.")
        return redirect(url_for('admin_panel'))
    if target['username'] == INITIAL_ADMIN[0]:
        log_admin(session.get('username'), 'attempt_delete_enes', target['username'])
        flash("Enes silinemez.")
        return redirect(url_for('admin_panel'))
    get_db().execute("DELETE FROM users WHERE id = ?", (uid,))
    get_db().commit()
    log_admin(session.get('username'), 'delete_user', target['username'])
    flash("Silindi.")
    return redirect(url_for('admin_panel'))

@app.route("/admin/set_limit/<int:uid>")
@admin_required
def admin_set_limit(uid):
    n = int(request.args.get('n', USER_DAILY_IMAGE_LIMIT))
    target = user_by_id(uid)
    if not target:
        flash("Kullanıcı yok.")
        return redirect(url_for('admin_panel'))
    get_db().execute("UPDATE users SET image_limit = ? WHERE id = ?", (n, uid))
    get_db().commit()
    flash("Limit güncellendi.")
    return redirect(url_for('admin_panel'))

@app.route("/admin/resolve/<int:rid>")
@admin_required
def admin_resolve(rid):
    get_db().execute("UPDATE requests SET status = 'done' WHERE id = ?", (rid,))
    get_db().commit()
    flash("İşaretlendi.")
    return redirect(url_for('admin_panel'))

# upload route
@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "Dosya yok"})
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"ok": False, "error": "Dosya adı yok"})
    fn = secure_filename(f.filename)
    ext = fn.rsplit(".",1)[-1].lower()
    if ext not in ALLOWED_IMAGE_EXT:
        return jsonify({"ok": False, "error": "Geçersiz uzantı"})
    t = int(time.time())
    save_name = f"{session.get('username')}_{t}_{fn}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], save_name)
    f.save(path)
    # log request
    get_db().execute("INSERT INTO requests (user_id, username, title, description, status) VALUES (?, ?, ?, ?, ?)",
                     (session.get('user_id'), session.get('username'), 'upload', save_name, 'done'))
    get_db().commit()
    return jsonify({"ok": True, "url": url_for('uploaded_file', filename=save_name)})

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# chat api
@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json() or {}
    prompt = data.get('prompt','').strip()
    mode = data.get('mode','chat')
    if not prompt:
        return jsonify({"ok": False, "error": "Boş prompt"}), 400
    # build system prompt by mode
    if mode == "homework":
        system = "Sen bir öğretmensin; açıklayıcı, adım adım çözüm ver; Türkçe."
    elif mode == "joke":
        system = "Kısa, etik espriler üret; Türkçe."
    elif mode == "slides":
        system = "Sunum taslağı üret: başlıklar ve kısa maddeler."
    else:
        system = "Türkçe, faydalı ve kısa cevap ver."
    # Try Groq
    ok, res = call_groq_chat(prompt if mode=='chat' else f"[{mode.upper()}] {prompt}", system_prompt=system)
    answer = None
    if ok and res:
        answer = res
    else:
        # fallback to web synth
        answer = synthesize_from_web(prompt)
    # store messages
    db = get_db()
    db.execute("INSERT INTO messages (user_id, username, role, content) VALUES (?, ?, ?, ?)",
               (session.get('user_id'), session.get('username'), "user", prompt))
    db.execute("INSERT INTO messages (user_id, username, role, content) VALUES (?, ?, ?, ?)",
               (session.get('user_id'), session.get('username'), "assistant", answer))
    db.commit()
    # log request
    get_db().execute("INSERT INTO requests (user_id, username, title, description, status) VALUES (?, ?, ?, ?, ?)",
                     (session.get('user_id'), session.get('username'), 'chat', prompt, 'done'))
    get_db().commit()
    return jsonify({"ok": True, "answer": answer})

# image endpoints
@app.route("/api/generate_image", methods=["POST"])
@login_required
def api_generate_image():
    data = request.get_json() or {}
    prompt = data.get('prompt','').strip()
    if not prompt:
        return jsonify({"ok": False, "error": "Prompt boş"}), 400
    user = user_by_id(session['user_id'])
    reset_daily_counters_if_needed(user)
    # check limit
    if not user['is_admin'] and user['image_used_today'] >= user['image_limit']:
        return jsonify({"ok": False, "error": "Günlük görsel kotanız doldu."}), 403
    ok, result = hf_generate_image(prompt)
    if not ok:
        # return fallback message and log
        get_db().execute("INSERT INTO requests (user_id, username, title, description, status) VALUES (?, ?, ?, ?, ?)",
                         (session.get('user_id'), session.get('username'), 'image_error', result, 'error'))
        get_db().commit()
        return jsonify({"ok": False, "error": result}), 500
    # save bytes to file
    ext = "png"
    t = int(time.time())
    filename = f"{session.get('username')}_{t}_gen.{ext}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(path, "wb") as f:
        f.write(result)
    # update user usage
    get_db().execute("UPDATE users SET image_used_today = image_used_today + 1 WHERE id = ?", (user['id'],))
    get_db().commit()
    # log
    get_db().execute("INSERT INTO requests (user_id, username, title, description, status) VALUES (?, ?, ?, ?, ?)",
                     (user['id'], session.get('username'), 'image', prompt, 'done'))
    get_db().commit()
    return jsonify({"ok": True, "url": url_for('uploaded_file', filename=filename)})

@app.route("/api/quality_up", methods=["POST"])
@login_required
def api_quality_up():
    data = request.get_json() or {}
    filename = data.get('filename')
    if not filename:
        return jsonify({"ok": False, "error": "filename gerekli"}), 400
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": "Dosya bulunamadı"}), 404
    with open(path, "rb") as f:
        img_bytes = f.read()
    # try HF upscaler first
    ok, out = hf_upscale_image_bytes(img_bytes)
    if not ok:
        # fallback to PIL upscaler
        ok2, out2 = pil_upscale_bytes(img_bytes)
        if not ok2:
            return jsonify({"ok": False, "error": "Upscale başarısız: "+str(out)}), 500
        # save out2
        t = int(time.time())
        newname = f"q_{t}_{filename}"
        with open(os.path.join(app.config['UPLOAD_FOLDER'], newname), "wb") as f2:
            f2.write(out2)
        return jsonify({"ok": True, "url": url_for('uploaded_file', filename=newname)})
    else:
        t = int(time.time())
        newname = f"q_{t}_{filename}"
        with open(os.path.join(app.config['UPLOAD_FOLDER'], newname), "wb") as f2:
            f2.write(out)
        return jsonify({"ok": True, "url": url_for('uploaded_file', filename=newname)})

# health and auto-fix endpoints
@app.route("/api/health")
@login_required
def api_health():
    issues = system_health_checks()
    return jsonify({"issues": issues})

@app.route("/api/auto_fix", methods=["POST"])
@login_required
def api_auto_fix():
    data = request.get_json() or {}
    action = data.get('action')
    # only admin can run fixes
    user = user_by_id(session['user_id'])
    if not user['is_admin']:
        return jsonify({"ok": False, "error": "Yönetici yetkisi gerekli."}), 403
    ok, msg = perform_auto_fix(action)
    return jsonify({"ok": ok, "msg": msg})

# simple logs / admin logs endpoint (admin)
@app.route("/api/admin_logs")
@admin_required
def api_admin_logs():
    logs = get_db().execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify([dict(l) for l in logs])

# start
if __name__ == "__main__":
    print("KralZeka v2 starting...")
    init_db()
    # set default HF models if not set
    db = get_db()
    cur = db.execute("SELECT v FROM config WHERE k = 'hf_image_model'").fetchone()
    if not cur:
        db.execute("INSERT OR REPLACE INTO config (k,v) VALUES (?,?)", ("hf_image_model", "stabilityai/stable-diffusion-xl-base-1.0"))
    cur2 = db.execute("SELECT v FROM config WHERE k = 'hf_upscaler_model'").fetchone()
    if not cur2:
        db.execute("INSERT OR REPLACE INTO config (k,v) VALUES (?,?)", ("hf_upscaler_model", "fiduswriter/real-esrgan-animevideov3"))
    db.commit()
    app.run(host="0.0.0.0", port=PORT, debug=True)
