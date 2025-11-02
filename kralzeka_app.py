#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka v1 - Tek dosya, tam sürüm
- SQLite backend
- HF + (opsiyonel) GROQ
- Templates: templates/*.html (base, index, login, register, admin.html, gorsel.html, sunum.html, 404,500,...)
- Start with gunicorn: gunicorn kralzeka_app:app
"""

import os
import sqlite3
import json
import uuid
import functools
import logging
import base64
from io import BytesIO
from datetime import datetime
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    g, jsonify, send_file, abort, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from PIL import Image

# ---------- CONFIG ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("KRALZEKA_DB", os.path.join(BASE_DIR, "kralzeka.db"))

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
HF_API_KEY = os.environ.get("HF_API_KEY", "").strip()
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", os.environ.get("SECRET_KEY", "")) or str(uuid.uuid4())

# Models defaults (can be left as-is)
DEFAULT_GROQ_MODEL = "llama-3.1-70b"
DEFAULT_HF_TEXT_MODEL = "meta-llama/Llama-2-7b-chat-hf"
DEFAULT_HF_IMAGE_MODEL = "stabilityai/stable-diffusion-xl"

IMAGE_DAILY_LIMIT = 5
ADMIN_USERNAME = "enes"
ADMIN_PASSWORD = "enes1357924680"

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kralzeka")

# ---------- FLASK ----------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------- DB HELPERS ----------
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
    CREATE TABLE IF NOT EXISTS feature_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        text TEXT,
        tag TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)
    db.commit()
    # initial admin
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
def close_db(exception):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()
        g._db = None

# ---------- UTIL ----------
def log_event(level: str, message: str, meta: Optional[dict] = None):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO logs (level, message, meta) VALUES (?, ?, ?)",
                    (level, message, json.dumps(meta or {})))
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

def require_login(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
        if not user:
            session.clear()
            return redirect(url_for("login"))
        g.user = user
        return fn(*args, **kwargs)
    return wrapper

def require_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
        if not user or not user["is_admin"]:
            return render_template("403.html"), 403
        g.user = user
        return fn(*args, **kwargs)
    return wrapper

def protected_admin_modify(target_username: str, acting_admin: str):
    if target_username == ADMIN_USERNAME:
        log_event("WARN", f"Admin değişikliği denemesi: {acting_admin} -> {target_username}",
                  {"actor": acting_admin, "target": target_username})
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

def ai_chat(prompt: str) -> str:
    try:
        if GROQ_API_KEY:
            try:
                out = call_groq_chat(prompt)
                if out:
                    return out
            except Exception:
                logger.warning("Groq çağrısı başarısız, HF'e düşülüyor.")
        if HF_API_KEY:
            return call_hf_text(prompt)
        raise RuntimeError("Hiçbir model erişilebilir değil (GROQ/HF anahtarları yok).")
    except Exception as e:
        logger.exception("ai_chat exception")
        return f"KralZeka Hata: {str(e)}"

# ---------- IMAGE (HF) ----------
def generate_image_hf(prompt: str, model: str = DEFAULT_HF_IMAGE_MODEL, size: str = "1024x1024"):
    if not HF_API_KEY:
        raise RuntimeError("HF key yok")
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
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

# ---------- IMAGE USAGE ----------
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

# ---------- ROUTES ----------
@app.route("/", methods=["GET"])
def index():
    user = None
    if "user_id" in session:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 20")
    msgs = cur.fetchall()
    return render_template("index.html", user=user, messages=msgs, image_limit=IMAGE_DAILY_LIMIT)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "") or request.form.get("password")
        if not username or not password:
            return render_template("register.html", error="Alanları doldurun")
        if password != password2:
            return render_template("register.html", error="Parolalar eşleşmiyor")
        if get_user_by_username(username):
            return render_template("register.html", error="Kullanıcı adı alınmış")
        uid = create_user(username, password, 0)
        if not uid:
            return render_template("register.html", error="Kayıt başarısız")
        log_event("INFO", f"Kayıt: {username}")
        session["user_id"] = uid
        return redirect(url_for("index"))
    return render_template("register.html", error=None)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user_by_username(username)
        if not user or not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Kullanıcı adı veya şifre hatalı")
        session["user_id"] = user["id"]
        log_event("INFO", f"Giriş: {username}")
        return redirect(url_for("index"))
    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/chat", methods=["POST"])
@require_login
def chat():
    prompt = request.form.get("prompt", "").strip()
    if not prompt:
        return redirect(url_for("index"))
    user = g.user
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)",
                (user["id"], user["username"], prompt))
    db.commit()
    try:
        response_text = ai_chat(prompt)
    except Exception as e:
        response_text = f"Hata: {str(e)}"
    cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)",
                (user["id"], "KralZeka", response_text))
    db.commit()
    return redirect(url_for("index"))

@app.route("/feature_request", methods=["POST"])
@require_login
def feature_request():
    txt = request.form.get("request_text", "").strip()
    tag = request.form.get("tag", "").strip()
    if txt:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO feature_requests (user_id, text, tag) VALUES (?, ?, ?)", (g.user["id"], txt, tag))
        db.commit()
        log_event("FEATURE", txt, {"tag": tag, "user": g.user["username"]})
    return redirect(url_for("index"))

# ---------- ADMIN ----------
@app.route("/admin", methods=["GET"])
@require_admin
def admin_panel():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.execute("SELECT level, message, meta, created_at FROM logs ORDER BY id DESC LIMIT 100")
    logs = cur.fetchall()
    cur.execute("SELECT id, text, tag, created_at FROM feature_requests ORDER BY id DESC LIMIT 200")
    requests_ = cur.fetchall()
    return render_template("admin.html", users=users, logs=logs, requests=requests_, admin_username=ADMIN_USERNAME, user=g.user)

@app.route("/admin/make_admin/<int:user_id>", methods=["POST","GET"])
@require_admin
def make_admin(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return "Kullanıcı yok", 404
    target = row["username"]
    if not protected_admin_modify(target, g.user["username"]):
        return f"{ADMIN_USERNAME} üzerinde değişiklik yapamazsın.", 403
    cur.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{g.user['username']} -> {target} admin yapıldı")
    return redirect(url_for("admin_panel"))

@app.route("/admin/revoke_admin/<int:user_id>", methods=["POST","GET"])
@require_admin
def revoke_admin(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return "Kullanıcı yok", 404
    target = row["username"]
    if not protected_admin_modify(target, g.user["username"]):
        return f"{ADMIN_USERNAME} üzerinde değişiklik yapamazsın.", 403
    cur.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{g.user['username']} -> {target} adminlığı kaldırdı")
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST","GET"])
@require_admin
def delete_user(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    r = cur.fetchone()
    if not r:
        return "Kullanıcı yok", 404
    target = r["username"]
    if not protected_admin_modify(target, g.user["username"]):
        return f"{ADMIN_USERNAME} üzerinde değişiklik yapamazsın.", 403
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    log_event("ADMIN", f"{g.user['username']} -> {target} silindi")
    return redirect(url_for("admin_panel"))

@app.route("/admin/code_tool", methods=["POST"])
@require_admin
def admin_code_tool():
    prompt = request.form.get("prompt", "").strip()
    if not prompt:
        return redirect(url_for("admin_panel"))
    try:
        ai_response = ai_chat(f"Admin kod üretme asistanı: {prompt}")
    except Exception as e:
        ai_response = f"Hata: {e}"
    log_event("CODE", ai_response, {"admin": g.user["username"], "prompt": prompt})
    return redirect(url_for("admin_panel"))

# ---------- IMAGE APIs ----------
@app.route("/api/generate_image", methods=["POST"])
@require_login
def api_generate_image():
    data = request.get_json() or {}
    prompt = data.get("prompt", "").strip()
    size = data.get("size", "1024x1024")
    if not prompt:
        return jsonify({"error": "prompt gerekli"}), 400
    user = g.user
    if not user["is_admin"]:
        used = get_image_usage_for_today(user["id"])
        if used >= IMAGE_DAILY_LIMIT:
            return jsonify({"error": f"Günlük limit aşıldı ({IMAGE_DAILY_LIMIT})"}), 403
    try:
        if GROQ_API_KEY:
            try:
                headers = {"Authorization": f"Bearer {GROQ_API_KEY}"}
                groq_url = "https://api.groq.com/v1/images/generations"
                payload = {"prompt": prompt, "size": size}
                r = requests.post(groq_url, headers=headers, json=payload, timeout=60)
                r.raise_for_status()
                jr = r.json()
                b64 = None
                if isinstance(jr, dict) and "data" in jr and jr["data"]:
                    b64 = jr["data"][0].get("b64_json")
                if b64:
                    image_bytes = base64.b64decode(b64)
                else:
                    raise RuntimeError("GROQ response unexpected")
            except Exception:
                logger.warning("GROQ image failed, falling back to HF")
                image_bytes = generate_image_hf(prompt, DEFAULT_HF_IMAGE_MODEL, size)
        else:
            image_bytes = generate_image_hf(prompt, DEFAULT_HF_IMAGE_MODEL, size)

        if not user["is_admin"]:
            increment_image_usage(user["id"], 1)

        b64 = base64.b64encode(image_bytes).decode("utf-8")
        db = get_db()
        cur = db.cursor()
        preview = f"data:image/png;base64,{b64[:180]}..."
        cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)",
                    (user["id"], "KralZeka (görsel)", preview))
        db.commit()
        return jsonify({"image_base64": b64}), 200
    except Exception as e:
        logger.exception("image generation error")
        return jsonify({"error": f"Görsel üretilemedi: {str(e)}"}), 500

@app.route("/api/upgrade_image", methods=["POST"])
@require_login
def api_upgrade_image():
    if "image" not in request.files:
        return jsonify({"error": "image file gerekli"}), 400
    file = request.files["image"]
    level = int(request.form.get("level", "2"))
    try:
        img = Image.open(file.stream).convert("RGBA")
        factor = max(1, min(level, 4))
        new_size = (img.width * factor, img.height * factor)
        up = img.resize(new_size, Image.LANCZOS)
        buff = BytesIO()
        up.save(buff, format="PNG")
        buff.seek(0)
        data = buff.read()
        b64 = base64.b64encode(data).decode("utf-8")
        db = get_db()
        cur = db.cursor()
        preview = f"data:image/png;base64,{b64[:180]}..."
        cur.execute("INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)",
                    (g.user["id"], "KralZeka (yükseltme)", preview))
        db.commit()
        return jsonify({"image_base64": b64}), 200
    except Exception as e:
        logger.exception("upgrade image error")
        return jsonify({"error": f"Yükseltme başarısız: {str(e)}"}), 500

# ---------- SUNUM ----------
@app.route("/sunum", methods=["GET"])
@require_login
def sunum_page():
    return render_template("sunum.html")

@app.route("/sunum_olustur", methods=["POST"])
@require_login
def sunum_olustur():
    konu = request.form.get("konu", "").strip()
    if not konu:
        return render_template("sunum.html", sunum="⚠️ Lütfen bir konu girin!")
    try:
        prompt = f"Konu: {konu}\nLütfen kısa ve anlaşılır başlıklar halinde bir sunum taslağı oluştur. Her slayt için kısa açıklama yaz."
        sunum_text = ai_chat(prompt)
    except Exception as e:
        sunum_text = f"⚠️ Sunum oluşturulamadı: {str(e)}"
    return render_template("sunum.html", sunum=sunum_text)

@app.route("/sunum_indir", methods=["POST"])
@require_login
def sunum_indir():
    icerik = request.form.get("icerik", "")
    if not icerik:
        return "İndirilecek içerik bulunamadı.", 400
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        import textwrap
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        wrapped = textwrap.wrap(icerik, 90)
        y = height - 50
        for line in wrapped:
            if y < 50:
                p.showPage()
                y = height - 50
            p.drawString(50, y, line)
            y -= 14
        p.save()
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name="KralZeka_Sunum.pdf", mimetype="application/pdf")
    except Exception:
        return (icerik, 200, {"Content-Type": "text/plain; charset=utf-8", "Content-Disposition": "attachment; filename=KralZeka_Sunum.txt"})

# ---------- ERROR HANDLERS ----------
@app.errorhandler(500)
def handle_500(e):
    try:
        log_event("ERROR", str(e), {"path": request.path})
    except Exception:
        logger.exception("log_event failed while handling 500")
    try:
        return render_template("500.html"), 500
    except Exception:
        return "Sunucu hatası (500)", 500

@app.errorhandler(404)
def handle_404(e):
    try:
        return render_template("404.html"), 404
    except Exception:
        return "Sayfa bulunamadı (404)", 404

@app.errorhandler(403)
def handle_403(e):
    try:
        return render_template("403.html"), 403
    except Exception:
        return "Erişim yasak (403)", 403

@app.errorhandler(401)
def handle_401(e):
    try:
        return render_template("401.html"), 401
    except Exception:
        return "Yetkisiz (401)", 401

# ---------- START ----------
def start_app():
    init_db()
    logger.info("KralZeka v1 starting...")
    if os.environ.get("FLASK_RUN_LOCAL", "").lower() in ("1", "true"):
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

if __name__ == "__main__":
    start_app()
# end of file
