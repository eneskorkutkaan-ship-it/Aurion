#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sqlite3
import json
from datetime import datetime
from flask import Flask, g, request, render_template_string, redirect, url_for, session, flash, abort
import requests
from bs4 import BeautifulSoup

# --- TEMEL AYARLAR ---
DB_PATH = 'kralzeka.db'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 🔐 Sadece bu environment’tan gelecek
GROQ_KEY = os.getenv("GROQ_API_KEY")

# Diğerleri sabit:
GROQ_MODEL = "llama-3.3-70b-versatile"
SECRET_KEY = "kralzeka_sabit_secret_2025"
HEADERS = {"User-Agent": "Mozilla/5.0 (KralZeka/1.0)"}

# --- Flask başlat ---
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Veritabanı işlemleri ---
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    c = db.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        role TEXT,
        content TEXT,
        created_at TEXT
    );
    """)
    db.commit()
    # İlk admin
    c.execute("SELECT id FROM users WHERE username=?", ("enes",))
    if not c.fetchone():
        c.execute("INSERT INTO users (username,password,is_admin,created_at) VALUES (?,?,?,?)",
                  ("enes","enes1357924680",1,datetime.utcnow().isoformat()))
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# --- Basit kimlik doğrulama ---
def auth_user(username, password):
    row = get_db().execute("SELECT * FROM users WHERE username=? AND password=?", (username, password)).fetchone()
    return row

def current_user():
    uid = session.get("user_id")
    if uid:
        return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return None

# --- Web arama fallback ---
def duckduckgo_search(query):
    try:
        url = "https://html.duckduckgo.com/html/"
        r = requests.post(url, data={"q": query}, headers=HEADERS, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        links = []
        for a in soup.select(".result__a")[:3]:
            links.append(a.get_text(strip=True))
        return " ".join(links)
    except Exception:
        return "Arama yapılırken hata oluştu."

# --- Groq API çağrısı ---
def call_groq(prompt):
    if not GROQ_KEY:
        return "Hata: GROQ_API_KEY ekli değil!"
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {GROQ_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": GROQ_MODEL,
            "messages": [
                {"role": "system", "content": "Sen KralZeka adında bir asistansın, Türkçe konuş."},
                {"role": "user", "content": prompt}
            ]
        }
        r = requests.post(url, headers=headers, json=data, timeout=30)
        res = r.json()
        if "choices" in res:
            return res["choices"][0]["message"]["content"]
        else:
            return f"Hata: {res}"
    except Exception as e:
        return f"Bağlantı hatası: {e}"

# --- Arayüz HTML ---
TEMPLATE = """
<!doctype html><html><head><meta charset="utf-8">
<title>KralZeka</title>
<style>
body{background:#021412;color:#cdece0;font-family:Arial;padding:25px}
.container{max-width:800px;margin:auto}
.box{background:#042620;padding:16px;border-radius:8px;margin-bottom:10px}
input[type=text]{width:75%;padding:10px;border-radius:5px;border:1px solid #0a2}
button{padding:10px 14px;background:#0b6d3f;color:white;border:none;border-radius:5px}
.msg-user{background:#06372f;padding:10px;border-radius:6px;margin:5px 0}
.msg-bot{background:#00342b;padding:10px;border-radius:6px;margin:5px 0}
</style></head><body>
<div class="container">
<h2>Merhaba, {{user['username']}} {% if user['is_admin'] %}<span style="color:gold">[ADMIN]</span>{% endif %}</h2>
<p><a href="{{url_for('logout')}}">Çıkış yap</a></p>
<div class="box">
<form method="post" action="{{url_for('send')}}">
  <input name="message" placeholder="Bir şey yaz..." required>
  <button type="submit">Gönder</button>
</form>
</div>

{% for m in msgs %}
  {% if m['role']=='user' %}
    <div class="msg-user"><b>Sen:</b> {{m['content']}}</div>
  {% else %}
    <div class="msg-bot"><b>KralZeka:</b> {{m['content']}}</div>
  {% endif %}
{% endfor %}
</div></body></html>
"""

# --- Routes ---
@app.route("/")
def index():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    msgs = db.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 15").fetchall()
    return render_template_string(TEMPLATE, user=user, msgs=msgs[::-1])

@app.route("/send", methods=["POST"])
def send():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    text = request.form["message"]
    db = get_db()
    db.execute("INSERT INTO messages (user_id,username,role,content,created_at) VALUES (?,?,?,?,?)",
               (user["id"],user["username"],"user",text,datetime.utcnow().isoformat()))
    db.commit()
    reply = call_groq(text)
    if "Hata" in reply or "Bağlantı" in reply:
        reply = "Groq hatası oldu, web araması yapılıyor... " + duckduckgo_search(text)
    db.execute("INSERT INTO messages (user_id,username,role,content,created_at) VALUES (?,?,?,?,?)",
               (None,"KralZeka","bot",reply,datetime.utcnow().isoformat()))
    db.commit()
    return redirect(url_for("index"))

LOGIN = """
<!doctype html><html><head><meta charset="utf-8"><title>Giriş</title></head>
<body style="background:#031912;color:#cdf5e8;padding:30px">
<div style="max-width:400px;margin:auto">
<h2>KralZeka Giriş</h2>
<form method="post">
<input name="username" placeholder="Kullanıcı adı"><br><br>
<input name="password" placeholder="Şifre"><br><br>
<button>Giriş Yap</button>
</form>
<p>{{msg}}</p>
</div></body></html>
"""

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN, msg="")
    u = request.form["username"]
    p = request.form["password"]
    user = auth_user(u,p)
    if user:
        session["user_id"] = user["id"]
        return redirect(url_for("index"))
    else:
        return render_template_string(LOGIN, msg="Hatalı giriş!")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- Uygulama başlat ---
if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
