#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KralZeka tek-dosya uygulama
- Kullanıcı kaydı / giriş
- Admin panel (enes ilk admin)
- Chat (Groq API ile, API key env değişkeninden alınır)
- Basit görsel yükleme (uploads/)
"""

import os
import traceback
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template_string, request, redirect, url_for,
    session, send_from_directory, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
import requests

# ----------------------------
# CONFIG
# ----------------------------
APP_SECRET = os.getenv("KRALEZKA_SECRET", "supersecretkey_change_me")
DB_PATH = os.getenv("KRALEZKA_DB", "sqlite:///kralzeka.db")
UPLOAD_FOLDER = os.getenv("KRALEZKA_UPLOADS", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
# Groq API: set in environment in Render / VPS
GROQ_API_KEY = os.getenv("GROQ_API_KEY", None)
# If you *must* hardcode (NOT RECOMMENDED), set below string (remove None)
# DEFAULT_KEY_FALLBACK = "gsk_your_key_here"   # <-- DON'T commit real key to repo
# if GROQ_API_KEY is None:
#     GROQ_API_KEY = DEFAULT_KEY_FALLBACK

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# ----------------------------
# APP INIT
# ----------------------------
app = Flask(__name__)
app.secret_key = APP_SECRET
app.config["SQLALCHEMY_DATABASE_URI"] = DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)

# ----------------------------
# MODELS
# ----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminAudit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(200), nullable=False)
    actor = db.Column(db.String(80), nullable=False)
    target = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ----------------------------
# UTIL
# ----------------------------
def init_db():
    with app.app_context():
        db.create_all()
        # create initial admin 'enes' if missing
        if not User.query.filter_by(username="enes").first():
            u = User(username="enes", password="enes1357924680", is_admin=True)
            db.session.add(u)
            db.session.commit()

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if "username" not in session:
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if "username" not in session:
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            abort(403)
        return fn(*a, **kw)
    return wrapper

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------------------
# GROQ API CALL
# ----------------------------
def ask_groq(prompt, model="llama-3.1-70b"):
    """
    Call Groq API (OpenAI compatible endpoint). Returns string reply or error message.
    - Expects GROQ_API_KEY set as env var.
    """
    if not GROQ_API_KEY:
        return "Uyarı: Sistem yöneticisi API anahtarını ayarlamamış. 'GROQ_API_KEY' eksik."

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 512
    }
    try:
        resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
        # raise for status except we want to capture errors for debugging
        if resp.status_code != 200:
            # try json
            try:
                err = resp.json()
            except Exception:
                err = resp.text
            return f"Hata {resp.status_code}: {err}"
        data = resp.json()
        # OpenAI-style response handling
        if "choices" in data and len(data["choices"]) > 0:
            msg = data["choices"][0].get("message", {}).get("content")
            if msg:
                return msg
        # fallback
        return str(data)
    except requests.exceptions.RequestException as e:
        return f"Bağlantı hatası: {e}"
    except Exception as e:
        return f"Hata: {e}"

# ----------------------------
# ROUTES: auth, register, logout
# ----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        pwd = request.form.get("password", "").strip()
        pwd2 = request.form.get("password2", "").strip()
        if not user or not pwd:
            flash("Kullanıcı adı ve şifre gerekli.", "warning")
            return redirect(url_for("register"))
        if pwd != pwd2:
            flash("Şifreler eşleşmiyor.", "warning")
            return redirect(url_for("register"))
        if User.query.filter_by(username=user).first():
            flash("Bu kullanıcı adı alınmış.", "warning")
            return redirect(url_for("register"))
        u = User(username=user, password=pwd, is_admin=False)
        db.session.add(u)
        db.session.commit()
        flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
        return redirect(url_for("login"))
    return render_template_string(REG_TEMPLATE_REGISTER)

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        pwd = request.form.get("password", "").strip()
        u = User.query.filter_by(username=user, password=pwd).first()
        if not u:
            flash("Hatalı kullanıcı/şifre.", "danger")
            return redirect(url_for("login"))
        session["username"] = u.username
        session["is_admin"] = bool(u.is_admin)
        return redirect(url_for("chat"))
    return render_template_string(REG_TEMPLATE_LOGIN)

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("login"))

# ----------------------------
# Chat route
# ----------------------------
@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    reply = None
    user_text = None
    if request.method == "POST":
        user_text = request.form.get("user_input", "").strip()
        if user_text:
            # save message
            m = Message(user=session["username"], content=user_text)
            db.session.add(m)
            db.session.commit()
            # Ask Groq
            reply = ask_groq(user_text)
            # update message with response
            m.response = reply
            db.session.commit()
    # fetch last 10 messages for the user
    last_msgs = Message.query.order_by(Message.created_at.desc()).limit(20).all()[::-1]
    return render_template_string(REG_TEMPLATE_CHAT, username=session["username"],
                                  is_admin=session.get("is_admin", False),
                                  reply=reply, user_text=user_text, messages=last_msgs)

# ----------------------------
# Upload image
# ----------------------------
@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        flash("Dosya seçilmedi.", "warning")
        return redirect(url_for("chat"))
    f = request.files["file"]
    if f.filename == "":
        flash("Dosya adı boş.", "warning")
        return redirect(url_for("chat"))
    if not allowed_file(f.filename):
        flash("İzin verilen dosya türü: png/jpg/jpeg/gif", "warning")
        return redirect(url_for("chat"))
    fname = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{session['username']}_{f.filename}"
    dest = os.path.join(app.config["UPLOAD_FOLDER"], fname)
    f.save(dest)
    flash("Yüklendi: " + fname, "success")
    return redirect(url_for("uploads", filename=fname))

@app.route("/uploads/<path:filename>")
@login_required
def uploads(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ----------------------------
# Admin panel
# ----------------------------
@app.route("/admin")
@admin_required
def admin_panel():
    users = User.query.order_by(User.created_at.desc()).all()
    audits = AdminAudit.query.order_by(AdminAudit.timestamp.desc()).limit(50).all()
    return render_template_string(REG_TEMPLATE_ADMIN, users=users, audits=audits, current=session["username"])

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
@admin_required
def make_admin(user_id):
    actor = session["username"]
    target_user = User.query.get_or_404(user_id)
    if target_user.username == "enes" and actor != "enes":
        # cannot remove enes' admin if actor is not enes
        flash("enes admin yetkisi özel, değiştirilemez (sadece enes kendini değiştirebilir).", "danger")
        # audit log
        a = AdminAudit(action="attempt_mkadmin_protected", actor=actor, target=target_user.username)
        db.session.add(a); db.session.commit()
        return redirect(url_for("admin_panel"))
    # toggle admin
    prev = target_user.is_admin
    target_user.is_admin = not prev
    db.session.commit()
    a = AdminAudit(action=("grant_admin" if target_user.is_admin else "revoke_admin"),
                   actor=actor, target=target_user.username)
    db.session.add(a); db.session.commit()
    flash(f"{target_user.username} admin durumu değişti -> {target_user.is_admin}", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    actor = session["username"]
    target_user = User.query.get_or_404(user_id)
    if target_user.username == "enes":
        flash("enes hesabı silinemez.", "danger")
        a = AdminAudit(action="attempt_delete_enes", actor=actor, target="enes")
        db.session.add(a); db.session.commit()
        return redirect(url_for("admin_panel"))
    db.session.delete(target_user)
    db.session.commit()
    a = AdminAudit(action="delete_user", actor=actor, target=target_user.username)
    db.session.add(a); db.session.commit()
    flash(f"{target_user.username} silindi.", "info")
    return redirect(url_for("admin_panel"))

# ----------------------------
# TEMPLATES (basit, tek dosya)
# ----------------------------
# Note: For maintainability move templates out into files in templates/
REG_TEMPLATE_LOGIN = """
<!doctype html>
<title>KralZeka - Giriş</title>
<style>
 body{background:#070707;color:#eee;font-family:Inter,Arial;text-align:center;padding:40px}
 .card{background:#0f1111;border-radius:10px;padding:24px;width:420px;margin:30px auto}
 input{width:90%;padding:10px;margin:8px 0;border-radius:6px;border:1px solid #222;background:#0b0b0b;color:#eee}
 button{padding:10px 18px;background:#1f8b4c;border:none;border-radius:8px;color:#fff}
 a{color:#f66}
 .flash{color:#ffd700}
</style>
<div class="card">
  <h2>👑 KralZeka</h2>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for cat,msg in messages %}
        <div class="flash">{{msg}}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="post">
    <input name="username" placeholder="Kullanıcı adı" required>
    <input name="password" placeholder="Şifre" type="password" required>
    <div style="margin-top:10px">
      <button type="submit">Giriş Yap</button>
      <a href="{{url_for('register')}}" style="margin-left:10px">Kayıt ol</a>
    </div>
  </form>
</div>
"""

REG_TEMPLATE_REGISTER = """
<!doctype html>
<title>KralZeka - Kayıt</title>
<style> body{background:#070707;color:#eee;font-family:Inter,Arial;text-align:center;padding:40px} .card{background:#0f1111;border-radius:10px;padding:24px;width:420px;margin:30px auto} input{width:90%;padding:10px;margin:8px 0;border-radius:6px;border:1px solid #222;background:#0b0b0b;color:#eee} button{padding:10px 18px;background:#1f8b4c;border:none;border-radius:8px;color:#fff} a{color:#f66} .flash{color:#ffd700}</style>
<div class="card">
  <h2>Kayıt ol</h2>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for cat,msg in messages %}<div class="flash">{{msg}}</div>{% endfor %}
    {% endif %}
  {% endwith %}
  <form method="post">
    <input name="username" placeholder="Kullanıcı adı" required>
    <input name="password" placeholder="Şifre" type="password" required>
    <input name="password2" placeholder="Şifre tekrar" type="password" required>
    <div style="margin-top:10px">
      <button type="submit">Kayıt ol</button>
      <a href="{{url_for('login')}}" style="margin-left:10px">Girişe dön</a>
    </div>
  </form>
</div>
"""

REG_TEMPLATE_CHAT = """
<!doctype html>
<title>KralZeka - Chat</title>
<style>
  body{background:#000;color:#fff;font-family:Inter,Arial;padding:18px}
  .wrap{max-width:960px;margin:0 auto}
  .top{display:flex;justify-content:space-between;align-items:center}
  .card{background:#0f1111;padding:20px;border-radius:10px;margin-top:16px}
  input[type=text]{width:78%;padding:12px;border-radius:8px;border:1px solid #222;background:#070707;color:#fff}
  button{padding:10px 14px;border-radius:8px;background:#1f8b4c;border:none;color:#fff}
  .msg{background:#0b2b2b;padding:10px;border-radius:8px;margin:8px 0}
  .admin-badge{color:#ffd700;font-weight:700}
  .small{font-size:13px;color:#ccc}
</style>
<div class="wrap">
  <div class="top">
    <h2>Merhaba, {{username}} {% if is_admin %}<span class="admin-badge">[ADMIN]</span>{% endif %}</h2>
    <div>
      <a href="{{url_for('logout')}}">Çıkış yap</a>
      {% if is_admin %} | <a href="{{url_for('admin_panel')}}">Admin Panel</a>{% endif %}
    </div>
  </div>

  <div class="card">
    <form method="post">
      <input type="text" name="user_input" placeholder="Bir şey yaz..." required>
      <button type="submit">Gönder</button>
    </form>

    {% if user_text %}
      <div style="margin-top:12px">
        <div class="msg"><b>Sen:</b> {{user_text}}</div>
        <div class="msg"><b>KralZeka:</b> {{reply}}</div>
      </div>
    {% endif %}

    <h4 style="margin-top:20px">Son mesajlar</h4>
    {% for m in messages %}
      <div class="msg"><span class="small">{{m.created_at.strftime('%Y-%m-%d %H:%M')}}</span>
        <div><b>{{m.user}}:</b> {{m.content}}</div>
        {% if m.response %}<div class="small" style="margin-top:6px;color:#bcd">{{m.response}}</div>{% endif %}
      </div>
    {% endfor %}
  </div>
</div>
"""

REG_TEMPLATE_ADMIN = """
<!doctype html>
<title>KralZeka - Admin</title>
<style>
  body{background:#000;color:#fff;font-family:Inter,Arial;padding:18px}
  .wrap{max-width:1000px;margin:0 auto}
  .card{background:#0f1111;padding:20px;border-radius:10px;margin-top:16px}
  table{width:100%;border-collapse:collapse}
  th,td{padding:8px;border-bottom:1px solid #222}
  .btn{padding:6px 10px;border-radius:6px;background:#1f8b4c;border:none;color:#fff}
  .danger{background:#c0392b}
</style>
<div class="wrap">
  <h2>Admin Paneli — Hoşgeldin {{current}}</h2>
  <div class="card">
    <h3>Kullanıcılar</h3>
    <table>
      <tr><th>#</th><th>Username</th><th>Admin</th><th>Oluşturulma</th><th>İşlemler</th></tr>
      {% for u in users %}
        <tr>
          <td>{{u.id}}</td>
          <td>{{u.username}}</td>
          <td>{{u.is_admin}}</td>
          <td>{{u.created_at.strftime('%Y-%m-%d')}}</td>
          <td>
            <form style="display:inline" method="post" action="{{url_for('make_admin', user_id=u.id)}}">
              <button class="btn" type="submit">{{ "Remove Admin" if u.is_admin else "Make Admin" }}</button>
            </form>
            <form style="display:inline" method="post" action="{{url_for('delete_user', user_id=u.id)}}">
              <button class="btn danger" type="submit">Delete</button>
            </form>
          </td>
        </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h3>Admin Audit (son 50)</h3>
    <table>
      <tr><th>Zaman</th><th>Actor</th><th>Action</th><th>Target</th></tr>
      {% for a in audits %}
        <tr>
          <td>{{a.timestamp.strftime('%Y-%m-%d %H:%M')}}</td>
          <td>{{a.actor}}</td>
          <td>{{a.action}}</td>
          <td>{{a.target}}</td>
        </tr>
      {% endfor %}
    </table>
  </div>
</div>
"""

# ----------------------------
# RUN
# ----------------------------
if __name__ == "__main__":
    try:
        init_db()
    except Exception:
        print("DB init hatası, devam ediliyor. Hata detay:")
        traceback.print_exc()
    # Normalde Render/Heroku gibi platformlarda app.run kullanılmaz - WSGI server üstlenir.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
