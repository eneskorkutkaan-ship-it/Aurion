import os
import sqlite3
from flask import Flask, render_template_string, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "super_secret_key_v1"  # Değiştirilebilir

DB_FILE = "kralzeka_v1.db"


# 🔹 Veritabanı Başlatma
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


# 🔹 Varsayılan admin hesabı oluştur
def ensure_admin():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                  ("admin", "12345", 1))
        conn.commit()
    conn.close()


# 🔹 Ana Sayfa
@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    is_admin = user[0] == 1 if user else False

    return render_template_string('''
        <html>
        <head>
            <title>KralZeka v1</title>
            <style>
                body { font-family: Arial; background: #0e0e0e; color: #fff; text-align: center; padding-top: 80px; }
                .card { background: #181818; padding: 40px; border-radius: 12px; display: inline-block; box-shadow: 0 0 20px #00c3ff; }
                input, button { margin: 5px; padding: 8px; border-radius: 6px; border: none; }
                button { background: #00c3ff; color: #000; cursor: pointer; }
                button:hover { background: #009edb; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>🤴 KralZeka v1'e Hoş Geldin {{username}}!</h1>
                {% if is_admin %}
                    <p>Admin olarak giriş yaptın. <a href="{{url_for('admin_panel')}}">Admin Paneline Git</a></p>
                {% else %}
                    <p>Kullanıcı paneline erişimin var.</p>
                {% endif %}
                <a href="{{url_for('logout')}}"><button>Çıkış Yap</button></a>
            </div>
        </body>
        </html>
    ''', username=username, is_admin=is_admin)


# 🔹 Giriş Sayfası
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session["username"] = username
            return redirect(url_for("index"))
        else:
            return render_template_string(LOGIN_HTML, error="Kullanıcı adı veya şifre hatalı!")

    return render_template_string(LOGIN_HTML)


LOGIN_HTML = '''
<html>
<head>
    <title>KralZeka v1 Giriş</title>
    <style>
        body { font-family: Arial; background: #101010; color: #fff; text-align: center; padding-top: 120px; }
        .login-box { background: #181818; padding: 40px; border-radius: 12px; display: inline-block; box-shadow: 0 0 20px #00c3ff; }
        input { margin: 8px; padding: 8px; border-radius: 6px; border: none; width: 200px; }
        button { background: #00c3ff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; color: #000; }
        button:hover { background: #009edb; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 KralZeka v1 Giriş</h2>
        {% if error %}<p style="color:red;">{{error}}</p>{% endif %}
        <form method="post">
            <input type="text" name="username" placeholder="Kullanıcı Adı" required><br>
            <input type="password" name="password" placeholder="Şifre" required><br>
            <button type="submit">Giriş Yap</button>
        </form>
    </div>
</body>
</html>
'''


# 🔹 Admin Paneli
@app.route("/admin")
def admin_panel():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if not user or user[0] == 0:
        return "❌ Bu sayfaya erişim yetkin yok!"

    return render_template_string('''
        <html>
        <head>
            <title>KralZeka v1 Admin Paneli</title>
            <style>
                body { font-family: Arial; background: #0a0a0a; color: #fff; text-align: center; padding-top: 60px; }
                .panel { background: #181818; padding: 40px; border-radius: 12px; display: inline-block; box-shadow: 0 0 20px #00ff6a; }
                textarea { width: 400px; height: 120px; border-radius: 8px; border: none; padding: 8px; margin-bottom: 8px; }
                button { background: #00ff6a; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; color: #000; }
                button:hover { background: #00db57; }
            </style>
        </head>
        <body>
            <div class="panel">
                <h2>👑 KralZeka v1 Admin Paneli</h2>
                <form method="post" action="{{url_for('generate_code')}}">
                    <textarea name="prompt" placeholder="Otomatik kod oluştur komutu yaz..."></textarea><br>
                    <button type="submit">Kod Oluştur</button>
                </form>
                <a href="{{url_for('index')}}"><button>Ana Sayfa</button></a>
            </div>
        </body>
        </html>
    ''')


# 🔹 Kod üretici (örnek otomatik sistem)
@app.route("/generate_code", methods=["POST"])
def generate_code():
    if "username" not in session:
        return redirect(url_for("login"))
    prompt = request.form["prompt"]
    if not prompt.strip():
        return "Lütfen bir komut girin!"
    # Gerçek AI API burada entegre edilecek (örnek cevap)
    return f"<pre><code># KralZeka v1 Otomatik Kod Çıktısı:\n\nprint('İstek: {prompt}')\nprint('Kod başarıyla oluşturuldu!')</code></pre><a href='/admin'>Geri Dön</a>"


# 🔹 Çıkış
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    ensure_admin()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
