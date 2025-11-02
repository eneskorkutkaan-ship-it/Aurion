# kralzeka_app.py
# 👑 KralZeka v1 - Hatasız Render Sürümü

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

DB_PATH = "kralzeka.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

def init_db(force=False):
    """Veritabanını güvenli şekilde başlatır."""
    try:
        if not os.path.exists(DB_PATH):
            print("🔧 Yeni veritabanı oluşturuluyor...")

        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()

            # force=True ise tüm tabloları sil
            if force:
                print("⚠️ Tablolar sıfırlanıyor...")
                cursor.executescript("""
                DROP TABLE IF EXISTS users;
                DROP TABLE IF EXISTS messages;
                """)

            # Şemayı uygula
            cursor.executescript(SCHEMA_SQL)

            # Admin hesabı yoksa oluştur
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin=1;")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1);",
                    ("admin", "admin123")
                )
                print("👑 Varsayılan admin hesabı oluşturuldu (admin / admin123)")

            db.commit()
            print("✅ Veritabanı başarıyla başlatıldı!")

    except Exception as e:
        print("🚨 Veritabanı başlatılırken hata oluştu:", e)

# --- API Rotaları ---

@app.route("/")
def home():
    return jsonify({
        "status": "ok",
        "message": "KralZeka v1 API aktif 👑"
    })

@app.route("/users", methods=["GET"])
def list_users():
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, username, is_admin FROM users;")
        users = [{"id": u[0], "username": u[1], "is_admin": bool(u[2])} for u in cursor.fetchall()]
    return jsonify(users)

@app.route("/add_user", methods=["POST"])
def add_user():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Eksik bilgi"}), 400
    try:
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?);",
                (data["username"], data["password"])
            )
            db.commit()
        return jsonify({"message": "Kullanıcı eklendi ✅"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu kullanıcı zaten var"}), 409

@app.route("/messages", methods=["GET"])
def get_messages():
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT messages.id, users.username, messages.content, messages.timestamp
            FROM messages
            JOIN users ON users.id = messages.user_id
            ORDER BY messages.timestamp DESC;
        """)
        data = [
            {"id": m[0], "user": m[1], "content": m[2], "timestamp": m[3]}
            for m in cursor.fetchall()
        ]
    return jsonify(data)

@app.route("/add_message", methods=["POST"])
def add_message():
    data = request.get_json()
    if not data or "username" not in data or "content" not in data:
        return jsonify({"error": "Eksik bilgi"}), 400
    try:
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.cursor()
            cursor.execute("SELECT id FROM users WHERE username=?;", (data["username"],))
            user = cursor.fetchone()
            if not user:
                return jsonify({"error": "Kullanıcı bulunamadı"}), 404
            cursor.execute(
                "INSERT INTO messages (user_id, content) VALUES (?, ?);",
                (user[0], data["content"])
            )
            db.commit()
        return jsonify({"message": "Mesaj kaydedildi ✅"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Uygulama Başlatma ---
if __name__ == "__main__":
    print("🚀 KralZeka başlatılıyor...")
    init_db(force=False)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
