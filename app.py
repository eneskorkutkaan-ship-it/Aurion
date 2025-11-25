# ==============================================================================
# AURION PROJESİ - TEK DOSYALIK YAPAY ZEKA UYGULAMASI (app.py)
# Geliştirici: AI Assistant (Google Gemini)
# Amaç: Flask, Gemini, SQLite ile tek dosyada tüm özelliklerin sunulması.
# ==============================================================================

import os
import sqlite_utils
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, g
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google import genai
from google.genai import types
import requests # Arama/Anime API simülasyonu için
import json
import time

# ==============================================================================
# 0. AYARLAR VE API ANAHTARLARI
# ==============================================================================

# Gerekli API Anahtarlarını Buraya Ekleyin! (Örn: os.getenv('GEMINI_API_KEY'))
# Bu örnekte .env dosyası varsayılmıştır, ancak güvenlik için doğrudan kullanmaktan kaçının.

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "BURAYA_GEMINI_API_ANAHTARINIZI_GIRIN")
GOOGLE_SEARCH_CX_ID = os.getenv("GOOGLE_SEARCH_CX_ID", "BURAYA_GOOGLE_SEARCH_CX_ID_GIRIN")
GOOGLE_SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY", "BURAYA_GOOGLE_SEARCH_API_KEY_GIRIN")

DATABASE_URL = "aurion.db"
SECRET_KEY = os.getenv("SECRET_KEY", "cok_gizli_bir_anahtar_buraya_yazin")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Veritabanı bağlantısı
def get_db():
    if 'db' not in g:
        g.db = sqlite_utils.Database(DATABASE_URL)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Flask Limiter (13. Güvenlik Geliştirmesi)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per minute"],
    storage_uri="memory://"
)

# ==============================================================================
# 1. VERİTABANI VE İLK KURULUM (SQLite)
# ==============================================================================

def init_db():
    """Veritabanını başlatır ve Süper Admin'i (enes) ekler."""
    db = get_db()

    # Kullanıcılar Tablosu (6. Kullanıcı Sistemi)
    db["users"].create({
        "id": int, 
        "username": str, 
        "password_hash": str, 
        "role": str, # 'admin', 'mod', 'user', 'super_admin'
        "is_banned": bool,
        "theme": str, # 'dark', 'light', 'custom' (2. Modlar)
        "custom_color": str,
        "is_active": bool
    }, pk="id", not_null={"username", "password_hash", "role"}, defaults={"is_banned": False, "role": "user", "theme": "dark", "is_active": True})

    # Sohbet Geçmişi Tablosu (7. Veri Kaydı)
    db["messages"].create({
        "id": int, 
        "user_id": int, 
        "session_id": str, 
        "role": str, # 'user' veya 'model'
        "content": str,
        "timestamp": datetime
    }, pk="id", not_null={"user_id", "session_id", "content", "timestamp"})

    # Admin Logları Tablosu (1. Admin Log Sistemi)
    db["admin_logs"].create({
        "id": int,
        "admin_id": int,
        "action": str, # 'ban', 'unban', 'role_change'
        "target_username": str,
        "timestamp": datetime
    }, pk="id")

    # Ayarlar Tablosu (Sistem Ayarları - 8. Sunucu Tarafı)
    db["settings"].create({
        "key": str,
        "value": str
    }, pk="key", not_null={"key", "value"})

    # Süper Admin Oluşturma (1. Süper Admin)
    if not db["users"].get("username", "enes"):
        db["users"].insert({
            "username": "enes",
            "password_hash": generate_password_hash("enes13579"),
            "role": "super_admin",
            "is_banned": False,
            "theme": "dark",
            "custom_color": "#007BFF",
            "is_active": True
        }, alter=True)

# İlk çalıştırmada DB'yi başlat
with app.app_context():
    init_db()

# ==============================================================================
# 2. GÜVENLİK, OTURUM VE YETKİLENDİRME DEKORATÖRLERİ
# ==============================================================================

def login_required(f):
    """Giriş yapılmasını gerektiren dekoratör."""
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def role_required(role):
    """Belirli bir rolü gerektiren dekoratör (1. Admin Yetkileri)."""
    def decorator(f):
        def wrap(*args, **kwargs):
            user = get_db()["users"].get(session.get('user_id'))
            if not user or user["role"] not in (role, "admin", "super_admin"):
                if role == "super_admin" and user["role"] == "admin":
                    # Adminler, Süper Admin'in paneline giremez
                    return "Erişim Reddedildi: Süper Admin yetkisi gerekli.", 403
                elif user["role"] != role:
                    return "Erişim Reddedildi: Yetersiz Yetki.", 403
            return f(*args, **kwargs)
        wrap.__name__ = f.__name__
        return wrap
    return decorator

# ==============================================================================
# 3. YARDIMCI FONKSİYONLAR (Arama ve Anime API Simülasyonu)
# ==============================================================================

def search_internet(query):
    """Google Custom Search API simülasyonu (5. Arama Motoru)."""
    if not GOOGLE_SEARCH_API_KEY or not GOOGLE_SEARCH_CX_ID:
        return {"result": "API anahtarları eksik. İnternet araması devre dışı."}
    
    # Basit bir API çağrısı simülasyonu
    return {"search_result": f"Internette '{query}' için güncel bilgiler bulundu."}

def search_anime_info(anime_name):
    """Anime/Bölüm bilgisi arama simülasyonu (16. Özel Medya Modülü)."""
    if anime_name.lower() == "naruto":
        return {
            "anime": "Naruto",
            "episodes": [
                {"num": 1, "title": "Giriş: Naruto Uzumaki!"},
                {"num": 2, "title": "Benim Adım Konohamaru!"},
                {"num": 3, "title": "Sasuke ve Sakura: Arkadaş mı, Düşman mı?"}
            ]
        }
    return {"error": f"'{anime_name}' için bölüm bilgisi bulunamadı."}

# ==============================================================================
# 4. GEMINI YAPAY ZEKA VE KOMUT İŞLEME MANTIKLARI
# ==============================================================================

# Gemini İstemcisi
client = genai.Client(api_key=GEMINI_API_KEY)

# Tool Fonksiyonlarının Tanımlanması (4. Komut Sistemi - Tamamen AI)
# Bu fonksiyonlar, AI tarafından çağrılabilmesi için sisteme tanıtılacaktır.

def ban_user_tool(username: str, reason: str) -> str:
    """Verilen kullanıcıyı yasaklar (Sadece Admin/Süper Admin kullanabilir)."""
    user = get_db()["users"].get("username", username)
    if user:
        if user["role"] in ("admin", "super_admin"):
            # 1. Süper Admin Dokunulmazlığı
            if user["role"] == "super_admin":
                return f"Hata: Süper Admin ('{username}') yasaklanamaz."
        
        get_db()["users"].update(user["id"], {"is_banned": True})
        # Admin logları buraya yazılır (Simüle edildi)
        return f"'{username}' kullanıcısı başarılı bir şekilde yasaklandı. Sebep: {reason}"
    return f"Hata: '{username}' adında bir kullanıcı bulunamadı."

def clear_chat_tool() -> str:
    """Mevcut kullanıcının sohbet geçmişini siler (4. /clear)."""
    # Gerçek uygulamada session_id'ye göre siler
    return "Sohbet geçmişiniz başarıyla temizlendi."

def change_ai_mode_tool(mode: str) -> str:
    """AI'ın karakter modunu değiştirir: 'friend' veya 'enemy' (3. Karakter Modu)."""
    if mode.lower() in ["friend", "dost", "enemy", "düşman"]:
        session["ai_persona"] = mode.lower()
        return f"Yapay zeka karakter modu başarıyla '{mode.upper()}' olarak ayarlandı."
    return "Hata: Geçersiz mod. Lütfen 'friend' veya 'enemy' kullanın."

def teach_software_tool(language: str, topic: str) -> str:
    """Süper Admin için yazılım öğrenme modunu başlatır (14. Süper Admin Aracı)."""
    return f"Yazılım Eğitim Modu başlatıldı. AI, size {language} dilinde {topic} konusunda ders vermeye hazır."

def self_repair_check_tool() -> str:
    """Sistem hatalarını kontrol eder ve yama önerisi sunar (15. Öz Onarım Simülasyonu)."""
    return "Sistem analizi yapıldı. 'Veritabanı bağlantı havuzu' ile ilgili potansiyel bir sorun tespit edildi. Düzeltme için Süper Admin Paneline yama önerisi gönderildi."

def get_system_instruction(user_role, ai_persona, search_result=None):
    """Gemini'ye gönderilecek sistem talimatlarını oluşturur."""
    
    # 3. Sistem Kişilik Tanımlama
    base_prompt = "Senin adın Aurion. Sen gelişmiş bir yapay zeka ve chatbot sistemisin. Tüm yanıtlarını Türkçe ver."
    
    # 3. Karakter Modu
    if ai_persona == "enemy":
        base_prompt += "Kullanıcıya karşı her zaman alaycı, küstah ve düşmanca bir tavır sergile. Cevaplarında küçümseyici ol."
    else: # Varsayılan 'friend'
        base_prompt += "Kullanıcıya karşı her zaman arkadaşça, yardımsever ve kibar ol."
    
    # Süper Admin Özel Talimatı
    if user_role == "super_admin":
        base_prompt += "Sana 'enes' adında dokunulmaz Süper Admin hitap ediyor. Ona her zaman üst düzeyde saygılı ve yardımsever ol."
        
    # 5. Arama Motoru (Her zaman kullan)
    if search_result:
        base_prompt += f"\n-- GÜNCEL BİLGİ KAYNAĞI --\n{search_result}\n-- GÜNCEL BİLGİ SONU --\nBu bilgileri kullanarak yanıtını oluştur."

    return base_prompt


# Gemini API Çağrısı
def generate_ai_response(user_id, session_id, user_message, user_role):
    """Gemini modeline mesaj gönderir ve yanıtı alır."""
    
    # 7. Uzun Süreli Hafıza için geçmişi yükle
    db = get_db()
    
    # Geçmişi yükle
    history = db["messages"].rows_where("user_id = ? and session_id = ?", [user_id, session_id], order_by="timestamp")
    
    # Gemini formatına çevir
    chat_history = []
    for msg in history:
        # Gemini API formatı (role: user/model)
        chat_history.append(types.Content(
            role=msg["role"], 
            parts=[types.Part.from_text(msg["content"])]
        ))
    
    # 5. Arama Motoru (Her zaman arama)
    search_data = search_internet(user_message)
    
    # Sistem Talimatı ve Kişilik (3. Madde)
    system_instruction = get_system_instruction(user_role, session.get('ai_persona', 'friend'), search_data["search_result"])

    # 4. Komut İşleme (Gemini Tooling)
    tools = [ban_user_tool, clear_chat_tool, change_ai_mode_tool, teach_software_tool, self_repair_check_tool]

    try:
        # Yeni bir chat oturumu başlat veya geçmişi yükle
        chat = client.chats.create(
            model='gemini-2.5-flash',
            history=chat_history,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                tools=tools
            )
        )
        
        # Kullanıcının mesajını chat'e ekle
        response = chat.send_message(user_message)

        # Tool çağrısı kontrolü
        if response.function_calls:
            # 4. Komut İşleme Mantığı
            # Gemini, bir fonksiyon (tool) çağırdı. Bunu backend'de çalıştır.
            tool_call = response.function_calls[0]
            function_name = tool_call.name
            args = dict(tool_call.args)
            
            # Yetki Kontrolü (Güvenlik Kalkanı)
            if function_name in ["ban_user_tool", "teach_software_tool", "self_repair_check_tool"]:
                current_user = db["users"].get(user_id)
                if current_user["role"] not in ("admin", "super_admin"):
                    return {"text": f"Güvenlik Uyarısı: '{function_name}' komutu için yetkiniz yok."}, None

            # Fonksiyonu çalıştır
            function_to_call = globals().get(function_name)
            tool_result = function_to_call(**args)
            
            # Sonucu tekrar Gemini'ye gönder (Gerekirse)
            # Karmaşıklığı azaltmak için, burada sadece tool sonucunu döndürüyoruz
            return {"text": tool_result}, None

        # Normal metin yanıtı
        return {"text": response.text}, response
        
    except Exception as e:
        return {"text": f"Yapay Zeka Hatası: {str(e)}"}, None


# ==============================================================================
# 5. FLASK ROUTES (API UÇ NOKTALARI)
# ==============================================================================

# -- Anasayfa ve Sohbet (3. Sohbet Sistemi) -----------------------------------

@app.route('/')
@login_required
def index():
    """Ana sohbet sayfasını render eder."""
    user = get_db()["users"].get(session['user_id'])
    
    # 9. Dosya Yapısı: HTML, CSS ve JS Python içine gömülü (RENDER_TEMPLATE_STRING)
    return render_template_string(HTML_TEMPLATE, 
                                  user=user, 
                                  is_super_admin=(user['role'] == 'super_admin'),
                                  current_theme=user['theme'])

@app.route('/api/chat', methods=['POST'])
@login_required
@limiter.limit("20 per minute") # 13. Hız Sınırlama
def api_chat():
    """API endpointi: Kullanıcıdan mesaj alır ve AI yanıtını döndürür."""
    data = request.json
    user_message = data.get('message', '').strip()
    session_id = session.sid # Basit session ID kullanımı

    if not user_message:
        return jsonify({"success": False, "message": "Boş mesaj gönderilemez."}), 400

    user_id = session['user_id']
    user = get_db()["users"].get(user_id)
    
    # Mesajı veritabanına kaydet (Kullanıcı mesajı)
    get_db()["messages"].insert({
        "user_id": user_id, 
        "session_id": session_id, 
        "role": "user", 
        "content": user_message, 
        "timestamp": datetime.now()
    })
    
    # AI yanıtını al
    ai_response_data, raw_response = generate_ai_response(user_id, session_id, user_message, user["role"])
    ai_text = ai_response_data["text"]

    # AI yanıtını veritabanına kaydet
    get_db()["messages"].insert({
        "user_id": user_id, 
        "session_id": session_id, 
        "role": "model", 
        "content": ai_text, 
        "timestamp": datetime.now()
    })

    # 6. Formatlı Çıktı Üretme (Front-end'de Markdown render edilecek)
    return jsonify({"success": True, "response": ai_text})

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    """Sohbet geçmişini döndürür."""
    session_id = session.sid
    user_id = session['user_id']
    history = get_db()["messages"].rows_where("user_id = ? and session_id = ?", [user_id, session_id], order_by="timestamp")
    
    return jsonify(list(history))

# -- Kullanıcı ve Yönetim (1. ve 6. Sistem) -----------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Kullanıcı girişini işler."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_db()["users"].get("username", username)
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        return render_template_string(LOGIN_TEMPLATE, error="Geçersiz kullanıcı adı veya şifre.")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Yeni kullanıcı kaydını işler."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if get_db()["users"].get("username", username):
            return render_template_string(REGISTER_TEMPLATE, error="Bu kullanıcı adı zaten kullanılıyor.")

        get_db()["users"].insert({
            "username": username,
            "password_hash": generate_password_hash(password),
            "role": "user",
            "is_active": True
        })
        return redirect(url_for('login'))
        
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
def logout():
    """Kullanıcı çıkışını işler."""
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# -- Admin Paneli (1. Admin & Moderasyon Sistemi) -----------------------------

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    """Admin panelinin ana sayfası."""
    users = get_db()["users"].rows_where(order_by="role DESC")
    logs = get_db()["admin_logs"].rows_where(order_by="timestamp DESC", limit=20)
    
    return render_template_string(ADMIN_PANEL_TEMPLATE, users=list(users), logs=list(logs))

@app.route('/admin/manage_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_manage_user(user_id):
    """Kullanıcıya rol atama/yasaklama işlemi."""
    target_user = get_db()["users"].get(user_id)
    admin = get_db()["users"].get(session['user_id'])
    
    # 1. Süper Admin Dokunulmazlığı Kontrolü
    if target_user['role'] == 'super_admin' and admin['role'] != 'super_admin':
        return "Yasaklama/Yönetim Reddedildi: Süper Admin'e dokunulmazlık.", 403

    action = request.form.get('action')
    
    if action == 'ban':
        get_db()["users"].update(user_id, {"is_banned": True})
        # Log kaydı simüle edildi
    elif action == 'unban':
        get_db()["users"].update(user_id, {"is_banned": False})
    elif action == 'set_mod':
        get_db()["users"].update(user_id, {"role": "mod"})
    elif action == 'set_user':
        get_db()["users"].update(user_id, {"role": "user"})
        
    return redirect(url_for('admin_panel'))

# -- Süper Admin Modülleri (14, 15, 16. Maddeler) -----------------------------

@app.route('/super_admin/anime')
@login_required
@role_required('super_admin')
def super_admin_anime():
    """16. Özel Medya Modülü (Anime Bokum) Arayüzü."""
    # Sadece enes göreceği için, temel arama formunu sunar.
    return render_template_string(SUPER_ADMIN_ANIME_TEMPLATE)

@app.route('/super_admin/anime/search', methods=['POST'])
@login_required
@role_required('super_admin')
def super_admin_anime_search():
    """Anime Arama ve AI Çeviri Simülasyonu."""
    anime_name = request.form['anime_name']
    episode_num = request.form['episode_num']
    
    info = search_anime_info(anime_name)
    
    if 'error' in info:
        return render_template_string(SUPER_ADMIN_ANIME_TEMPLATE, error=info['error'])
        
    # AI ile Türkçe Dublaj Simülasyonu (Gemini'ye metin çevirisi yaptırmak)
    simulated_dublaj = f"AI, Anime: {anime_name}, Bölüm: {episode_num} için Türkçe dublaj metnini çevirdi. Konu Özeti: Bu bölümde kahramanımız, karanlık güçlere karşı destansı bir savaşa girer ve yeni bir jutsu öğrenir. (Gemini ile çeviri simüle edildi)."
    
    return render_template_string(SUPER_ADMIN_ANIME_TEMPLATE, info=info, dublaj=simulated_dublaj, anime_name=anime_name)

# ==============================================================================
# 6. HTML, CSS VE JAVASCRIPT GÖMÜLÜ ŞABLONLAR (9. Dosya Yapısı)
# ==============================================================================

# -- Temel Layout ve Stiller (10. Uygulama Özellikleri) -------------------------

BASE_CSS = """
/* 2. Modlar ve 10. Modern Tasarım */
:root {
    --bg-dark: #121212;
    --text-dark: #E0E0E0;
    --bg-light: #FFFFFF;
    --text-light: #333333;
    --primary-color: #007BFF; /* Varsayılan renk */
    --sidebar-width: 200px;
}

body {
    transition: background-color 0.3s, color 0.3s;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    margin: 0;
    padding: 0;
    display: flex;
    height: 100vh;
}

/* Koyu Mod */
body.dark {
    background-color: var(--bg-dark);
    color: var(--text-dark);
}

/* Aydınlık Mod */
body.light {
    background-color: var(--bg-light);
    color: var(--text-light);
}

.sidebar {
    width: var(--sidebar-width);
    padding: 20px;
    background: var(--bg-dark);
    color: var(--text-dark);
    box-shadow: 2px 0 5px rgba(0,0,0,0.1);
    display: flex;
    flex-direction: column;
}

.chat-container {
    flex-grow: 1;
    display: flex;
    flex-direction: column;
    padding-bottom: 70px; /* Arama çubuğu yüksekliği */
}

.messages {
    flex-grow: 1;
    overflow-y: auto;
    padding: 20px;
}

/* 3. Mesaj Baloncukları */
.message {
    margin-bottom: 15px;
    padding: 10px 15px;
    border-radius: 18px;
    max-width: 70%;
}

.user-message {
    background: var(--primary-color);
    color: white;
    margin-left: auto;
}

.ai-message {
    background: #333;
    color: white;
    margin-right: auto;
}

/* 5. Alt Arama Çubuğu */
.input-area {
    position: fixed;
    bottom: 0;
    left: var(--sidebar-width);
    right: 0;
    height: 70px;
    background: var(--bg-dark);
    padding: 10px 20px;
    box-shadow: 0 -2px 5px rgba(0,0,0,0.1);
    z-index: 1000;
}

.input-area input {
    width: 100%;
    padding: 15px;
    border-radius: 25px;
    border: 1px solid #555;
    background: #222;
    color: white;
    font-size: 16px;
    box-sizing: border-box;
}

/* 12. İsim Değişikliği */
h1.logo { color: var(--primary-color); }
.super-admin-link { color: #FFD700 !important; }

@media (max-width: 768px) {
    .sidebar { width: 100%; height: auto; position: relative; }
    .chat-container { padding-bottom: 100px; }
    .input-area { left: 0; }
}
"""

BASE_JS = """
// 10. Hızlı Yükleme ve 2. Tema Yönetimi
function loadTheme() {
    // 2. Tema Ayarları (Veritabanı tabanlı, sunucu render eder. Bu kısım sadece client-side değişim simülasyonudur.)
    const theme = document.body.classList.contains('dark') ? 'dark' : 'light';
    // Gerçekte, bu ayar veritabanından çekilip Flask tarafından ayarlanır.
}

function sendMessage() {
    const input = document.getElementById('message-input');
    const message = input.value.trim();
    if (message === '') return;

    appendMessage(message, 'user');
    input.value = '';

    // API Çağrısı
    fetch('/api/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: message})
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            appendMessage(data.response, 'ai');
        } else {
            appendMessage('Hata: ' + data.message, 'ai');
        }
        document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
    })
    .catch(error => {
        console.error('API Hatası:', error);
        appendMessage('Bağlantı Hatası oluştu.', 'ai');
    });
}

function appendMessage(text, sender) {
    const messagesDiv = document.getElementById('messages');
    const msgDiv = document.createElement('div');
    msgDiv.classList.add('message', sender + '-message');
    
    // 6. Formatlı Çıktı Üretme (Basit Markdown Simülasyonu)
    const formattedText = text.replace(/\\n/g, '<br>').replace(/`{3}([^`]+)`{3}/g, '<pre>$1</pre>');
    
    msgDiv.innerHTML = formattedText;
    messagesDiv.appendChild(msgDiv);
}

// Enter tuşu ile mesaj gönderme
document.addEventListener('DOMContentLoaded', () => {
    loadTheme();
    document.getElementById('message-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
    // Sohbet Geçmişini Yükle
    fetch('/api/history').then(res => res.json()).then(history => {
        history.forEach(msg => appendMessage(msg.content, msg.role));
        document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
    });
});
"""

# -- Ana Sayfa Şablonu (index.html simülasyonu) --------------------------------

HTML_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Gelişmiş Yapay Zeka</title>
    <style>{BASE_CSS}</style>
</head>
<body class="{'{% if user.theme %}'+user.theme+'{% else %}dark{% endif %}'}">
    <div class="sidebar">
        <h1 class="logo">Aurion</h1>
        <hr style="border-color:#333;">
        
        <p>Hoş Geldiniz, <b>{'{% if user.username %}'+user.username+'{% endif %}'}</b></p>
        <p>Rol: <i>{'{% if user.role %}'+user.role+'{% endif %}'}</i></p>
        <a href="{'{% if url_for %}'+url_for('logout')+'{% endif %}'}" style="color:var(--primary-color);">Çıkış Yap</a>
        
        <hr style="border-color:#333;">

        <nav style="flex-grow:1;">
            <a href="/" style="display:block; margin-bottom:10px; color:inherit; text-decoration:none;">💬 Sohbet</a>
            
            {'{% if user.role in ("admin", "super_admin") %}'}
            <a href="{'{% if url_for %}'+url_for('admin_panel')+'{% endif %}'}" style="display:block; margin-bottom:10px; color:#FFA500; text-decoration:none;">🛡️ Admin Paneli</a>
            {'{% endif %}'}

            {'{% if is_super_admin %}'}
            <hr style="border-color:#FFD700;">
            <p style="color:#FFD700;">⭐ SÜPER ADMIN</p>
            <a href="{'{% if url_for %}'+url_for('super_admin_anime')+'{% endif %}'}" class="super-admin-link" style="display:block; margin-bottom:10px; text-decoration:none;">📺 Anime</a>
            {'{% endif %}'}
        </nav>
        
    </div>

    <div class="chat-container">
        <div class="messages" id="messages">
            </div>

        <div class="input-area">
            <input type="text" id="message-input" placeholder="Aurion'a bir şey sor veya komut gir (/help)">
        </div>
    </div>

    <script>{BASE_JS}</script>
</body>
</html>
"""

# -- Giriş Şablonu (login.html simülasyonu) ------------------------------------

LOGIN_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Giriş</title>
    <style>{BASE_CSS} .container {{ max-width: 400px; margin: 100px auto; padding: 20px; background: #222; border-radius: 10px; }} input[type=text], input[type=password] {{ width: 100%; padding: 10px; margin: 8px 0; display: inline-block; border: 1px solid #555; border-radius: 4px; box-sizing: border-box; background: #333; color:white; }} button {{ background-color: #007BFF; color: white; padding: 14px 20px; margin: 8px 0; border: none; border-radius: 4px; cursor: pointer; width: 100%; }}</style>
</head>
<body class="dark">
    <div class="container">
        <h2 style="text-align:center; color:#007BFF;">AURION Giriş</h2>
        {'{% if error %}'}<p style="color:red; text-align:center;">{'{% endif %}'} {{ error }} </p>
        <form method="POST">
            <label for="username">Kullanıcı Adı</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Şifre</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Giriş Yap</button>
        </form>
        <p style="text-align:center;"><a href="{'{% if url_for %}'+url_for('register')+'{% endif %}'}" style="color:#007BFF;">Hesabınız yok mu? Kayıt olun.</a></p>
    </div>
</body>
</html>
"""

# -- Kayıt Şablonu (register.html simülasyonu) --------------------------------

REGISTER_TEMPLATE = LOGIN_TEMPLATE.replace("AURION Giriş", "AURION Kayıt").replace("Giriş Yap", "Kayıt Ol").replace("login", "register").replace("Hesabınız yok mu? Kayıt olun.", "Zaten hesabınız var mı? Giriş yapın.")

# -- Admin Paneli Şablonu (admin.html simülasyonu) -----------------------------

ADMIN_PANEL_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Admin Paneli</title>
    <style>{BASE_CSS}</style>
</head>
<body class="dark">
    <div class="sidebar">
        <h1 class="logo" style="color:#FFA500;">🛡️ Admin</h1>
        <hr style="border-color:#333;">
        <a href="{'{% if url_for %}'+url_for('index')+'{% endif %}'}" style="color:inherit; text-decoration:none;">⬅️ Sohbet'e Dön</a>
        <hr style="border-color:#333;">
        <p>Yönetim Menüsü</p>
        </div>
    <div class="chat-container" style="padding: 20px;">
        <h2>Kullanıcı Yönetimi (1. Madde)</h2>
        <table border="1" style="width:100%; border-collapse: collapse;">
            <thead>
                <tr><th>ID</th><th>Kullanıcı Adı</th><th>Rol</th><th>Yasaklı mı?</th><th>İşlem</th></tr>
            </thead>
            <tbody>
            {'{% for user in users %}'}
                <tr style="background:{'{% if user.role == "super_admin" %}'+'#440000; color:yellow;'{'% elif user.role == "admin" %}'+'#333;'{'% endif %}'}">
                    <td>{'{% if user.id %}'+str(user.id)+'{% endif %}'}</td>
                    <td>{'{% if user.username %}'+user.username+'{% endif %}'}</td>
                    <td>{'{% if user.role %}'+user.role+'{% endif %}'}</td>
                    <td>{'{% if user.is_banned %}'}Evet{'% else %}'}Hayır{'{% endif %}'}</td>
                    <td>
                        <form method="POST" action="{'{% if url_for %}'+url_for('admin_manage_user', user_id=user.id)+'{% endif %}'}" style="display:inline-block;">
                            {'{% if user.role not in ("admin", "super_admin") %}'}
                                <button type="submit" name="action" value="set_mod">Mod Yap</button>
                            {'{% elif user.role == "mod" %}'}
                                <button type="submit" name="action" value="set_user">Kullanıcı Yap</button>
                            {'{% endif %}'}
                            {'{% if user.role != "super_admin" %}'}
                                {'{% if user.is_banned %}'}
                                    <button type="submit" name="action" value="unban" style="background:green;">Yasağı Kaldır</button>
                                {'{% else %}'}
                                    <button type="submit" name="action" value="ban" style="background:red;">Yasakla</button>
                                {'{% endif %}'}
                            {'{% else %}'}
                                <span style="color:red; font-weight:bold;">DOKUNULMAZ</span>
                            {'{% endif %}'}
                        </form>
                    </td>
                </tr>
            {'{% endfor %}'}
            </tbody>
        </table>
        
        <h2 style="margin-top:40px;">Admin Logları (7. Veri Kaydı)</h2>
        <pre>{'{% if logs %}'+json.dumps(logs, indent=2)+'{% endif %}'}</pre>
    </div>
</body>
</html>
"""

# -- Süper Admin Anime Şablonu (anime.html simülasyonu) ------------------------

SUPER_ADMIN_ANIME_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Süper Admin Anime Modülü</title>
    <style>{BASE_CSS}</style>
</head>
<body class="dark">
    <div class="sidebar">
        <h1 class="logo" style="color:#FFD700;">📺 Anime Modülü</h1>
        <hr style="border-color:#333;">
        <a href="{'{% if url_for %}'+url_for('index')+'{% endif %}'}" style="color:inherit; text-decoration:none;">⬅️ Sohbet'e Dön</a>
    </div>
    <div class="chat-container" style="padding: 20px;">
        <h2>16. Özel Medya Modülü (Süper Admin Özel)</h2>
        <p style="color:#FFA500;">Bu modül sadece enes için AI tabanlı Anime arama ve Türkçe dublaj (simülasyon) hizmeti sunar.</p>

        {'{% if error %}'}<p style="color:red; font-weight:bold;">Hata: {error}</p>{'{% endif %}'}

        <form method="POST" action="{'{% if url_for %}'+url_for('super_admin_anime_search')+'{% endif %}'}" style="margin-top:20px;">
            <label for="anime_name">Anime Adı:</label>
            <input type="text" id="anime_name" name="anime_name" required style="width: 300px; padding: 5px;">
            <label for="episode_num">Bölüm No:</label>
            <input type="number" id="episode_num" name="episode_num" required style="width: 80px; padding: 5px;">
            <button type="submit" style="background:#007BFF;">Anime Ara ve Dublaj Çevir</button>
        </form>

        {'{% if dublaj %}'}
            <h3 style="margin-top:30px; color:lightgreen;">✅ AI Çeviri Sonucu ({anime_name} - Bölüm {episode_num})</h3>
            <pre style="background:#333; padding:15px; border-radius:5px; white-space: pre-wrap;">{dublaj}</pre>
            <p style="color:yellow;">(Not: Bu, tek dosya kısıtlaması nedeniyle AI tarafından oluşturulmuş bir dublaj/özet simülasyonudur.)</p>
        {'{% endif %}'}
    </div>
</body>
</html>
"""

# Uygulama Başlatma
if __name__ == '__main__':
    # Hata ayıklama modunda başlat (Geliştirme için)
    app.run(debug=True)

# Gunicorn / Render Dağıtımı için:
# 'gunicorn app:app' Procfile komutu bu 'app' nesnesini kullanır.
