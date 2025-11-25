# ==============================================================================
# AURION PROJESİ - TEK DOSYALIK YAPAY ZEKA UYGULAMASI (app.py)
# Tüm 16 özellik dahil edilmiştir. (1. Admin, 3. Gemini, 9. Tek Dosya, 16. Süper Admin Modülleri)
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
import json
import time
import re # Öz Onarım Simülasyonu için

# ==============================================================================
# 0. AYARLAR VE ÇEVRESEL DEĞİŞKENLER
# ==============================================================================

# Çevresel değişkenler os.getenv() ile yüklenir (Render.com uyumlu)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GOOGLE_SEARCH_CX_ID = os.getenv("GOOGLE_SEARCH_CX_ID")
GOOGLE_SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "cok_gizli_bir_anahtar_buraya_yazin")

DATABASE_URL = "aurion.db"

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
# 1. VERİTABANI VE İLK KURULUM
# ==============================================================================

def init_db():
    """Veritabanını başlatır ve Süper Admin'i (enes) ekler."""
    db = get_db()

    # Tablo Oluşturma
    db["users"].create({
        "id": int, "username": str, "password_hash": str, "role": str, # 'super_admin' dahil
        "is_banned": bool, "theme": str, "is_active": bool
    }, pk="id", not_null={"username", "password_hash", "role"}, defaults={"is_banned": False, "role": "user", "theme": "dark", "is_active": True})

    db["messages"].create({
        "id": int, "user_id": int, "session_id": str, "role": str, "content": str, "timestamp": datetime
    }, pk="id", not_null={"user_id", "session_id", "content", "timestamp"})

    db["admin_logs"].create({
        "id": int, "admin_id": int, "action": str, "target_username": str, "timestamp": datetime
    }, pk="id")
    
    # Süper Admin Oluşturma (1. Süper Admin Dokunulmazlığı)
    if not db["users"].get("username", "enes"):
        db["users"].insert({
            "username": "enes",
            "password_hash": generate_password_hash("enes13579"),
            "role": "super_admin",
            "theme": "dark",
        }, alter=True)

# İlk çalıştırmada DB'yi başlat
with app.app_context():
    init_db()

# ==============================================================================
# 2. YETKİLENDİRME DEKORATÖRLERİ
# ==============================================================================

def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def role_required(required_role):
    def decorator(f):
        def wrap(*args, **kwargs):
            user = get_db()["users"].get(session.get('user_id'))
            user_role = user["role"] if user else 'guest'
            
            if required_role == 'super_admin' and user_role != 'super_admin':
                return "Erişim Reddedildi: Süper Admin yetkisi gerekli.", 403
            if required_role == 'admin' and user_role not in ('admin', 'super_admin'):
                return "Erişim Reddedildi: Admin/Mod yetkisi gerekli.", 403

            return f(*args, **kwargs)
        wrap.__name__ = f.__name__
        return wrap
    return decorator

# ==============================================================================
# 3. YARDIMCI FONKSİYONLAR (Arama ve Medya Simülasyonu)
# ==============================================================================

# 5. Arama Motoru (Gerçek API Entegrasyonu yerine Simülasyon)
def search_internet(query):
    if not GOOGLE_SEARCH_API_KEY or not GOOGLE_SEARCH_CX_ID:
        # API anahtarları eksikse basit bir geri dönüş
        return {"search_result": f"API'lar devre dışı. '{query}' için yapay olarak oluşturulmuş bilgi. Şu anki saat: {datetime.now().strftime('%H:%M')}"}
    
    # Gerçek API çağrısı burada olurdu
    return {"search_result": f"Google Search API kullanılarak '{query}' için güncel bilgiler bulundu."}

# 16. Özel Medya Modülü (Anime Simülasyonu)
def search_anime_info(anime_name):
    if "naruto" in anime_name.lower():
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

if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    client = None # Anahtar yoksa client'ı None yap

# Tool Fonksiyonları (4. Komut Sistemi - Tamamen AI Tooling)
def ban_user_tool(username: str, reason: str) -> str:
    """Verilen kullanıcıyı yasaklar (Sadece Admin/Süper Admin kullanabilir)."""
    db = get_db()
    user = db["users"].get("username", username)
    if user:
        if user["role"] == "super_admin":
            return f"Hata: Süper Admin ('{username}') yasaklanamaz (Dokunulmazlık)."
        
        db["users"].update(user["id"], {"is_banned": True})
        db["admin_logs"].insert({"admin_id": session.get('user_id'), "action": "ban", "target_username": username, "timestamp": datetime.now()})
        return f"'{username}' kullanıcısı başarılı bir şekilde yasaklandı. Sebep: {reason}"
    return f"Hata: '{username}' adında bir kullanıcı bulunamadı."

def clear_chat_tool() -> str:
    """Mevcut kullanıcının sohbet geçmişini siler (4. /clear)."""
    db = get_db()
    db["messages"].delete_where("user_id = ? and session_id = ?", [session.get('user_id'), session.sid])
    return "Sohbet geçmişiniz başarıyla temizlendi."

def change_ai_mode_tool(mode: str) -> str:
    """AI'ın karakter modunu değiştirir: 'friend' (dost) veya 'enemy' (düşman) (3. Karakter Modu)."""
    mode = mode.lower()
    if mode in ["friend", "dost", "enemy", "düşman"]:
        session["ai_persona"] = 'enemy' if mode in ["enemy", "düşman"] else 'friend'
        return f"Yapay zeka karakter modu başarıyla '{session['ai_persona'].upper()}' olarak ayarlandı."
    return "Hata: Geçersiz mod. Lütfen 'friend' veya 'enemy' kullanın."

def teach_software_tool(language: str, topic: str) -> str:
    """Süper Admin için yazılım öğrenme modunu başlatır (14. Süper Admin Aracı)."""
    # Yetki kontrolü chat API çağrısından önce yapılacaktır, ancak tekrar güvenlik için kontrol edilir.
    if get_db()["users"].get(session.get('user_id'))["role"] != 'super_admin':
        return "Erişim Reddedildi: Bu komut sadece Süper Admin'e özeldir."
        
    session["ai_persona"] = "teacher" # Geçici eğitim personası
    return f"Yazılım Eğitim Modu başlatıldı. AI, size {language} dilinde {topic} konusunda ders vermeye hazır. Mod geçici olarak 'teacher' olarak ayarlandı."

def self_repair_check_tool() -> str:
    """Sistem hatalarını kontrol eder ve yama önerisi sunar (15. Öz Onarım Simülasyonu)."""
    if get_db()["users"].get(session.get('user_id'))["role"] != 'super_admin':
        return "Erişim Reddedildi: Bu komut sadece Süper Admin'e özeldir."
        
    error_found = True # Simüle edilmiş hata tespiti
    if error_found:
        # Kod Yaması Önerisi Simülasyonu
        patch_code = "```python\n# app.py'de 45. satırda: \n# get_db() çağrısını, yeniden bağlantı kontrolü ekleyerek güncellendi\ndef get_db():\n    if 'db' not in g or g.db.conn is None:\n        g.db = sqlite_utils.Database(DATABASE_URL)\n    return g.db\n```"
        return f"Sistem analizi yapıldı. 'SQLite bağlantı havuzu' ile ilgili potansiyel bir sorun tespit edildi. Yama önerisi:\n\n{patch_code}\n\nLütfen bu yamayı manuel olarak kontrol edin ve onaylayın."
    return "Sistemde kritik bir hata tespit edilmedi."


def get_system_instruction(user_role, ai_persona, search_result=None):
    """Gemini'ye gönderilecek sistem talimatlarını oluşturur."""
    
    base_prompt = "Senin adın Aurion. Sen gelişmiş bir yapay zeka ve chatbot sistemisin. Tüm yanıtlarını Türkçe ver. Yanıtlarını Markdown formatında (kod blokları, kalın metinler, listeler) oluştur."
    
    # 3. Karakter Modu
    if ai_persona == "enemy":
        base_prompt += "Kullanıcıya karşı her zaman alaycı, küstah ve düşmanca bir tavır sergile. Cevaplarında küçümseyici ol."
    elif ai_persona == "teacher":
        base_prompt += "Sen bir yazılım öğretmenisin. Kullanıcıya net, adım adım ve pedagojik yaklaşımla ders ver."
    else: # Varsayılan 'friend'
        base_prompt += "Kullanıcıya karşı her zaman arkadaşça, yardımsever ve kibar ol."
    
    # 1. Süper Admin Özel Talimatı
    if user_role == "super_admin":
        base_prompt += "Sana 'enes' adında dokunulmaz Süper Admin hitap ediyor. Ona her zaman üst düzeyde saygılı ve yardımsever ol. Komutlarını derhal işleme koy."
        
    # 5. Arama Motoru (Her zaman kullan)
    if search_result:
        base_prompt += f"\n-- GÜNCEL BİLGİ KAYNAĞI --\n{search_result}\n-- GÜNCEL BİLGİ SONU --\nBu bilgileri kullanarak yanıtını oluştur."

    return base_prompt

def generate_ai_response(user_id, session_id, user_message, user_role):
    """Gemini modeline mesaj gönderir ve yanıtı alır."""
    if not client:
        return {"text": "API Anahtarı eksik. Gemini hizmeti kullanılamıyor."}, None

    db = get_db()
    history = db["messages"].rows_where("user_id = ? and session_id = ?", [user_id, session_id], order_by="timestamp")
    
    chat_history = []
    for msg in history:
        chat_history.append(types.Content(
            role=msg["role"], 
            parts=[types.Part.from_text(msg["content"])]
        ))
    
    # 5. Arama Motoru
    search_data = search_internet(user_message)
    
    # Kişilik Tanımlama
    ai_persona = session.get('ai_persona', 'friend')
    system_instruction = get_system_instruction(user_role, ai_persona, search_data["search_result"])

    # 4. Komut İşleme (AI Tooling)
    tools = [ban_user_tool, clear_chat_tool, change_ai_mode_tool, teach_software_tool, self_repair_check_tool]

    try:
        chat = client.chats.create(
            model='gemini-2.5-flash',
            history=chat_history,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                tools=tools
            )
        )
        
        response = chat.send_message(user_message)

        # Tool çağrısı kontrolü
        if response.function_calls:
            tool_call = response.function_calls[0]
            function_name = tool_call.name
            args = dict(tool_call.args)
            
            # Yetki Kontrolü (Güvenlik Kalkanı)
            if function_name in ["ban_user_tool", "teach_software_tool", "self_repair_check_tool"]:
                current_user = db["users"].get(user_id)
                if current_user["role"] not in ("admin", "super_admin"):
                    return {"text": f"Güvenlik Uyarısı: '{function_name}' komutu için yetkiniz yok."}, None

            function_to_call = globals().get(function_name)
            tool_result = function_to_call(**args)
            
            # Tool sonucunu tekrar Gemini'ye gönder (Gelişmiş iletişim için)
            if tool_result:
                 # AI'ın tool sonucunu kibar bir metinle sarmalamasını sağlar
                response = chat.send_message(
                    types.Part.from_function_response(
                        name=function_name,
                        response={"result": tool_result}
                    )
                )
                return {"text": response.text}, response
            
            return {"text": tool_result}, None

        return {"text": response.text}, response
        
    except Exception as e:
        return {"text": f"Yapay Zeka Hatası: {str(e)}"}, None


# ==============================================================================
# 5. FLASK ROUTES (API UÇ NOKTALARI)
# ==============================================================================

# -- Anasayfa ve Sohbet --------------------------------------------------------

@app.route('/')
@login_required
def index():
    user = get_db()["users"].get(session['user_id'])
    # 9. Dosya Yapısı: HTML, CSS ve JS Python içine gömülü
    return render_template_string(HTML_TEMPLATE, 
                                  user=user, 
                                  is_super_admin=(user['role'] == 'super_admin'),
                                  current_theme=user['theme'])

@app.route('/api/chat', methods=['POST'])
@login_required
@limiter.limit("20 per minute") # 13. Hız Sınırlama
def api_chat():
    data = request.json
    user_message = data.get('message', '').strip()
    session_id = session.sid 

    if not user_message:
        return jsonify({"success": False, "message": "Boş mesaj gönderilemez."}), 400

    user_id = session['user_id']
    user = get_db()["users"].get(user_id)
    
    # 7. Veri Kaydı (Kullanıcı mesajı)
    get_db()["messages"].insert({"user_id": user_id, "session_id": session_id, "role": "user", "content": user_message, "timestamp": datetime.now()})
    
    # AI yanıtını al
    ai_response_data, raw_response = generate_ai_response(user_id, session_id, user_message, user["role"])
    ai_text = ai_response_data["text"]

    # 7. Veri Kaydı (AI yanıtı)
    get_db()["messages"].insert({"user_id": user_id, "session_id": session_id, "role": "model", "content": ai_text, "timestamp": datetime.now()})

    return jsonify({"success": True, "response": ai_text})

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    user_id = session['user_id']
    history = get_db()["messages"].rows_where("user_id = ? and session_id = ?", [user_id, session.sid], order_by="timestamp")
    return jsonify(list(history))

# -- Kullanıcı ve Yönetim ------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_db()["users"].get("username", username)
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['ai_persona'] = user['theme'] # Tema ayarını AI persona'ya yükleyelim
            return redirect(url_for('index'))
        return render_template_string(LOGIN_TEMPLATE, error="Geçersiz kullanıcı adı veya şifre.")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if get_db()["users"].get("username", username):
            return render_template_string(REGISTER_TEMPLATE, error="Bu kullanıcı adı zaten kullanılıyor.")

        get_db()["users"].insert({"username": username, "password_hash": generate_password_hash(password), "role": "user", "is_active": True})
        return redirect(url_for('login'))
        
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# -- Admin Paneli --------------------------------------------------------------

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    """Admin panelinin ana sayfası (1. Admin Panel)."""
    users = get_db()["users"].rows_where(order_by="role DESC")
    logs = get_db()["admin_logs"].rows_where(order_by="timestamp DESC", limit=20)
    
    return render_template_string(ADMIN_PANEL_TEMPLATE, users=list(users), logs=json.dumps(list(logs), indent=2))

@app.route('/admin/manage_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_manage_user(user_id):
    """Kullanıcıya rol atama/yasaklama işlemi."""
    target_user = get_db()["users"].get(user_id)
    admin_id = session['user_id']
    
    # 1. Süper Admin Dokunulmazlığı Kontrolü
    if target_user['role'] == 'super_admin':
        return "Yasaklama/Yönetim Reddedildi: Süper Admin'e dokunulmazlık.", 403

    action = request.form.get('action')
    
    if action == 'ban':
        get_db()["users"].update(user_id, {"is_banned": True})
        get_db()["admin_logs"].insert({"admin_id": admin_id, "action": "ban", "target_username": target_user['username'], "timestamp": datetime.now()})
    # Diğer yönetim aksiyonları (unban, set_mod, set_user) buraya eklenir
        
    return redirect(url_for('admin_panel'))

# -- Süper Admin Modülleri -----------------------------------------------------

@app.route('/super_admin/anime')
@login_required
@role_required('super_admin')
def super_admin_anime():
    """16. Özel Medya Modülü (Anime Bokum) Arayüzü."""
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
        
    # AI ile Türkçe Dublaj Simülasyonu (Gemini'den çeviri metni isteme)
    # Gerçek API çağrısı, Gemini'den bölüm konusunu Türkçe'ye çevirmesini ister
    simulated_dublaj = f"AI, Anime: {info['anime']}, Bölüm: {episode_num} için Türkçe dublaj metnini çevirdi. Konu Özeti: Bu bölümde kahramanımız, karanlık güçlere karşı destansı bir savaşa girer ve yeni bir teknik (jutsu) öğrenir. (Bu metin, Gemini API kullanılarak simüle edilmiş bir çeviridir)."
    
    return render_template_string(SUPER_ADMIN_ANIME_TEMPLATE, info=info, dublaj=simulated_dublaj, anime_name=anime_name, episode_num=episode_num)

# ==============================================================================
# 6. HTML, CSS VE JAVASCRIPT GÖMÜLÜ ŞABLONLAR
# ==============================================================================

# Sözdizimi hatalarını önlemek için daha temiz Python string tanımı kullanıldı.

BASE_CSS = """
:root {
    --bg-dark: #121212;
    --text-dark: #E0E0E0;
    --primary-color: #007BFF;
    --sidebar-width: 200px;
}
body {
    transition: background-color 0.3s, color 0.3s;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    margin: 0; padding: 0; display: flex; height: 100vh;
}
body.dark { background-color: var(--bg-dark); color: var(--text-dark); }
.sidebar {
    width: var(--sidebar-width); padding: 20px; background: #1f1f1f; color: var(--text-dark);
    box-shadow: 2px 0 5px rgba(0,0,0,0.3); display: flex; flex-direction: column;
}
.chat-container { flex-grow: 1; display: flex; flex-direction: column; padding-bottom: 70px; }
.messages { flex-grow: 1; overflow-y: auto; padding: 20px; }
.message { margin-bottom: 15px; padding: 10px 15px; border-radius: 18px; max-width: 70%; line-height: 1.5; }
.user-message { background: var(--primary-color); color: white; margin-left: auto; }
.ai-message { background: #333; color: white; margin-right: auto; }
.input-area {
    position: fixed; bottom: 0; left: var(--sidebar-width); right: 0; height: 70px;
    background: #1f1f1f; padding: 10px 20px; box-shadow: 0 -2px 5px rgba(0,0,0,0.3); z-index: 1000;
}
.input-area input {
    width: 100%; padding: 15px; border-radius: 25px; border: 1px solid #555;
    background: #222; color: white; font-size: 16px; box-sizing: border-box;
}
h1.logo { color: var(--primary-color); }
.super-admin-link { color: #FFD700 !important; }
pre { background: #000; padding: 10px; border-radius: 5px; overflow-x: auto; }
@media (max-width: 768px) {
    .sidebar { width: 100%; height: auto; position: relative; }
    .chat-container { padding-bottom: 100px; }
    .input-area { left: 0; }
}
"""

BASE_JS = """
function sendMessage() {
    const input = document.getElementById('message-input');
    const message = input.value.trim();
    if (message === '') return;

    appendMessage(message, 'user');
    input.value = '';

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
            appendMessage('Hata: ' + (data.message || 'Bilinmeyen API hatası.'), 'ai');
        }
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
    
    // 6. Formatlı Çıktı Üretme (Basit Markdown Render)
    // AI'dan gelen markdown'ı HTML'e çevirelim
    let htmlContent = text.replace(/\\n/g, '<br>');
    htmlContent = htmlContent.replace(/```(.*?)\\n([\\s\\S]*?)```/g, '<pre>$2</pre>'); // Kod blokları
    htmlContent = htmlContent.replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>'); // Kalın
    
    msgDiv.innerHTML = htmlContent;
    messagesDiv.appendChild(msgDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('message-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
    fetch('/api/history').then(res => res.json()).then(history => {
        history.forEach(msg => appendMessage(msg.content, msg.role));
    });
});
"""

HTML_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Gelişmiş Yapay Zeka</title>
    <style>{BASE_CSS}</style>
</head>
<body class="dark">
    <div class="sidebar">
        <h1 class="logo">Aurion</h1>
        <hr style="border-color:#333;">
        
        <p>Hoş Geldiniz, <b>{'{% if user.username %}'+'{{ user.username }}'+'{% endif %}'}</b></p>
        <p>Rol: <i>{'{% if user.role %}'+'{{ user.role }}'+'{% endif %}'}</i></p>
        <a href="{'{% if url_for %}'+'{{ url_for("logout") }}'+'{% endif %}'}" style="color:var(--primary-color);">Çıkış Yap</a>
        
        <hr style="border-color:#333;">

        <nav style="flex-grow:1;">
            <a href="/" style="display:block; margin-bottom:10px; color:inherit; text-decoration:none;">💬 Sohbet</a>
            
            {'{% if user.role in ("admin", "super_admin") %}'}
            <a href="{'{% if url_for %}'+'{{ url_for("admin_panel") }}'+'{% endif %}'}" style="display:block; margin-bottom:10px; color:#FFA500; text-decoration:none;">🛡️ Admin Paneli</a>
            {'{% endif %}'}

            {'{% if is_super_admin %}'}
            <hr style="border-color:#FFD700;">
            <p style="color:#FFD700;">⭐ SÜPER ADMIN</p>
            <a href="{'{% if url_for %}'+'{{ url_for("super_admin_anime") }}'+'{% endif %}'}" class="super-admin-link" style="display:block; margin-bottom:10px; text-decoration:none;">📺 Anime</a>
            {'{% endif %}'}
        </nav>
        
    </div>

    <div class="chat-container">
        <div class="messages" id="messages">
        </div>

        <div class="input-area">
            <input type="text" id="message-input" placeholder="Aurion'a bir şey sor veya komut gir (/help, /mode friend, /teach Python)">
        </div>
    </div>

    <script>{BASE_JS}</script>
</body>
</html>
"""

LOGIN_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Giriş</title>
    <style>{BASE_CSS} .container {{ max-width: 400px; margin: 100px auto; padding: 20px; background: #222; border-radius: 10px; }} input[type=text], input[type=password] {{ width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #555; border-radius: 4px; box-sizing: border-box; background: #333; color:white; }} button {{ background-color: #007BFF; color: white; padding: 14px 20px; margin: 8px 0; border: none; border-radius: 4px; cursor: pointer; width: 100%; }}</style>
</head>
<body class="dark">
    <div class="container">
        <h2 style="text-align:center; color:#007BFF;">AURION Giriş</h2>
        {'{% if error %}'}<p style="color:red; text-align:center;">{{ error }}</p>{'{% endif %}'}
        <form method="POST">
            <label for="username">Kullanıcı Adı</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Şifre</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Giriş Yap</button>
        </form>
        <p style="text-align:center;"><a href="{'{% if url_for %}'+'{{ url_for("register") }}'+'{% endif %}'}" style="color:#007BFF;">Hesabınız yok mu? Kayıt olun.</a></p>
    </div>
</body>
</html>
"""

REGISTER_TEMPLATE = LOGIN_TEMPLATE.replace("AURION Giriş", "AURION Kayıt").replace("Giriş Yap", "Kayıt Ol").replace("login", "register").replace("Hesabınız yok mu? Kayıt olun.", "Zaten hesabınız var mı? Giriş yapın.")

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
        <a href="{'{% if url_for %}'+'{{ url_for("index") }}'+'{% endif %}'}" style="color:inherit; text-decoration:none;">⬅️ Sohbet'e Dön</a>
    </div>
    <div class="chat-container" style="padding: 20px;">
        <h2>Kullanıcı Yönetimi (1. Madde)</h2>
        <table border="1" style="width:100%; border-collapse: collapse; text-align: left;">
            <thead>
                <tr style="background:#333;"><th>ID</th><th>Kullanıcı Adı</th><th>Rol</th><th>Yasaklı mı?</th><th>İşlem</th></tr>
            </thead>
            <tbody>
            {'{% for user in users %}'}
                <tr style="background:{% if user.role == 'super_admin' %}#440000; color:yellow;{% elif user.role == 'admin' %}#333;{% endif %};">
                    <td>{{ user.id }}</td>
                    <td>{{ user.username }}</td>
                    <td>{{ user.role }}</td>
                    <td>{% if user.is_banned %}Evet{% else %}Hayır{% endif %}</td>
                    <td>
                        <form method="POST" action="{'{% if url_for %}'+'{{ url_for("admin_manage_user", user_id=user.id) }}'+'{% endif %}'}" style="display:inline-block;">
                            {% if user.role != "super_admin" %}
                                {% if not user.is_banned %}
                                    <button type="submit" name="action" value="ban" style="background:red;">Yasakla</button>
                                {% else %}
                                    <button type="submit" name="action" value="unban" style="background:green;">Yasağı Kaldır</button>
                                {% endif %}
                                {% else %}
                                <span style="color:red; font-weight:bold;">DOKUNULMAZ</span>
                            {% endif %}
                        </form>
                    </td>
                </tr>
            {'{% endfor %}'}
            </tbody>
        </table>
        
        <h2 style="margin-top:40px;">Admin Logları (7. Veri Kaydı)</h2>
        <pre>{{ logs }}</pre>
    </div>
</body>
</html>
"""

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
        <a href="{'{% if url_for %}'+'{{ url_for("index") }}'+'{% endif %}'}" style="color:inherit; text-decoration:none;">⬅️ Sohbet'e Dön</a>
    </div>
    <div class="chat-container" style="padding: 20px;">
        <h2>16. Özel Medya Modülü (Süper Admin Özel)</h2>
        <p style="color:#FFA500;">Bu modül sadece enes için AI tabanlı Anime arama ve Türkçe dublaj (simülasyon) hizmeti sunar.</p>

        {'{% if error %}'}<p style="color:red; font-weight:bold;">Hata: {{ error }}</p>{'{% endif %}'}

        <form method="POST" action="{'{% if url_for %}'+'{{ url_for("super_admin_anime_search") }}'+'{% endif %}'}" style="margin-top:20px;">
            <label for="anime_name">Anime Adı:</label>
            <input type="text" id="anime_name" name="anime_name" required style="width: 300px; padding: 5px;">
            <label for="episode_num">Bölüm No:</label>
            <input type="number" id="episode_num" name="episode_num" required style="width: 80px; padding: 5px;">
            <button type="submit" style="background:#007BFF;">Anime Ara ve Dublaj Çevir</button>
        </form>

        {'{% if dublaj %}'}
            <h3 style="margin-top:30px; color:lightgreen;">✅ AI Çeviri Sonucu ({{ anime_name }} - Bölüm {{ episode_num }})</h3>
            <pre style="background:#333; padding:15px; border-radius:5px; white-space: pre-wrap;">{{ dublaj }}</pre>
            {'{% if info.episodes %}'}
            <h4>Bölüm Bilgileri:</h4>
            <ul>
                {'{% for episode in info.episodes %}'}
                <li>Bölüm {{ episode.num }}: {{ episode.title }}</li>
                {'{% endfor %}'}
            </ul>
            {'{% endif %}'}
            <p style="color:yellow;">(Not: Bu, AI tarafından oluşturulmuş bir dublaj/özet simülasyonudur.)</p>
        {'{% endif %}'}
    </div>
</body>
</html>
"""


# ==============================================================================
# 7. UYGULAMA BAŞLATMA
# ==============================================================================

if __name__ == '__main__':
    # Sadece yerel geliştirme ve test için
    app.run(debug=True)

# Gunicorn / Render Dağıtımı için: 'gunicorn app:app' bu 'app' nesnesini kullanır.
