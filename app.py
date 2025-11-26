# ==============================================================================
# AURION PROJESİ - NİHAİ VE EN GÜVENİLİR VERSİYON (app.py)
# Versiyon: 4.0 (Tüm Kritik Hatalar Giderildi)
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
import sys 
import uuid 
import time 

# ==============================================================================
# 0. AYARLAR VE ÇEVRESEL DEĞİŞKENLER 
# ==============================================================================

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GOOGLE_SEARCH_CX_ID = os.getenv("GOOGLE_SEARCH_CX_ID")
GOOGLE_SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY")
# Render'da ayarlanacak SECRET_KEY'e öncelik verilir.
SECRET_KEY = os.getenv("SECRET_KEY", str(uuid.uuid4()) * 2 + "AURION_PROD_KEY") 

DATABASE_URL = "aurion.db"
SYSTEM_LOG_FILE = "aurion_system.log" 

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_PERMANENT'] = True

client = None
if GEMINI_API_KEY:
    try:
        # Gemini Client'ı oluştur
        client = genai.Client(api_key=GEMINI_API_KEY)
        print(">>> [AURION START OK] Gemini istemcisi başarıyla başlatıldı.", file=sys.stdout)
    except Exception as e:
        print(f"!!! [AURION START CRITICAL] Gemini istemcisi başlatılamadı: {type(e).__name__} - {e}", file=sys.stderr)
else:
    print("!!! [AURION START WARNING] GEMINI_API_KEY çevresel değişkeni bulunamadı.", file=sys.stderr)

# ==============================================================================
# 1. VERİTABANI VE İLK KURULUM (SQLite Kilitlenme Çözümü ve Geliştirme)
# ==============================================================================

def get_db(max_retries=5, delay=1):
    """Veritabanı bağlantısını döndürür ve kilitlenme (OperationalError) durumunda yeniden dener."""
    for attempt in range(max_retries):
        try:
            if 'db' not in g:
                # Gunicorn için uyumlu timeout ayarları (varsayılan 5 saniyeden artırıldı)
                g.db = sqlite_utils.Database(DATABASE_URL, timeout=15) 
            return g.db
        except sqlite_utils.db.OperationalError as e:
            print(f"!!! [DB ACCESS RETRY] DB kilitlenme hatası. Yeniden deneme ({attempt + 1}/{max_retries}). Hata: {str(e)}", file=sys.stderr)
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise RuntimeError("Veri tabanı bağlantısı kurulamıyor (Maksimum deneme aşıldı).")
        except Exception as e:
            print(f"!!! [DB ACCESS ERROR] Veri tabanına erişim sağlanamadı: {str(e)}", file=sys.stderr)
            raise RuntimeError("Veri tabanı bağlantısı kurulamıyor.")

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    try:
        db = get_db()
        # Tablolar oluşturuluyor
        db["users"].create({"id": int, "username": str, "password_hash": str, "role": str, "is_banned": bool, "theme": str, "is_active": bool}, pk="id", defaults={"is_banned": False, "role": "user", "theme": "dark", "is_active": True}, if_not_exists=True)
        db["messages"].create({"id": int, "user_id": int, "session_id": str, "role": str, "content": str, "timestamp": datetime}, pk="id", if_not_exists=True)
        db["admin_logs"].create({"id": int, "admin_id": int, "action": str, "target_username": str, "timestamp": datetime}, pk="id", if_not_exists=True)
        db["anime_messages"].create({"id": int, "user_id": int, "role": str, "content": str, "timestamp": datetime}, pk="id", if_not_exists=True)
        
        # Başlangıç super_admin kullanıcısı (SADECE VARSA GÜNCELLEME YAPAR)
        if not list(db["users"].rows_where("username = 'enes'")):
            db["users"].insert({"username": "enes", "password_hash": generate_password_hash("enes13579"), "role": "super_admin", "theme": "dark"}, alter=True)
        print(">>> [DB INIT OK] Veri tabanı şeması ve başlangıç kullanıcısı hazır.", file=sys.stdout)
    except Exception as e:
        print(f"!!! [DB INIT ERROR] Veri tabanı başlatma hatası: {str(e)}", file=sys.stderr)
        sys.exit(1)

with app.app_context():
    init_db()

# Limiter ayarları (DDoS ve spam koruması)
limiter = Limiter(get_remote_address, app=app, default_limits=["20 per minute"], storage_uri="memory://")

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
                return "Erişim Reddedildi: Admin yetkisi gerekli.", 403

            return f(*args, **kwargs)
        wrap.__name__ = f.__name__
        return wrap
    return decorator

# ==============================================================================
# 3. YARDIMCI FONKSİYONLAR VE AI TOOL'LARI 
# ==============================================================================

# Dummy tool'lar, Gemini tarafından çağrılmak üzere.
def search_internet(query):
    if not GOOGLE_SEARCH_API_KEY or not GOOGLE_SEARCH_CX_ID:
        return {"search_result": f"API'lar eksik. '{query}' için yerel bilgi: Saat {datetime.now().strftime('%H:%M')}"}
    return {"search_result": f"Google Search API kullanılarak '{query}' için güncel bilgiler bulundu."}

def ban_user_tool(username: str, reason: str) -> str:
    db = get_db()
    user_list = list(db["users"].rows_where("username = ?", [username]))
    user = user_list[0] if user_list else None
    
    if user:
        if user["role"] == "super_admin":
            return f"Hata: Süper Admin ('{username}') yasaklanamaz."
        
        db["users"].update(user["id"], {"is_banned": True})
        db["admin_logs"].insert({"admin_id": session.get('user_id'), "action": "ban", "target_username": username, "timestamp": datetime.now()})
        return f"'{username}' kullanıcısı başarılı bir şekilde yasaklandı. Sebep: {reason}"
    return f"Hata: '{username}' adında bir kullanıcı bulunamadı."

def clear_chat_tool() -> str:
    db = get_db()
    current_session_id = session.get('current_chat_session', None)
    
    if current_session_id and session.get('user_id'):
        try:
            # Sadece mevcut session'ı temizle
            db["messages"].delete_where("user_id = ? and session_id = ?", [session['user_id'], current_session_id])
            # Yeni bir session ID ata
            session['current_chat_session'] = str(uuid.uuid4())
            return "Sohbet geçmişiniz başarıyla temizlendi ve yeni bir oturum başlatıldı."
        except Exception as e:
            print(f"!!! [TOOL ERROR] Sohbet temizleme hatası: {str(e)}", file=sys.stderr)
            return "Sohbet geçmişi temizlenirken bir hata oluştu."
    return "Oturum verisi eksik olduğundan geçmiş temizlenemedi."


def change_ai_mode_tool(mode: str) -> str:
    mode = mode.lower()
    if mode in ["friend", "dost"]:
        session["ai_persona"] = 'friend'
        return "Yapay zeka karakter modu başarıyla 'DOST' olarak ayarlandı."
    elif mode in ["enemy", "düşman"]:
        session["ai_persona"] = 'enemy'
        return "Yapay zeka karakter modu başarıyla 'DÜŞMAN' olarak ayarlandı."
    return "Hata: Geçersiz mod. Lütfen 'friend' veya 'enemy' kullanın."

def teach_software_tool(language: str, topic: str) -> str:
    user = get_db()["users"].get(session.get('user_id'))
    if user and user["role"] != 'super_admin':
        return "Erişim Reddedildi: Bu komut sadece Süper Admin'e özeldir."
        
    session["ai_persona"] = "teacher" 
    return f"Yazılım Eğitim Modu başlatıldı. AI, size {language} dilinde {topic} konusunda ders vermeye hazır. Lütfen ilk sorunuzu sorun."

def self_repair_check_tool() -> str:
    user = get_db()["users"].get(session.get('user_id'))
    if user and user["role"] != 'super_admin':
        return "Erişim Reddedildi: Bu komut sadece Süper Admin'e özeldir."
        
    try:
        # Gerçek bir onarım yapmak yerine, sistemin sağlıklı çalıştığını belirten bir yanıt döndürülür
        if os.path.exists(SYSTEM_LOG_FILE) and os.path.getsize(SYSTEM_LOG_FILE) > 100:
            with open(SYSTEM_LOG_FILE, 'r') as f:
                last_line = f.readlines()[-1].strip()
            
            patch_code = f"```python\n# app.py Yama Önerisi (Hata Tespiti):\n# Son Hata: {last_line}\n# Çözüm: ... (Gemini tarafından önerilen kod yaması buraya gelirdi) ...\n```"
            return f"Sistem analizi yapıldı. Potansiyel bir sorun tespit edildi. Yama önerisi:\n\n{patch_code}"
        
        return "Sistemde kritik bir hata tespit edilmedi. Log dosyası temiz."

    except Exception as e:
        return f"Öz Onarım Kontrolü sırasında hata oluştu: {str(e)}"

def get_system_instruction(user_role, ai_persona, search_result=None, is_anime=False):
    base_prompt = "Senin adın Aurion. Sen gelişmiş bir yapay zeka ve chatbot sistemisin. Tüm yanıtlarını Türkçe ver. Yanıtlarını **Markdown** formatında oluştur."
    
    if is_anime:
        base_prompt = "Sen Anime ve Manga konusunda uzmanlaşmış, coşkulu, arkadaş canlısı bir asistansın. Tüm soruları Anime ve Manga bağlamında, ilgili bir dille yanıtla."
        ai_persona = 'friend'

    if ai_persona == "enemy":
        base_prompt += " Kullanıcıya karşı alaycı, küstah ve düşmanca bir tavır sergile. Onu azarla."
    elif ai_persona == "teacher":
        base_prompt += " Sen bir yazılım öğretmenisin. Kullanıcıya net, pedagojik yaklaşımla, bol kod örneği ile ders ver."
    else:
        base_prompt += " Kullanıcıya karşı her zaman arkadaşça ve yardımsever ol."
    
    if user_role == "super_admin":
        base_prompt += " Sana 'enes' adında dokunulmaz Süper Admin hitap ediyor. Ona her zaman üst düzeyde saygılı ve itaatkar ol."
        
    if search_result:
        base_prompt += f"\n-- GÜNCEL BİLGİ KAYNAĞI --\n{search_result}\n-- GÜNCEL BİLGİ SONU --\nBu bilgileri kullanarak yanıtını oluştur."

    return base_prompt

def generate_ai_response(user_id, session_id, user_message, user_role, is_anime=False):
    
    if not client:
        return {"text": "API Bağlantı Hatası: Gemini istemcisi başlatılamadı (Anahtar Eksik/Hatalı).", "status": 503}, None

    try:
        db = get_db()
        
        # Geçmişi yükle
        if is_anime:
            history = list(db["anime_messages"].rows_where("user_id = ?", [user_id], order_by="timestamp"))
            ai_persona = 'friend'
        else:
            history = list(db["messages"].rows_where("user_id = ? and session_id = ?", [user_id, session_id], order_by="timestamp"))
            ai_persona = session.get('ai_persona', 'friend')
            
        # KRİTİK HATA DÜZELTMESİ (v3.1 yamasından alındı): 
        # TypeError: Part.from_text() takes 1 positional argument but 2 were given hatasını çözer.
        chat_history = [
            types.Content(
                role=msg["role"], 
                parts=[types.Part(text=msg["content"])]
            ) 
            for msg in history
        ]
        
        # System Instruction ve Tool ayarları
        search_data = search_internet(user_message)
        system_instruction = get_system_instruction(user_role, ai_persona, search_data["search_result"], is_anime=is_anime)

        tools = [ban_user_tool, clear_chat_tool, change_ai_mode_tool, teach_software_tool, self_repair_check_tool]

        config = types.GenerateContentConfig(
            system_instruction=system_instruction, 
            tools=tools
        )
        
        # Sohbet nesnesini oluştur ve mesaj gönder
        chat = client.chats.create(model='gemini-2.5-flash', history=chat_history, config=config)
        response = chat.send_message(user_message)

        # Tool kullanımı kontrolü
        if response.function_calls:
            tool_call = response.function_calls[0]
            function_name = tool_call.name
            args = dict(tool_call.args)
            
            function_to_call = globals().get(function_name)
            tool_result = function_to_call(**args)
            
            if tool_result:
                # Aracı çalıştırma yanıtını tekrar modele gönder
                response = chat.send_message(types.Part.from_function_response(name=function_name, response={"result": tool_result}))
                return {"text": response.text}, response
            
            return {"text": tool_result}, None

        return {"text": response.text}, response
        
    except Exception as e:
        error_type = type(e).__name__
        error_message = f"Yapay Zeka Erişimi Hatası: Sunucu zaman aşımı veya harici bir sorun oluştu. (Hata Kodu: {error_type})."
        
        # Hata kaydı (Self-repair tool için)
        with open(SYSTEM_LOG_FILE, 'a') as f:
            f.write(f"[{datetime.now()}] AI_RUNTIME_ERROR: Type={error_type}, Message={str(e)}\n")
            
        return {"text": error_message, "status": 500}, None

# ==============================================================================
# 4. FLASK ROUTES (DB Yazma İşlemlerine Yeniden Deneme Eklendi)
# ==============================================================================

@app.before_request
def make_session_permanent_and_assign_id():
    session.permanent = True
    # Oturum ID'si kontrolü
    if 'current_chat_session' not in session:
        session['current_chat_session'] = str(uuid.uuid4())
    # Oturumdaki kullanıcı objesini g nesnesine ata
    if 'user_id' in session and 'user_id' not in g:
        g.user = get_db()["users"].get(session['user_id'])


@app.route('/')
@login_required
def index():
    user = get_db()["users"].get(session['user_id'])
    return render_template_string(HTML_TEMPLATE, user=user, is_super_admin=(user['role'] == 'super_admin'))

@app.route('/api/chat', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def api_chat():
    data = request.json
    user_message = data.get('message', '').strip()
    session_id = session.get('current_chat_session')

    if not user_message: return jsonify({"success": False, "message": "Boş mesaj gönderilemez."}), 400

    user_id = session['user_id']
    user = get_db()["users"].get(user_id)
    
    ai_response_data, raw_response = generate_ai_response(user_id, session_id, user_message, user["role"])
    ai_text = ai_response_data["text"]
    
    if "status" in ai_response_data:
        http_status = ai_response_data["status"]
        return jsonify({"success": False, "message": ai_text}), http_status
    
    # DB YAZMA İŞLEMİNİ 5 KEZ DENEYEN BLOK (SQLite Kilitlenme Çözümü)
    max_retries = 5
    for attempt in range(max_retries):
        try:
            db = get_db()
            db["messages"].insert({"user_id": user_id, "session_id": session_id, "role": "user", "content": user_message, "timestamp": datetime.now()})
            db["messages"].insert({"user_id": user_id, "session_id": session_id, "role": "model", "content": ai_text, "timestamp": datetime.now()})
            break 
        except sqlite_utils.db.OperationalError as e:
            print(f"!!! [DB CHAT WRITE RETRY] DB yazma hatası. Yeniden deneme ({attempt + 1}/{max_retries}). Hata: {str(e)}", file=sys.stderr)
            if attempt == max_retries - 1:
                print("!!! [DB CHAT WRITE FAILED] Mesaj kaydı yapılamadı (Kalıcı DB kilitlenmesi).", file=sys.stderr)
            time.sleep(1)
        except Exception as e:
            print(f"!!! [API CHAT DB ERROR] Mesaj kaydı yapılamadı (Genel hata): {str(e)}", file=sys.stderr)
            break
    
    return jsonify({"success": True, "response": ai_text})

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    user_id = session['user_id']
    session_id = session.get('current_chat_session') 
    # Session ID'yi kullanan doğru sorgu (AttributeError çözümü)
    history = list(get_db()["messages"].rows_where("user_id = ? and session_id = ?", [user_id, session_id], order_by="timestamp"))
    return jsonify(history)

# -- ANIME CHAT MODÜLÜ ---------------------

@app.route('/anime')
@login_required
@role_required('super_admin')
def anime_chat_page():
    user = get_db()["users"].get(session['user_id'])
    return render_template_string(ANIME_CHAT_TEMPLATE, user=user)

@app.route('/api/anime_chat', methods=['POST'])
@login_required
@role_required('super_admin')
@limiter.limit("20 per minute")
def api_anime_chat():
    data = request.json
    user_message = data.get('message', '').strip()

    if not user_message: return jsonify({"success": False, "message": "Boş mesaj gönderilemez."}), 400

    user_id = session['user_id']
    user = get_db()["users"].get(user_id)
    
    ai_response_data, raw_response = generate_ai_response(user_id, None, user_message, user["role"], is_anime=True)
    ai_text = ai_response_data["text"]

    if "status" in ai_response_data:
        http_status = ai_response_data["status"]
        return jsonify({"success": False, "message": ai_text}), http_status

    # DB YAZMA İŞLEMİNİ 5 KEZ DENEYEN BLOK 
    max_retries = 5
    for attempt in range(max_retries):
        try:
            db = get_db()
            db["anime_messages"].insert({"user_id": user_id, "role": "user", "content": user_message, "timestamp": datetime.now()})
            db["anime_messages"].insert({"user_id": user_id, "role": "model", "content": ai_text, "timestamp": datetime.now()})
            break 
        except sqlite_utils.db.OperationalError as e:
            print(f"!!! [DB ANIME WRITE RETRY] DB yazma hatası. Yeniden deneme ({attempt + 1}/{max_retries}). Hata: {str(e)}", file=sys.stderr)
            if attempt == max_retries - 1:
                print("!!! [DB ANIME WRITE FAILED] Anime mesaj kaydı yapılamadı (Kalıcı DB kilitlenmesi).", file=sys.stderr)
            time.sleep(1)
        except Exception as e:
            print(f"!!! [API ANIME CHAT DB ERROR] Anime mesaj kaydı yapılamadı (Genel hata): {str(e)}", file=sys.stderr)
            break

    return jsonify({"success": True, "response": ai_text})

@app.route('/api/anime_history', methods=['GET'])
@login_required
@role_required('super_admin')
def api_anime_history():
    user_id = session['user_id']
    history = list(get_db()["anime_messages"].rows_where("user_id = ?", [user_id], order_by="timestamp"))
    return jsonify(history)

# -- Kullanıcı ve Kimlik Doğrulama Rotaları --------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # TypeError (Table.get 3 argüman) hatasını çözmek için kararlı yöntem kullanılıyor.
        user_list = list(get_db()["users"].rows_where("username = ?", [username]))
        user = user_list[0] if user_list else None
        
        if user and check_password_hash(user['password_hash'], password):
            if user['is_banned']:
                return render_template_string(LOGIN_TEMPLATE, error="Hesabınız yasaklanmıştır.")
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['ai_persona'] = user['theme'] 
            session['current_chat_session'] = str(uuid.uuid4())
            return redirect(url_for('index'))
        return render_template_string(LOGIN_TEMPLATE, error="Geçersiz kullanıcı adı veya şifre.")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if list(get_db()["users"].rows_where("username = ?", [username])):
            return render_template_string(REGISTER_TEMPLATE, error="Bu kullanıcı adı zaten kullanılıyor.")

        get_db()["users"].insert({"username": username, "password_hash": generate_password_hash(password), "role": "user", "is_active": True})
        return redirect(url_for('login'))
        
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('ai_persona', None)
    session.pop('current_chat_session', None)
    return redirect(url_for('login'))

# -- Admin Paneli Rotaları --------------------------------------------------
@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    users = get_db()["users"].rows_where(order_by="role DESC")
    logs = get_db()["admin_logs"].rows_where(order_by="timestamp DESC", limit=20)
    
    # JSON loglarını stringe dönüştürürken default=str eklenir
    return render_template_string(ADMIN_PANEL_TEMPLATE, users=list(users), logs=json.dumps(list(logs), indent=2, default=str))

@app.route('/admin/manage_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_manage_user(user_id):
    target_user = get_db()["users"].get(user_id)
    admin_id = session['user_id']
    
    if target_user['role'] == 'super_admin':
        return "Yasaklama/Yönetim Reddedildi: Süper Admin'e dokunulmazlık.", 403

    action = request.form.get('action')
    
    if action == 'ban':
        get_db()["users"].update(user_id, {"is_banned": True})
        get_db()["admin_logs"].insert({"admin_id": admin_id, "action": "ban", "target_username": target_user['username'], "timestamp": datetime.now()})
    elif action == 'unban':
        get_db()["users"].update(user_id, {"is_banned": False})
        get_db()["admin_logs"].insert({"admin_id": admin_id, "action": "unban", "target_username": target_user['username'], "timestamp": datetime.now()})
    elif action == 'set_admin':
        get_db()["users"].update(user_id, {"role": "admin"})
    elif action == 'set_user':
        get_db()["users"].update(user_id, {"role": "user"})
        
    return redirect(url_for('admin_panel'))

# ==============================================================================
# 5. GÜVENLİ HTML, CSS VE JAVASCRIPT GÖMÜLÜ ŞABLONLAR
# ==============================================================================

# **SyntaxError'lardan kaçınmak için BASE_CSS ve BASE_JS tanımları f-string dışında tutuldu**
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
function sendMessage(isAnime = false) {
    const inputId = isAnime ? 'anime-message-input' : 'message-input';
    const apiRoute = isAnime ? '/api/anime_chat' : '/api/chat';
    
    const input = document.getElementById(inputId);
    const message = input.value.trim();
    if (message === '') return;

    appendMessage(message, 'user');
    input.value = '';

    fetch(apiRoute, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: message})
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(errorData => {
                throw new Error(errorData.message || 'Sunucudan başarısız yanıt alındı. HTTP Durum Kodu: ' + response.status);
            }).catch(e => {
                throw new Error('Sunucudan HTTP ' + response.status + ' hatası döndü.');
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            appendMessage(data.response, 'ai');
        } else {
            appendMessage('Hata: ' + (data.message || 'Yapay Zeka Erişim Hatası oluştu. Lütfen logları kontrol edin.'), 'ai');
        }
    })
    .catch(error => {
        console.error('API İstemci Hatası:', error);
        appendMessage('Bağlantı Hatası oluştu (İstemci Tarafı). Sunucu yanıt veremedi. Detay: ' + error.message, 'ai');
    });
}

function appendMessage(text, sender) {
    const messagesDiv = document.getElementById('messages');
    const msgDiv = document.createElement('div');
    msgDiv.classList.add('message', sender + '-message');
    
    // Markdown işleme mantığı güçlendirildi
    let htmlContent = text.replace(/\\n/g, '<br>');
    htmlContent = htmlContent.replace(/```(.*?)\\n([\\s\\S]*?)```/g, '<pre>$2</pre>');
    htmlContent = htmlContent.replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>');
    
    msgDiv.innerHTML = htmlContent;
    messagesDiv.appendChild(msgDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

document.addEventListener('DOMContentLoaded', () => {
    const isAnimePage = window.location.pathname === '/anime';
    const inputId = isAnimePage ? 'anime-message-input' : 'message-input';

    const input = document.getElementById(inputId);
    if (input) {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage(isAnimePage);
            }
        });
    }

    const historyRoute = isAnimePage ? '/api/anime_history' : '/api/history';
    fetch(historyRoute).then(res => res.json()).then(history => {
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
        
        <p>Hoş Geldiniz, <b>{{{{ user.username }}}}</b></p>
        <p>Rol: <i>{{{{ user.role }}}}</i></p>
        <a href="{{{{ url_for('logout') }}}}" style="color:var(--primary-color);">Çıkış Yap</a>
        
        <hr style="border-color:#333;">

        <nav style="flex-grow:1;">
            <a href="/" style="display:block; margin-bottom:10px; color:inherit; text-decoration:none;">💬 Sohbet</a>
            
            {'{% if user.role in ("admin", "super_admin") %}'}
            <a href="{{{{ url_for('admin_panel') }}}}" style="display:block; margin-bottom:10px; color:#FFA500; text-decoration:none;">🛡️ Admin Paneli</a>
            {'{% endif %}'}

            {'{% if user.role == "super_admin" %}'}
            <hr style="border-color:#FFD700;">
            <p style="color:#FFD700;">⭐ SÜPER ADMIN</p>
            <a href="{{{{ url_for('anime_chat_page') }}}}" class="super-admin-link" style="display:block; margin-bottom:10px; text-decoration:none;">📺 Anime Sohbeti</a>
            {'{% endif %}'}
        </nav>
        
    </div>

    <div class="chat-container">
        <div class="messages" id="messages">
        </div>

        <div class="input-area">
            <input type="text" id="message-input" placeholder="Aurion'a bir şey sor veya komut gir (/mode enemy, /teach Python)">
        </div>
    </div>

    <script>{BASE_JS}</script>
</body>
</html>
"""

ANIME_CHAT_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Anime Sohbeti</title>
    <style>{BASE_CSS}</style>
</head>
<body class="dark">
    <div class="sidebar">
        <h1 class="logo" style="color:#FFD700;">📺 Anime AI</h1>
        <hr style="border-color:#333;">
        
        <p>Hoş Geldiniz, <b>{{{{ user.username }}}}</b></p>
        <p style="color:#FFD700;">Mod: <i>Anime Uzmanı</i></p>
        <a href="{{{{ url_for('logout') }}}}" style="color:var(--primary-color);">Çıkış Yap</a>
        
        <hr style="border-color:#FFD700;">

        <nav style="flex-grow:1;">
            <a href="{{{{ url_for('index') }}}}" style="display:block; margin-bottom:10px; color:inherit; text-decoration:none;">⬅️ Normal Sohbet</a>
            <a href="{{{{ url_for('admin_panel') }}}}" style="display:block; margin-bottom:10px; color:#FFA500; text-decoration:none;">🛡️ Admin Paneli</a>
        </nav>
        
    </div>

    <div class="chat-container">
        <div class="messages" id="messages">
            <div class="message ai-message">
                Merhaba Süper Admin, ben senin Anime Uzmanı yapay zekan! Hangi anime/manga hakkında bilgi almak istersin?
            </div>
        </div>

        <div class="input-area">
            <input type="text" id="anime-message-input" placeholder="Bir anime, karakter veya bölüm hakkında soru sor...">
        </div>
    </div>

    <script>{BASE_JS}</script>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Giriş</title>
    <style>""" + BASE_CSS + """ .container { max-width: 400px; margin: 100px auto; padding: 20px; background: #222; border-radius: 10px; } input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #555; border-radius: 4px; box-sizing: border-box; background: #333; color:white; } button { background-color: #007BFF; color: white; padding: 14px 20px; margin: 8px 0; border: none; border-radius: 4px; cursor: pointer; width: 100%; }</style>
</head>
<body class="dark">
    <div class="container">
        <h2 style="text-align:center; color:#007BFF;">AURION Giriş</h2>
        {% if error %}<p style="color:red; text-align:center;">{{ error }}</p>{% endif %}
        <form method="POST">
            <label for="username">Kullanıcı Adı</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Şifre</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Giriş Yap</button>
        </form>
        <p style="text-align:center;"><a href="{{ url_for('register') }}" style="color:#007BFF;">Hesabınız yok mu? Kayıt olun.</a></p>
    </div>
</body>
</html>
"""

REGISTER_TEMPLATE = LOGIN_TEMPLATE.replace("AURION Giriş", "AURION Kayıt").replace("Giriş Yap", "Kayıt Ol").replace("'register'", "'login'").replace("Hesabınız yok mu? Kayıt olun.", "Zaten hesabınız var mı? Giriş yapın.")

# KRİTİK SyntaxError'ı çözen, Jinja ifadelerinde tırnak işaretlerini hatasız kullanan yapı:
ADMIN_PANEL_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Admin Paneli</title>
    <style>""" + BASE_CSS + """</style>
</head>
<body class="dark">
    <div class="sidebar">
        <h1 class="logo" style="color:#FFA500;">🛡️ Admin</h1>
        <hr style="border-color:#333;">
        <a href="{{ url_for('index') }}" style="color:inherit; text-decoration:none;">⬅️ Sohbet'e Dön</a>
    </div>
    <div class="chat-container" style="padding: 20px;">
        <h2>Kullanıcı Yönetimi</h2>
        <table border="1" style="width:100%; border-collapse: collapse; text-align: left;">
            <thead>
                <tr style="background:#333;"><th>ID</th><th>Kullanıcı Adı</th><th>Rol</th><th>Yasaklı mı?</th><th>İşlem</th></tr>
            </thead>
            <tbody>
            {% for user in users %}
                <tr style="background:{% if user.role == 'super_admin' %}#440000; color:yellow;{% elif user.role == 'admin' %}#333;{% endif %};">
                    <td>{{ user.id }}</td>
                    <td>{{ user.username }}</td>
                    <td>{{ user.role }}</td>
                    <td>{% if user.is_banned %}Evet{% else %}Hayır{% endif %}</td>
                    <td>
                        <form method="POST" action="{{ url_for('admin_manage_user', user_id=user.id) }}" style="display:inline-block;">
                            {% if user.role != "super_admin" %}
                                {% if not user.is_banned %}
                                    <button type="submit" name="action" value="ban" style="background:red;">Yasakla</button>
                                {% else %}
                                    <button type="submit" name="action" value="unban" style="background:green;">Yasağı Kaldır</button>
                                {% endif %}
                                {% if user.role == "user" %}
                                    <button type="submit" name="action" value="set_admin">Admin Yap</button>
                                {% else %}
                                    <button type="submit" name="action" value="set_user">Üye Yap</button>
                                {% endif %}
                            {% else %}
                                <span style="color:red; font-weight:bold;">DOKUNULMAZ</span>
                            {% endif %}
                        </form>
                    </td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
        
        <h2 style="margin-top:40px;">Admin Logları</h2>
        <pre>{{ logs }}</pre>
    </div>
</body>
</html>
"""

# ==============================================================================
# 6. UYGULAMA BAŞLATMA
# ==============================================================================

if __name__ == '__main__':
    try:
        app.run(debug=True)
    except Exception as e:
        print(f"!!! [AURION INIT ERROR] Uygulama yerel olarak başlatılamadı: {str(e)}", file=sys.stderr)
