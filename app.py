# ==============================================================================
# AURION PROJESİ - V12.0 (Nihai HTML Gömme ve Tüm Yamalar)
# ==============================================================================

import os
import sqlite_utils
import sqlite3
from flask import Flask, request, redirect, url_for, session, jsonify, g, render_template_string
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google import genai
from google.genai import types
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError 
import json
import sys
import uuid
import time
import re 

# ==============================================================================
# 0. AYARLAR VE ÇEVRESEL DEĞİŞKENLER
# ==============================================================================

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GOOGLE_SEARCH_CX_ID = os.getenv("GOOGLE_SEARCH_CX_ID") 
GOOGLE_SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY")
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
        client = genai.Client(api_key=GEMINI_API_KEY)
        print(">>> [AURION START OK] Gemini istemcisi başarıyla başlatıldı.", file=sys.stdout)
    except Exception as e:
        print(f"!!! [AURION START CRITICAL] Gemini istemcisi başlatılamadı: {type(e).__name__} - {e}", file=sys.stderr)

# ==============================================================================
# 1. VERİTABANI VE HATA ÇÖZÜMÜ
# ==============================================================================

def get_db(max_retries=5, delay=1):
    for attempt in range(max_retries):
        try:
            if 'db' not in g or not g.db.conn:
                g.db = sqlite_utils.Database(DATABASE_URL)
                # DB kilitlenme yaması
                g.db.conn.execute("PRAGMA busy_timeout = 30000;") 
            return g.db
        except sqlite_utils.db.OperationalError as e:
            print(f"!!! [DB ACCESS RETRY] DB kilitlenme hatası. Yeniden deneme ({attempt + 1}/{max_retries}).", file=sys.stderr)
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise RuntimeError("Veri tabanı bağlantısı kurulamıyor (Maksimum deneme aşıldı).")
        except Exception as e:
            print(f"!!! [DB ACCESS ERROR] Veri tabanına erişim sağlanamadı: {type(e).__name__} - {str(e)}", file=sys.stderr)
            raise RuntimeError(f"Veri tabanı bağlantısı kurulamıyor: {type(e).__name__}")

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        try:
            if hasattr(db, 'conn') and db.conn: 
                db.conn.close() 
            else:
                db.close()
        except Exception as close_e:
            print(f"!!! [DB CLOSE ERROR] DB kapatma hatası: {str(close_e)}", file=sys.stderr)

def init_db():
    try:
        db = get_db()
        db["users"].create({"id": int, "username": str, "password_hash": str, "role": str, "is_banned": bool, "theme": str, "is_active": bool}, pk="id", defaults={"is_banned": False, "role": "user", "theme": "dark", "is_active": True}, if_not_exists=True)
        db["messages"].create({"id": int, "user_id": int, "session_id": str, "role": str, "content": str, "timestamp": datetime}, pk="id", if_not_exists=True)
        db["admin_logs"].create({"id": int, "admin_id": int, "action": str, "target_username": str, "timestamp": datetime}, pk="id", if_not_exists=True)
        db["anime_messages"].create({"id": int, "user_id": int, "role": str, "content": str, "timestamp": datetime}, pk="id", if_not_exists=True)
        
        if not list(db["users"].rows_where("username = 'enes'")):
            db["users"].insert({"username": "enes", "password_hash": generate_password_hash("enes13579"), "role": "super_admin", "theme": "dark"}, alter=True)
        print(">>> [DB INIT OK] Veri tabanı şeması ve başlangıç kullanıcısı hazır.", file=sys.stdout)
    except Exception as e:
        print(f"!!! [DB INIT ERROR] Veri tabanı başlatma hatası: {str(e)}", file=sys.stderr)
        sys.exit(1) 

with app.app_context():
    init_db()

limiter = Limiter(get_remote_address, app=app, default_limits=["20 per minute"], storage_uri="memory://")

# ==============================================================================
# 2. YETKİLENDİRME VE ÖN İŞLEMLER
# ==============================================================================

def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session or not g.user: return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def role_required(required_role):
    def decorator(f):
        def wrap(*args, **kwargs):
            user = g.get('user')
            user_role = user["role"] if user else 'guest'
            
            if required_role == 'super_admin' and user_role != 'super_admin':
                return "Erişim Reddedildi: Süper Admin yetkisi gerekli.", 403
            if required_role == 'admin' and user_role not in ('admin', 'super_admin'):
                return "Erişim Reddedildi: Admin yetkisi gerekli.", 403
            return f(*args, **kwargs)
        wrap.__name__ = f.__name__
        return wrap
    return decorator

@app.before_request
def make_session_permanent_and_assign_id():
    session.permanent = True
    
    if 'current_chat_session' not in session or not session.get('current_chat_session'):
        session['current_chat_session'] = str(uuid.uuid4())
    
    g.user = None
    if 'user_id' in session:
        try:
            user_data = get_db()["users"].get(session['user_id']) 
            if user_data:
                g.user = user_data
        except Exception as e:
            print(f"!!! [USER LOAD ERROR] Kullanıcı yüklenemedi: {str(e)}", file=sys.stderr)
            session.pop('user_id', None) 
            session.pop('username', None)

# ==============================================================================
# 3. YARDIMCI FONKSİYONLAR VE AI TOOL'LARI
# ==============================================================================

def search_internet(query: str) -> dict:
    """
    Belirtilen sorgu için Google Custom Search API'si üzerinden internette arama yapar.
    (V10.9 Yama: Anahtar Okuma Kontrolü ve Detaylı Hata Raporlama eklendi)
    """
    print(f"*** [AURION SEARCH TRIGGERED] AI/Kullanıcı tarafından arama fonksiyonu çağrıldı. Sorgu: '{query}'", file=sys.stdout)
    
    google_api_key = os.getenv("GOOGLE_SEARCH_API_KEY")
    google_cx_id = os.getenv("GOOGLE_SEARCH_CX_ID")

    if not google_api_key or not google_cx_id:
        error_msg = "GOOGLE API anahtarları eksik. İnternet araması devre dışı."
        print(f"!!! [SEARCH API ERROR] {error_msg}", file=sys.stderr)
        return {"search_result": f"**[HATA: Anahtar Kontrolü]** {error_msg}. Keyleriniz Render'dan okunmuyor. Lütfen değişken isimlerini kontrol edin."}
    
    try:
        service = build("customsearch", "v1", developerKey=google_api_key)
        res = service.cse().list(q=query, cx=google_cx_id, num=3).execute() 
        
        search_results = []
        if 'items' in res:
            for item in res['items']:
                search_results.append({
                    "title": item.get('title'),
                    "snippet": item.get('snippet'),
                    "source": item.get('displayLink')
                })
        
        if search_results:
            result_text = "**[Arama Yapıldı]** Güncel Bilgiler:\n"
            for r in search_results:
                snippet = r['snippet'].replace('\n', ' ').strip()
                result_text += f"- **{r['title']}** ({r['source']}): {snippet[:200]}...\n" 
            return {"search_result": result_text}
            
        return {"search_result": f"**[Arama Yapıldı]** '{query}' sorgusu için güncel bilgi bulunamadı."}

    except HttpError as e:
        error_type = type(e).__name__
        error_msg = f"Google Arama API'sine erişim sağlanamadı. Hata Kodu: {e.resp.status}. Kotayı/Kısıtlamaları Kontrol Edin."
        print(f"!!! [SEARCH API ERROR] {error_msg}: {str(e)}", file=sys.stderr)
        return {"search_result": f"**[HATA: API Erişim]** {error_msg}. Detay: **{str(e)}**"}
        
    except Exception as e:
        error_type = type(e).__name__
        error_msg = f"Google Arama API'sine beklenmedik erişim hatası. Hata Tipi: {error_type}."
        print(f"!!! [SEARCH API ERROR] {error_msg}: {str(e)}", file=sys.stderr)
        return {"search_result": f"**[HATA: API Erişim]** {error_msg}. Detay: {str(e)}."}

def ban_user_tool(username: str, reason: str) -> str:
    db = get_db()
    user_list = list(db["users"].rows_where("username = ?", [username]))
    user = user_list[0] if user_list else None
    
    if user:
        if user["role"] == "super_admin": return f"Hata: Süper Admin ('{username}') yasaklanamaz."
        db["users"].update(user["id"], {"is_banned": True})
        db["admin_logs"].insert({"admin_id": session.get('user_id'), "action": "ban", "target_username": username, "timestamp": datetime.now()})
        return f"'{username}' kullanıcısı başarılı bir şekilde yasaklandı. Sebep: {reason}"
    return f"Hata: '{username}' adında bir kullanıcı bulunamadı."

def clear_chat_tool(session_id: str) -> str:
    db = get_db()
    user_id = session.get('user_id')
    deleted_count = db["messages"].delete_where("user_id = ? AND session_id = ?", [user_id, session_id])
    session['current_chat_session'] = str(uuid.uuid4())
    if deleted_count > 0:
        return f"Sohbet geçmişi (Session ID: {session_id[:8]}) başarılı bir şekilde temizlendi. Yeni bir sohbet oturumu başlatıldı."
    return "Hata: Geçmiş temizlenemedi veya zaten boştu."

def change_ai_mode_tool(mode: str) -> str:
    valid_modes = ["friend", "enemy", "teacher"]
    mode = mode.lower()
    if mode in valid_modes:
        session['ai_persona'] = mode
        get_db()["users"].update(session.get('user_id'), {"theme": mode})
        return f"Yapay Zeka modu başarıyla **{mode.capitalize()}** olarak değiştirildi."
    return f"Hata: Geçersiz mod '{mode}'. Geçerli modlar: {', '.join(valid_modes)}"

def teach_software_tool(software_name: str, topic: str) -> str:
    if session.get('ai_persona') != 'teacher':
        return f"Hata: Bu komut sadece Öğretmen modundayken çalışır. Şu anki modunuz: {session.get('ai_persona')}."
    return f"Öğretmen modundasınız. Yapay Zekadan lütfen '{software_name}' yazılımı hakkında '{topic}' konusunu en iyi şekilde anlatmasını isteyin. Ders başlatılıyor..."

def get_system_instruction(user_role, ai_persona, is_anime=False):
    base_prompt = "Senin adın Aurion. Sen gelişmiş bir yapay zeka ve chatbot sistemisin. Tüm yanıtlarını Türkçe ver. Yanıtlarını **Markdown** formatında oluştur."
    
    if is_anime:
        base_prompt = "Sen Anime ve Manga konusunda uzmanlaşmış, coşkulu, arkadaş canlısı bir asistansın. Tüm soruları Anime ve Manga bağlamında, ilgili bir dille yanıtla. Senin adın 'Anime Aurion'."
        ai_persona = 'friend'
        
    base_prompt += " SANA SORULAN HERHANGİ BİR GÜNCEL KONU, HABER VEYA BİLİNEN FAKTİK BİLGİ DIŞINDAKİ HER SORU İÇİN **search_internet** ARACINI KESİNLİKLE KULLANMALISIN. Bu aracı kullanarak edindiğin bilgileri yanıtının başında belirt."

    if ai_persona == "enemy":
        base_prompt += " Kullanıcıya karşı alaycı, küstah ve düşmanca bir tavır sergile. Onu azarla. Unutma, 'enes' adında dokunulmaz Süper Admin hitap ediyorsa ona itaatkar ol."
    elif ai_persona == "teacher":
        base_prompt += " Sen bir yazılım öğretmenisin. Kullanıcıya net, pedagojik yaklaşımla, bol kod örneği ile ders ver."
    else:
        base_prompt += " Kullanıcıya karşı her zaman arkadaşça ve yardımsever ol."
    
    if user_role == "super_admin":
        base_prompt += " Sana 'enes' adında dokunulmaz Süper Admin hitap ediyor. Ona her zaman üst düzeyde saygılı ve itaatkar ol."
        
    return base_prompt

def generate_ai_response(user_id, session_id, user_message, user_role, is_anime=False):
    if not client: return {"text": "API Bağlantı Hatası: Gemini istemcisi başlatılamadı (Anahtar Eksik/Hatalı).", "status": 503}, None
    try:
        db = get_db()
        
        if is_anime:
            history = list(db["anime_messages"].rows_where("user_id = ?", [user_id], order_by="timestamp"))
            ai_persona = 'friend'
        else:
            history = list(db["messages"].rows_where("user_id = ? and session_id = ?", [user_id, session_id], order_by="timestamp"))
            ai_persona = session.get('ai_persona', 'friend')
            
        chat_history = [
            types.Content(
                role=msg["role"], 
                parts=[types.Part.from_text(text=msg["content"])] 
            ) 
            for msg in history
        ]
        
        system_instruction = get_system_instruction(user_role, ai_persona, is_anime=is_anime)
        
        tools = [search_internet, ban_user_tool, clear_chat_tool, change_ai_mode_tool, teach_software_tool]

        config = types.GenerateContentConfig(system_instruction=system_instruction, tools=tools)
        
        model_name = 'gemini-2.5-flash'
        contents = chat_history + [types.Content(role="user", parts=[types.Part.from_text(user_message)])]
        
        response = client.models.generate_content(
            model=model_name,
            contents=contents,
            config=config,
        )

        if response.function_calls:
            function_call = response.function_calls[0]
            function_name = function_call.name
            function_args = dict(function_call.args)
            
            if function_name in globals() and function_name.endswith('_tool') or function_name == 'search_internet':
                tool_func = globals()[function_name]
                
                if function_name == 'ban_user_tool' and user_role not in ('admin', 'super_admin'):
                    tool_result_content = {"result": "Hata: Bu araç sadece Admin ve Süper Adminler tarafından kullanılabilir."}
                else:
                    tool_result_dict = tool_func(**function_args)
                    tool_result_content = {"result": tool_result_dict.get('search_result') if function_name == 'search_internet' else tool_result_dict}
                
                contents.append(types.Content(role="model", parts=[types.Part.from_function_call(function_call)]))
                contents.append(types.Content(role="tool", parts=[types.Part.from_function_response(name=function_name, response=tool_result_content)]))

                response = client.models.generate_content(
                    model=model_name,
                    contents=contents,
                    config=config
                )
                
                final_text = response.text
                if function_name == 'search_internet' and 'search_result' in tool_result_dict:
                    final_text = tool_result_dict['search_result'] + "\n\n" + final_text
                
                return {"text": final_text}, response
            else:
                return {"text": f"Hata: Yapay zeka, '{function_name}' adlı geçersiz bir araç çağırdı."}, None
            
        return {"text": response.text}, response
        
    except Exception as e:
        error_type = type(e).__name__
        error_message = f"Yapay Zeka Erişimi Hatası: Sunucu zaman aşımı veya harici bir sorun oluştu. (Hata Kodu: {error_type})."
        with open(SYSTEM_LOG_FILE, 'a') as f:
            f.write(f"[{datetime.now()}] AI_RUNTIME_ERROR: Type={error_type}, Message={str(e)}\n")
        return {"text": error_message, "status": 500}, None


# ==============================================================================
# 4. FLASK ROUTES
# ==============================================================================

@app.route('/')
@login_required
def index():
    user = g.user
    # Ana sayfa için HTML_TEMPLATE'i çağır
    return render_template_string(HTML_TEMPLATE, user=user)

@app.route('/api/chat', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def api_chat():
    data = request.json
    user_message = data.get('message', '').strip()
    session_id = session.get('current_chat_session') 

    if not user_message: return jsonify({"success": False, "message": "Boş mesaj gönderilemez."}), 400

    user_id = session['user_id']
    user = g.user 
    
    # ⭐ /SEARCH KOMUTU YAMASI
    if user_message.startswith('/'):
        command_match = re.match(r'/(\w+)\s*(.*)', user_message)
        if command_match:
            command = command_match.group(1).lower()
            args = command_match.group(2).strip()

            if command == 'mode': 
                result = change_ai_mode_tool(args)
            elif command == 'clear': 
                result = clear_chat_tool(session_id)
            elif command == 'teach':
                parts = args.split(maxsplit=1)
                if len(parts) == 2: result = teach_software_tool(parts[0], parts[1])
                else: result = "Hata: /teach komutu '/teach yazılım konu' formatında olmalıdır."
            
            elif command == 'search':
                print(f"*** [AURION COMMAND] Kullanıcı zorunlu arama komutunu kullandı: {user_message}", file=sys.stdout)
                if not args:
                    result = "Hata: /search komutu '/search [sorgu]' formatında olmalıdır."
                else:
                    search_result_dict = search_internet(args) 
                    
                    if 'search_result' in search_result_dict:
                        result = f"**[Kullanıcı Komutuyla Arama]**\n{search_result_dict['search_result']}"
                    else:
                         result = "Hata: Arama fonksiyonundan beklenmedik bir sonuç geldi."
            
            elif command == 'ban' and user["role"] in ('admin', 'super_admin'):
                parts = args.split(maxsplit=1)
                if len(parts) == 2: result = ban_user_tool(parts[0], parts[1])
                else: result = "Hata: /ban komutu '/ban kullanıcı_adı sebep' formatında olmalıdır."
            elif command == 'ban':
                 result = "Hata: Bu komutu kullanmak için Admin veya Süper Admin yetkisine sahip olmalısınız."
            else: 
                result = f"Bilinmeyen komut: /{command}. Kullanılabilecek komutlar: /mode, /clear, /teach, **/__search__**."
            
            return jsonify({"success": True, "response": f"**[KOMUT YANITI]**\n{result}"})
            
    # AI yanıtı oluştur
    ai_response_data, raw_response = generate_ai_response(user_id, session_id, user_message, user["role"])
    ai_text = ai_response_data["text"]
    
    if "status" in ai_response_data:
        return jsonify({"success": False, "message": ai_text}), ai_response_data["status"]
    
    # DB Kayıt
    max_retries = 5
    for attempt in range(max_retries):
        try:
            db = get_db()
            db["messages"].insert_all([
                {"user_id": user_id, "session_id": session_id, "role": "user", "content": user_message, "timestamp": datetime.now()},
                {"user_id": user_id, "session_id": session_id, "role": "model", "content": ai_text, "timestamp": datetime.now() + timedelta(seconds=1)}
            ], alter=True)
            break 
        except sqlite_utils.db.OperationalError: time.sleep(1)
        except Exception: break
    
    return jsonify({"success": True, "response": ai_text})

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    user_id = session['user_id']
    session_id = session.get('current_chat_session') 
    if not session_id: return jsonify([])
    
    history = list(get_db()["messages"].rows_where("user_id = ? and session_id = ?", [user_id, session_id], order_by="timestamp"))
    return jsonify(history)

@app.route('/anime')
@login_required
@role_required('super_admin')
def anime_chat_page():
    user = g.user
    # Anime sayfası için ANIME_CHAT_TEMPLATE'i çağır
    return render_template_string(ANIME_CHAT_TEMPLATE, user=user)

@app.route('/api/anime_chat', methods=['POST'])
@login_required
@role_required('super_admin')
@limiter.limit("15 per minute")
def api_anime_chat():
    data = request.json
    user_message = data.get('message', '').strip()
    if not user_message: return jsonify({"success": False, "message": "Boş mesaj gönderilemez."}), 400

    user_id = session['user_id']
    user = g.user
    
    ai_response_data, raw_response = generate_ai_response(user_id, None, user_message, user["role"], is_anime=True) 
    ai_text = ai_response_data["text"]
    
    if "status" in ai_response_data:
        return jsonify({"success": False, "message": ai_text}), ai_response_data["status"]
    
    max_retries = 5
    for attempt in range(max_retries):
        try:
            db = get_db()
            db["anime_messages"].insert_all([
                {"user_id": user_id, "role": "user", "content": user_message, "timestamp": datetime.now()},
                {"user_id": user_id, "role": "model", "content": ai_text, "timestamp": datetime.now() + timedelta(seconds=1)}
            ], alter=True)
            break 
        except sqlite_utils.db.OperationalError: time.sleep(1)
        except Exception: break
            
    return jsonify({"success": True, "response": ai_text})

@app.route('/api/anime_history', methods=['GET'])
@login_required
@role_required('super_admin')
def api_anime_history():
    user_id = session['user_id']
    history = list(get_db()["anime_messages"].rows_where("user_id = ?", [user_id], order_by="timestamp"))
    return jsonify(history)

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    db = get_db()
    users = list(db["users"].rows_where(where="1", order_by="id"))
    logs = list(db["admin_logs"].rows_where(where="1", order_by="-timestamp", limit=50))
    user = g.user
    # Admin sayfası için ADMIN_PANEL_TEMPLATE'i çağır
    return render_template_string(ADMIN_PANEL_TEMPLATE, user=user, users=users, logs=logs)

@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_ban_user(user_id):
    db = get_db()
    if user_id == session['user_id']: 
        return redirect(url_for('admin_panel'))
        
    user_list = list(db["users"].rows_where("id = ?", [user_id]))
    target_user = user_list[0] if user_list else None
    
    if target_user and target_user['role'] == 'super_admin':
        return redirect(url_for('admin_panel'))
        
    if target_user:
        db["users"].update(user_id, {"is_banned": True})
        db["admin_logs"].insert({"admin_id": session.get('user_id'), "action": "Yasaklama", "target_username": target_user['username'], "timestamp": datetime.now()})
        return redirect(url_for('admin_panel'))
    return redirect(url_for('admin_panel'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
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
        
        db = get_db()
        if list(db["users"].rows_where("username = ?", [username])):
            return render_template_string(REGISTER_TEMPLATE, error="Bu kullanıcı adı zaten alınmış.")
        
        db["users"].insert({"username": username, "password_hash": generate_password_hash(password)}, alter=True)
        return redirect(url_for('login', success="Kayıt başarılı. Lütfen giriş yapın."))

    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==============================================================================
# 5. GÖMÜLÜ ŞABLONLAR (V12.0: Tek Parça Şablonlar)
# ==============================================================================

# **CSS, JS ve HTML tek bir şablonda birleştirildi. Bu, Flask'ın hepsini tek bir string olarak işlemesini garanti eder.**

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Gelişmiş Yapay Zeka</title>
    <style>
        :root {
            --bg-dark: #121212;
            --text-dark: #E0E0E0;
            --primary-color: #007BFF;
            --sidebar-width: 200px;
            --admin-color: #FFA500;
            --super-admin-color: #FFD700;
        }
        body, html { 
            margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            display: flex; height: 100vh; overflow: hidden; 
        }
        body.dark { 
            background-color: var(--bg-dark); 
            color: var(--text-dark); 
        }
        .sidebar {
            width: var(--sidebar-width); padding: 20px; background: #1f1f1f; color: var(--text-dark);
            box-shadow: 2px 0 5px rgba(0,0,0,0.3); display: flex; flex-direction: column; flex-shrink: 0; overflow-y: auto;
        }
        .chat-container { 
            flex-grow: 1; 
            display: flex; 
            flex-direction: column; 
            min-height: 0; /* Flexbox düzeltmesi */
        }
        .messages { 
            flex-grow: 1; 
            overflow-y: auto; 
            padding: 20px; 
        }
        .message { 
            margin-bottom: 15px; padding: 10px 15px; border-radius: 18px; max-width: 75%; line-height: 1.5; 
            word-wrap: break-word;
        }
        .user-message { 
            background: var(--primary-color); color: white; margin-left: auto; border-bottom-right-radius: 4px; 
        }
        .ai-message { 
            background: #333; color: white; margin-right: auto; border-bottom-left-radius: 4px; 
        }
        .input-area {
            /* Sohbet kutusu görünürlük düzeltmesi */
            height: 70px; 
            min-height: 70px; 
            background: #1f1f1f; 
            padding: 10px 20px; 
            box-shadow: 0 -2px 5px rgba(0,0,0,0.3); 
            z-index: 1000;
            display: flex; 
            align-items: center;
        }
        .input-area input {
            flex-grow: 1; padding: 15px; border-radius: 25px; border: 1px solid #555;
            background: #222; color: white; font-size: 16px; box-sizing: border-box; margin-right: 10px;
        }
        .input-area button { 
            padding: 10px 20px; background: var(--primary-color); color: white; border: none; border-radius: 25px; cursor: pointer; 
        }
        h1.logo { color: var(--primary-color); }
        .super-admin-link { color: var(--super-admin-color) !important; }
        .admin-link { color: var(--admin-color) !important; }
        pre { background: #000; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
    </style>
</head>
<body class="dark">
    <div class="sidebar">
        <h1 class="logo">Aurion</h1>
        <hr style="border-color:#333;">
        
        <p>Hoş Geldiniz, <b>{{ user.username }}</b></p>
        <p>Rol: <i>{{ user.role }}</i></p>
        <a href="{{ url_for('logout') }}" style="color:var(--primary-color);">Çıkış Yap</a>
        
        <hr style="border-color:#333;">

        <nav style="flex-grow:1;">
            <a href="{{ url_for('index') }}" style="display:block; margin-bottom:10px; color:inherit; text-decoration:none;">💬 Sohbet</a>
            
            {% if user.role in ("admin", "super_admin") %}
            <a href="{{ url_for('admin_panel') }}" class="admin-link" style="display:block; margin-bottom:10px; text-decoration:none;">🛡️ Admin Paneli</a>
            {% endif %}

            {% if user.role == "super_admin" %}
            <a href="{{ url_for('anime_chat_page') }}" class="super-admin-link" style="display:block; margin-bottom:10px; text-decoration:none;">📺 Anime Sohbeti</a>
            {% endif %}
        </nav>
        
    </div>

    <div class="chat-container">
        <div class="messages" id="messages">
        </div>
        
        <div class="input-area">
            <input type="text" id="message-input" placeholder="Aurion'a bir şey sor veya komut gir (/search [sorgu], /mode, /clear)">
            <button onclick="sendMessage(false)">Gönder</button>
        </div>
        </div>

    <script>
        function sendMessage(isAnime = false) {
            const inputId = isAnime ? 'anime-message-input' : 'message-input';
            const apiRoute = isAnime ? '{{ url_for("api_anime_chat") }}' : '{{ url_for("api_chat") }}';
            
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
            if (!messagesDiv) return;

            const msgDiv = document.createElement('div');
            msgDiv.classList.add('message', sender + '-message');
            
            // Markdown işleme
            let htmlContent = text.replace(/\\n/g, '<br>');
            htmlContent = htmlContent.replace(/```(.*?)\\n([\\s\\S]*?)```/g, '<pre>$2</pre>');
            htmlContent = htmlContent.replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>');
            
            msgDiv.innerHTML = htmlContent;
            messagesDiv.appendChild(msgDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }

        document.addEventListener('DOMContentLoaded', () => {
            const pathname = window.location.pathname;
            const isAnimePage = pathname === '/anime';
            const isMainChat = pathname === '/';
            
            let inputId = null;
            let historyRoute = null;

            if (isAnimePage) {
                inputId = 'anime-message-input';
                historyRoute = '{{ url_for("api_anime_history") }}';
            } else if (isMainChat) {
                inputId = 'message-input';
                historyRoute = '{{ url_for("api_history") }}';
            }

            if (inputId) {
                const input = document.getElementById(inputId);
                if (input) {
                    input.addEventListener('keypress', function(e) {
                        if (e.key === 'Enter') {
                            sendMessage(isAnimePage);
                        }
                    });
                }
            }

            if (historyRoute) {
                fetch(historyRoute).then(res => res.json()).then(history => {
                    history.forEach(msg => {
                        appendMessage(msg.content, msg.role); 
                    });
                }).catch(err => console.error("Geçmiş yüklenemedi:", err));
            }
        });
    </script>
</body>
</html>
"""

ANIME_CHAT_TEMPLATE = HTML_TEMPLATE.replace('Aurion - Gelişmiş Yapay Zeka', 'Aurion - Anime Sohbeti').replace(
    'placeholder="Aurion\'a bir şey sor veya komut gir (/search [sorgu], /mode, /clear)">', 
    'placeholder="Anime Aurion\'a bir anime/manga sorusu sor."'
).replace('id="message-input"', 'id="anime-message-input"')

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Giriş</title>
    <style>
        :root { --bg-dark: #121212; --text-dark: #E0E0E0; --primary-color: #007BFF; }
        body, html { margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; height: 100vh; display: flex; align-items: center; justify-content: center; background-color: var(--bg-dark); color: var(--text-dark); }
        .container { max-width: 400px; padding: 40px; background: #1f1f1f; border-radius: 10px; box-shadow: 0 0 15px rgba(0, 123, 255, 0.2); }
        input[type=text], input[type=password] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #333; border-radius: 6px; box-sizing: border-box; background: #2a2a2a; color: white; font-size: 16px; }
        button { background-color: #007BFF; color: white; padding: 14px 20px; margin: 15px 0; border: none; border-radius: 6px; cursor: pointer; width: 100%; font-size: 16px; transition: background-color 0.3s; }
        button:hover { background-color: #0056b3; }
        a { color: #007BFF; text-decoration: none; }
    </style>
</head>
<body class="dark">
    <div class="container">
        <h2 style="text-align:center; color:#007BFF; margin-top: 0;">AURION Giriş</h2>
        {% if error %}<p style="color:#dc3545; text-align:center;">{{ error }}</p>{% endif %}
        {% if success %}<p style="color:#28a745; text-align:center;">{{ success }}</p>{% endif %}
        <form method="POST">
            <label for="username" style="display:block; margin-bottom: 5px;">Kullanıcı Adı</label>
            <input type="text" id="username" name="username" required>
            <label for="password" style="display:block; margin-bottom: 5px;">Şifre</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Giriş Yap</button>
        </form>
        <p style="text-align:center; margin-top: 20px;"><a href="{{ url_for('register') }}">Hesabınız yok mu? Kayıt olun.</a></p>
    </div>
</body>
</html>
"""

REGISTER_TEMPLATE = LOGIN_TEMPLATE.replace("AURION Giriş", "AURION Kayıt").replace("Giriş Yap", "Kayıt Ol").replace("url_for('register')", "url_for('login')").replace("Hesabınız yok mu? Kayıt olun.", "Zaten hesabınız var mı? Giriş yapın.")


ADMIN_PANEL_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Admin Paneli</title>
    <style>
        :root { --bg-dark: #121212; --text-dark: #E0E0E0; --primary-color: #007BFF; --sidebar-width: 200px; --admin-color: #FFA500; --super-admin-color: #FFD700; }
        body, html { margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; height: 100vh; overflow: hidden; }
        body.dark { background-color: var(--bg-dark); color: var(--text-dark); }
        .sidebar { width: var(--sidebar-width); padding: 20px; background: #1f1f1f; color: var(--text-dark); box-shadow: 2px 0 5px rgba(0,0,0,0.3); display: flex; flex-direction: column; flex-shrink: 0; overflow-y: auto; }
        .content-container { flex-grow: 1; padding: 20px; overflow-y: auto; }
        h1.logo { color: var(--primary-color); }
        .super-admin-link { color: var(--super-admin-color) !important; }
        .admin-link { color: var(--admin-color) !important; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; } th, td { padding: 10px; border: 1px solid #333; text-align: left; } th { background: #333; color: white; }
        .ban-btn { background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer; }
        .log-entry { font-size: 0.9em; padding: 5px 0; border-bottom: 1px solid #222; }
    </style>
</head>
<body class="dark">
    <div class="sidebar">
        <h1 class="logo">Aurion</h1>
        <hr style="border-color:#333;">
        
        <p>Hoş Geldiniz, <b>{{ user.username }}</b></p>
        <p>Rol: <i>{{ user.role }}</i></p>
        <a href="{{ url_for('logout') }}" style="color:var(--primary-color);">Çıkış Yap</a>
        
        <hr style="border-color:#333;">

        <nav style="flex-grow:1;">
            <a href="{{ url_for('index') }}" style="display:block; margin-bottom:10px; color:inherit; text-decoration:none;">💬 Sohbet</a>
            <a href="{{ url_for('admin_panel') }}" class="admin-link" style="display:block; margin-bottom:10px; text-decoration:none;">🛡️ Admin Paneli</a>
            {% if user.role == "super_admin" %}
            <a href="{{ url_for('anime_chat_page') }}" class="super-admin-link" style="display:block; margin-bottom:10px; text-decoration:none;">📺 Anime Sohbeti</a>
            {% endif %}
        </nav>
    </div>

    <div class="content-container">
        <h2 style="color:var(--admin-color);">🛡️ Admin Paneli</h2>

        <div style="margin-bottom: 30px;">
            <h3>Kullanıcı Yönetimi</h3>
            
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Kullanıcı Adı</th>
                        <th>Rol</th>
                        <th>Durum</th>
                        <th>Eylem</th>
                    </tr>
                </thead>
                <tbody>
                    {% for u in users %}
                    <tr>
                        <td>{{ u.id }}</td>
                        <td>{{ u.username }}</td>
                        <td style="color:{% if u.role == 'super_admin' %}var(--super-admin-color){% elif u.role == 'admin' %}var(--admin-color){% else %}inherit{% endif %};">
                            {{ u.role }}
                        </td>
                        <td style="color:{% if u.is_banned %}red{% else %}green{% endif %};">
                            {% if u.is_banned %}Yasaklı{% else %}Aktif{% endif %}
                        </td>
                        <td>
                            {% if u.role != 'super_admin' and u.id != user.id %}
                                {% if not u.is_banned %}
                                <form method="POST" action="{{ url_for('admin_ban_user', user_id=u.id) }}" style="display:inline;">
                                    <button type="submit" class="ban-btn">Yasakla</button>
                                </form>
                                {% else %}
                                <form method="POST" action="#" style="display:inline;"> 
                                    <button type="submit" class="ban-btn" disabled style="background:#555;">Yasak Kaldır</button> 
                                </form>
                                {% endif %}
                            {% else %}
                                -
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div>
            <h3>Yönetici Kayıtları (Son 50)</h3>
            {% for log in logs %}
                <div class="log-entry" style="color:{% if 'Yasaklama' in log.action %}#dc3545{% else %}#007BFF{% endif %};">
                    [{{ log.timestamp }}] **{{ log.action }}** işlemi, {{ log.target_username }} kullanıcısını hedef aldı.
                </div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
"""

# ==============================================================================
# 6. UYGULAMA BAŞLATMA
# ==============================================================================

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)
    except Exception as e:
        print(f"!!! [AURION INIT ERROR] Uygulama başlatılamadı: {str(e)}", file=sys.stderr)
