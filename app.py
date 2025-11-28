# app.py
import os
import json
import uuid
import datetime
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ValidationError
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional, List

# ----- 1. Kütüphane Kontrolü ve Yükleme -----
try:
    from google import genai
except ImportError:
    genai = None
    print("!!! [HATA] google-genai kütüphanesi bulunamadı.")

# ----- 2. KONFİGÜRASYON VE SABİTLER (Kişiselleştirilmiş ve Parçalanmış Key) -----

# API Anahtarınız, kullanıcının isteği üzerine 8 parçaya bölündü.
# DİKKAT: Bu gerçek bir güvenlik yöntemi değildir.
KEY_PARTS = [
    "AIzaS", "yD0KH", "3AFQX", "Rh84I", "mhLc0", "SXyG9", "bZny4", "0IMM"
]
GEMINI_API_KEY = "".join(KEY_PARTS) # Anahtar burada birleştirildi

# Güvenlik ve JWT (Token) ayarları
SECRET_KEY = os.environ.get("SECRET_KEY", "aurion-random-secret-key-123456") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 7 gün

# Dosya yolları
DB_YOLU = "data/db.json"
DATA_DİZİNİ = "data"

# Şifreleme (Bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----- 3. Pydantic Modelleri -----
class ChatMessage(BaseModel):
    sender: str
    content: str
    timestamp: datetime.datetime = datetime.datetime.now()

class User(BaseModel):
    id: str = None
    username: str
    password: str
    role: str = "user"  # user, super_admin
    chat_history: List[ChatMessage] = [] # KULLANICIYA ÖZEL SOHBET GEÇMİŞİ EKLENDİ

class DatabaseSchema(BaseModel):
    users: List[User] = []
    # Global 'chats' listesi kaldırıldı, tarihçeler artık User modelinde tutuluyor.

# ----- 4. Gemini AI Yapılandırması ve Durumu -----

AI_ENABLED = False
if GEMINI_API_KEY and genai:
    try:
        genai.configure(api_key=GEMINI_API_KEY) 
        if genai.Client(): 
             print(f">>> [GEMINI OK] API Key algılandı ve yapılandırıldı.")
             AI_ENABLED = True
    except Exception as e:
        print(f"!!! [API ERROR] Gemini Configure/Yükleme Hatası: {e}")
        AI_ENABLED = False
else:
    print("!!! [UYARI] Google GenAI kütüphanesi veya API Key eksik.")


# ----- 5. DatabaseManager Sınıfı -----

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._ensure_data_dir()
        self._ensure_db_exists()

    def _ensure_data_dir(self):
        if not os.path.exists(DATA_DİZİNİ):
            os.makedirs(DATA_DİZİNİ)

    def _hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def _ensure_db_exists(self):
        if not os.path.exists(self.db_path):
            print(">>> [DB INIT] Veritabanı oluşturuluyor.")
            admin_password_hash = self._hash_password("enes12345") 

            initial_data = {
                "users": [
                    # ENES: Yeni varsayılan Super Admin
                    User(id=str(uuid.uuid4()), username="enes", role="super_admin", password=admin_password_hash).dict(),
                ]
            }
            try:
                DatabaseSchema(**initial_data)
                with open(self.db_path, "w", encoding="utf-8") as f:
                    json.dump(initial_data, f, ensure_ascii=False, indent=4)
            except Exception as e:
                print(f"!!! [DB HATA] İlk veri oluşturulurken hata: {e}")

    def load_db(self) -> dict:
        self._ensure_db_exists()
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Yüklenen veriyi Pydantic ile doğrula
            return DatabaseSchema(**data).dict()
        except Exception as e:
            print(f"!!! [DB HATA] Veritabanı okuma/şema hatası: {e}")
            raise HTTPException(status_code=500, detail="Veritabanı hatası.")

    def save_db(self, data: dict):
        try:
            # Kaydetmeden önce Pydantic ile doğrula
            DatabaseSchema(**data) 
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"!!! [DB HATA] Veri kaydetme hatası: {e}")
            raise HTTPException(status_code=500, detail="Veri kaydetme hatası.")

db_manager = DatabaseManager(DB_YOLU)

# ----- 6. Şifreleme ve Token Fonksiyonları -----

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# JWT Kontrolü için kullanılan bağımlılık fonksiyonu
def get_current_user(request: Request) -> dict:
    """JWT token'ı kullanarak mevcut kullanıcının kimliğini ve rolünü doğrular."""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Yetkilendirme token'ı eksik.")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_role: str = payload.get("role")
        if username is None or user_role is None:
            raise HTTPException(status_code=401, detail="Token geçersiz.")
        return {"username": username, "role": user_role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş token. Lütfen tekrar giriş yapın.")


# ----- 7. AI_Assistant Sınıfı (Stateless - Geçmişi Dışarıdan Alır) -----

class AI_Assistant:
    def __init__(self):
        self.client = genai.Client() if AI_ENABLED else None
    
    # Kullanıcının tüm geçmişini alıp, yeni mesajla birlikte gönderir
    def generate_response(self, history: List[dict], prompt: str) -> str:
        if not AI_ENABLED or not self.client:
            return "AI servisi şu anda aktif değil. Lütfen Super Admin ile iletişime geçin."

        try:
            # History'den API'nin beklediği 'contents' formatını oluşturma
            contents = []
            for message in history:
                # 'user' gönderenler 'user' rolüne, 'ai' gönderenler 'model' rolüne maplenir
                role = "user" if message["sender"] == "user" else "model"
                contents.append(
                    {"role": role, "parts": [{"text": message["content"]}]}
                )
            
            # Güncel isteği ekle
            contents.append(
                {"role": "user", "parts": [{"text": prompt}]}
            )

            response = self.client.models.generate_content(
                model='gemini-2.5-flash', # Çalışan model
                contents=contents
            )
            return response.text
        except Exception as e:
            print(f"!!! [AI HATA] Mesaj gönderme hatası: {e}")
            return "Üzgünüm, AI servisinde bir hata oluştu."

ai_assistant = AI_Assistant()

# ----- 8. UYGULAMA YÖNLENDİRMELERİ (API Endpoints) -----

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    db = db_manager.load_db()
    user_record = next((u for u in db["users"] if u["username"] == username), None)

    if not user_record or not verify_password(password, user_record["password"]):
        raise HTTPException(status_code=401, detail="Hatalı kullanıcı adı veya şifre")

    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_record["username"], "role": user_record["role"]}, 
        expires_delta=access_token_expires
    )
    
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.set_cookie(key="user_name", value=user_record["username"], httponly=False)
    response.set_cookie(key="user_role", value=user_record["role"], httponly=False)
    return response

# KULLANICIYA ÖZEL SOHBET GEÇMİŞİ YÜKLEME ENDPOINT'İ EKLENDİ
@app.get("/api/chat_history")
async def get_chat_history(current_user: dict = Depends(get_current_user)):
    user_name = current_user["username"]
    db = db_manager.load_db()
    
    user_record = next((u for u in db["users"] if u["username"] == user_name), None)
    if not user_record:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")

    # Veritabanından kullanıcının sohbet geçmişini döndür
    return {"history": user_record.get("chat_history", [])}

@app.post("/api/chat")
async def chat_message(request: Request, current_user: dict = Depends(get_current_user)):
    user_name = current_user["username"]
    
    form_data = await request.form()
    user_message = form_data.get("message")
    
    if not user_message:
        raise HTTPException(status_code=400, detail="Mesaj boş olamaz")

    # DB'yi yükle ve kullanıcıyı bul
    db = db_manager.load_db()
    user_index, user_record = next(((i, u) for i, u in enumerate(db["users"]) if u["username"] == user_name), (None, None))
    if user_record is None: raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")
    
    # Mevcut sohbet geçmişini al
    current_history = user_record.get("chat_history", [])
    
    # Kullanıcı mesajını history'ye ekle
    user_msg_record = ChatMessage(sender="user", content=user_message).dict()
    current_history.append(user_msg_record)
    
    # AI yanıtını al (Tüm geçmişi context olarak kullan)
    ai_response_content = ai_assistant.generate_response(current_history, user_message)
    
    # AI yanıtını history'ye ekle
    ai_msg_record = ChatMessage(sender="ai", content=ai_response_content).dict()
    current_history.append(ai_msg_record)
    
    # Güncellenmiş history'yi kullanıcı kaydına geri kaydet
    db["users"][user_index]["chat_history"] = current_history
    db_manager.save_db(db)
    
    return {"user_message": user_message, "ai_response": ai_response_content}


@app.get("/api/admin/users")
async def get_users(current_user: dict = Depends(get_current_user)):
    """Tüm kullanıcıları listeler (Yalnızca Super Admin)."""
    # Yetkilendirme kontrolü JWT ile yapılıyor
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Erişim Reddedildi: Yalnızca Super Admin yetkisi gereklidir.")

    db = db_manager.load_db()
    # Şifre alanını güvenlik nedeniyle kaldırma
    users_clean = [{"username": u["username"], "role": u["role"], "id": u["id"]} for u in db["users"]]
    return {"users": users_clean}

# SADECE SUPER ADMIN İÇİN KULLANICI EKLEME/SİLME FONKSİYONLARI 
@app.post("/api/admin/user_action")
async def user_action(action: str = Form(...), username: str = Form(...), password: Optional[str] = Form(None), role: Optional[str] = Form("user"), current_user: dict = Depends(get_current_user)):
    # Yetkilendirme kontrolü JWT ile yapılıyor
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Erişim Reddedildi: Yalnızca Super Admin yetkisi gereklidir.")

    db = db_manager.load_db()

    if action == "add":
        if not password:
            raise HTTPException(status_code=400, detail="Yeni kullanıcı için şifre zorunludur.")
        if any(u["username"] == username for u in db["users"]):
            raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten mevcut.")
        
        # Yeni kullanıcı ekle
        hashed_password = pwd_context.hash(password)
        # Yeni kullanıcı varsayılan olarak boş bir chat_history ile eklenir
        new_user = User(id=str(uuid.uuid4()), username=username, password=hashed_password, role=role, chat_history=[]).dict()
        db["users"].append(new_user)
        db_manager.save_db(db)
        return {"status": "success", "message": f"Kullanıcı '{username}' ({role}) başarıyla eklendi."}

    elif action == "delete":
        if username == "enes": # Super admin'i silmeyi engelle
            raise HTTPException(status_code=403, detail="Varsayılan Super Admin silinemez.")
        
        # Kullanıcıyı sil
        initial_count = len(db["users"])
        db["users"] = [u for u in db["users"] if u["username"] != username]
        if len(db["users"]) == initial_count:
            raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")
        
        db_manager.save_db(db)
        return {"status": "success", "message": f"Kullanıcı '{username}' başarıyla silindi."}

    raise HTTPException(status_code=400, detail="Geçersiz eylem.")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    # Ana sayfa HTML içeriği
    html_content = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Gelişmiş Cevap Motoru</title>
    <style>
        /* CSS kodları önceki haliyle aynı */
        :root {{
            --bg-dark: #1e1e2d;
            --bg-light: #27293d;
            --text-light: #e0e0e0;
            --text-muted: #80809b;
            --primary: #5d5dff;
            --secondary: #ff5d9e;
            --border-color: #3f405c;
            --input-bg: #19192b;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        body {{
            background-color: var(--bg-dark);
            color: var(--text-light);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        #authSection, #dashboard {{
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            padding: 40px;
            background-color: var(--bg-light);
            max-width: 450px;
            width: 90%;
            display: none;
            flex-direction: column;
            gap: 20px;
        }}
        h1 {{
            color: var(--primary);
            text-align: center;
            font-size: 28px;
            margin-bottom: 20px;
        }}
        form {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        input[type="text"], input[type="password"] {{
            padding: 12px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background-color: var(--input-bg);
            color: var(--text-light);
            font-size: 16px;
            transition: border-color 0.3s;
        }}
        input[type="text"]:focus, input[type="password"]:focus {{
            border-color: var(--primary);
            outline: none;
        }}
        button {{
            padding: 12px;
            border: none;
            border-radius: 8px;
            background-color: var(--primary);
            color: white;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
        }}
        button:hover {{
            background-color: #4b4bd8;
        }}
        #dashboard {{
            max-width: 1200px;
            height: 90vh;
            display: grid;
            grid-template-columns: 250px 1fr;
            padding: 0;
            gap: 0;
            overflow: hidden;
            background-color: var(--bg-dark);
        }}
        #sidebar {{
            background-color: var(--bg-light);
            padding: 20px 0;
            display: flex;
            flex-direction: column;
            gap: 10px;
            border-right: 1px solid var(--border-color);
        }}
        .menu-header {{
            padding: 0 20px 20px;
            font-size: 24px;
            font-weight: bold;
            color: var(--secondary);
            text-align: center;
        }}
        .nav-link {{
            padding: 12px 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            transition: background-color 0.2s, color 0.2s;
            color: var(--text-muted);
            font-size: 16px;
        }}
        .nav-link:hover, .nav-link.active {{
            background-color: var(--border-color);
            color: var(--text-light);
        }}
        #userInfo {{
            padding: 10px 20px;
            border-top: 1px solid var(--border-color);
            margin-top: auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: var(--text-muted);
            font-size: 14px;
        }}
        #logoutButton {{
            background-color: #dc3545;
            padding: 8px 15px;
            font-size: 14px;
        }}
        #logoutButton:hover {{
            background-color: #c82333;
        }}
        #content {{
            padding: 20px;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }}
        .tab-content {{
            display: none;
            flex-direction: column;
            height: 100%;
        }}
        .tab-content.active {{
            display: flex;
        }}
        #chatContent {{
            flex-grow: 1;
            overflow-y: auto;
            padding: 10px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 15px;
        }}
        .message {{
            margin-bottom: 15px;
            max-width: 80%;
            padding: 10px 15px;
            border-radius: 18px;
            line-height: 1.5;
        }}
        .user-message {{
            background-color: var(--primary);
            color: white;
            align-self: flex-end;
            margin-left: auto;
            border-bottom-right-radius: 2px;
        }}
        .ai-message {{
            background-color: var(--bg-light);
            color: var(--text-light);
            align-self: flex-start;
            border: 1px solid var(--border-color);
            border-bottom-left-radius: 2px;
        }}
        #chatForm {{
            display: flex;
            gap: 10px;
            padding-bottom: 10px;
        }}
        #chatInput {{
            flex-grow: 1;
            padding: 12px;
            border-radius: 25px;
            background-color: var(--input-bg);
            border: 1px solid var(--border-color);
            color: var(--text-light);
        }}
        #chatSendBtn {{
            width: 100px;
            border-radius: 25px;
            background-color: var(--secondary);
        }}
        #chatSendBtn:hover {{
            background-color: #e04a85;
        }}
        .tab-title {{
            font-size: 24px;
            margin-bottom: 20px;
            color: var(--primary);
        }}
        .admin-section {{
            margin-bottom: 30px;
            padding: 20px;
            background-color: var(--bg-light);
            border-radius: 8px;
        }}
        .admin-section h3 {{
            color: var(--secondary);
            margin-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }}
        .admin-form {{
            display: flex;
            gap: 10px;
            align-items: center;
        }}
        .admin-form input, .admin-form select {{
            padding: 10px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            background-color: var(--input-bg);
            color: var(--text-light);
        }}
        .admin-form button {{
            padding: 10px 15px;
            white-space: nowrap;
        }}
        #userList {{
            list-style: none;
            padding: 0;
            margin-top: 15px;
        }}
        #userList li {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px dashed var(--border-color);
        }}
        #userList li:last-child {{
            border-bottom: none;
        }}
        .delete-btn {{
            background-color: #dc3545;
            padding: 5px 10px;
        }}
        .delete-btn:hover {{
            background-color: #c82333;
        }}

        @media (max-width: 768px) {{
            #dashboard {{
                grid-template-columns: 1fr;
                grid-template-rows: 60px 1fr;
                height: 100vh;
                max-width: none;
            }}
            #sidebar {{
                flex-direction: row;
                justify-content: space-around;
                align-items: center;
                border-right: none;
                border-bottom: 1px solid var(--border-color);
                padding: 0;
            }}
            .menu-header, #userInfo {{
                display: none;
            }}
            .nav-link {{
                padding: 10px;
                gap: 5px;
                flex-direction: column;
                font-size: 12px;
                text-align: center;
            }}
            .nav-link span {{
                display: none;
            }}
            #content {{
                padding: 10px;
            }}
        }}
    </style>
</head>
<body>

    <section id="authSection">
        <h1 style="color:var(--secondary);">AURION</h1>
        <form id="loginForm">
            <h2 style="color:var(--text-light); text-align:center;">Giriş</h2> 
            <input type="text" id="username" name="username" placeholder="Kullanıcı Adı" required>
            <input type="password" id="password" name="password" placeholder="Şifre" required>
            <button type="submit">Giriş Yap</button>
        </form>
    </section>

    <section id="dashboard" style="display: none;">
        <div id="sidebar">
            <div class="menu-header">AURION</div>
            
            <a class="nav-link active" data-tab="chat" onclick="switchTab('chat')">
                <span class="icon">💬</span> <span>Chat & AI</span>
            </a>
            
            <a class="nav-link" data-tab="admin" onclick="switchTab('admin')">
                <span class="icon">👥</span> <span>Admin Panel (Users)</span>
            </a>

            <a class="nav-link" data-tab="anime" onclick="switchTab('anime')">
                <span class="icon">🎬</span> <span>Anime Producer</span>
            </a>

            <a class="nav-link" data-tab="minecraft" onclick="switchTab('minecraft')">
                <span class="icon">🤖</span> <span>Minecraft BotNet</span>
            </a>
            
            <div id="userInfo">
                <div>
                    <span id="currentUsername"></span> (<span id="currentUserRole"></span>)
                </div>
                <button id="logoutButton" onclick="logout()">Çıkış</button>
            </div>
        </div>

        <div id="content">
            
            <div id="chat" class="tab-content active">
                <h2 class="tab-title">Gelişmiş Cevap Motoru</h2>
                <div id="chatContent">
                    </div>
                <form id="chatForm">
                    <input type="text" id="chatInput" name="message" placeholder="Ask Aurion or Type / for commands" required>
                    <button type="submit" id="chatSendBtn">Gönder</button>
                </form>
            </div>

            <div id="admin" class="tab-content">
                <h2 class="tab-title">Kullanıcı Yönetimi (Super Admin)</h2>
                
                <div class="admin-section">
                    <h3>Kullanıcı Ekle</h3>
                    <form id="addUserForm" class="admin-form">
                        <input type="text" name="username" placeholder="Kullanıcı Adı" required>
                        <input type="password" name="password" placeholder="Şifre" required>
                        <select name="role">
                            <option value="user">User</option>
                            <option value="super_admin">Super Admin</option>
                        </select>
                        <button type="submit">Kullanıcı Ekle</button>
                    </form>
                </div>

                <div class="admin-section">
                    <h3>Mevcut Kullanıcılar</h3>
                    <ul id="userList">
                        </ul>
                </div>
                
                <div id="adminMessage" style="margin-top: 15px; color: yellow;"></div>
            </div>

            <div id="anime" class="tab-content">
                <h2 class="tab-title">Anime Üretici (Geliştirme Aşamasında)</h2>
                <p style="color:var(--text-muted);">Bu özellik, yalnızca Super Adminler için hazırlanmaktadır. Yakında daha fazla detay eklenecektir.</p>
            </div>

            <div id="minecraft" class="tab-content">
                <h2 class="tab-title">Minecraft Bot Kontrolü (Geliştirme Aşamasında)</h2>
                <p style="color:var(--text-muted);">Bu özellik, yalnızca Super Adminler için hazırlanmaktadır. Yakında daha fazla detay eklenecektir.</p>
            </div>
        </div>
    </section>

    <script>
        // ----- Yardımcı Fonksiyonlar -----

        function getCookie(name) {{
            const nameEQ = name + "=";
            const ca = document.cookie.split(';');
            for(let i = 0; i < ca.length; i++) {{
                let c = ca[i];
                while (c.charAt(0) === ' ') c = c.substring(1, c.length);
                if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
            }}
            return null;
        }}

        function deleteCookie(name) {{
            document.cookie = name + '=; Max-Age=-99999999; path=/';
        }}

        function switchTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            const targetTab = document.getElementById(tabId);
            if(targetTab) {{
                targetTab.classList.add('active');
            }}
            
            document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
            const targetLink = document.querySelector(`.nav-link[data-tab="${{tabId}}"]`);
            if(targetLink) {{
                targetLink.classList.add('active');
            }}
            
            if (tabId === 'admin') {{
                loadUserList();
            }} else if (tabId === 'chat') {{
                loadChatHistory(); // Chat sekmesi açıldığında geçmişi yükle
            }}
        }}

        // ----- Kullanıcı Arayüzü Yönetimi -----

        function updateMenuVisibility(userRole) {{
            const adminTabs = ['admin', 'minecraft', 'anime']; 
            
            adminTabs.forEach(tab => {{
                const link = document.querySelector(`.nav-link[data-tab="${{tab}}"]`);
                if (link) {{
                    if (userRole !== 'super_admin') {{
                        link.style.display = 'none';
                    }} else {{
                        link.style.display = 'flex';
                    }}
                }}
            }});
        }}

        async function showDashboard() {{
            const userName = getCookie('user_name');
            const userRole = getCookie('user_role');

            if (userName && userRole) {{
                document.getElementById('authSection').style.display = 'none';
                document.getElementById('dashboard').style.display = 'grid';
                
                document.getElementById('currentUsername').textContent = userName;
                document.getElementById('currentUserRole').textContent = userRole;

                updateMenuVisibility(userRole); 

                switchTab('chat'); // Her zaman chat sekmesinde başla ve geçmişi yükle
            } else {{
                document.getElementById('authSection').style.display = 'flex';
                document.getElementById('dashboard').style.display = 'none';
            }}
        }}

        function logout() {{
            deleteCookie('access_token');
            deleteCookie('user_name');
            deleteCookie('user_role');
            window.location.reload();
        }}

        // ----- Login İşlemi -----
        document.getElementById('loginForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const form = e.target;
            const formData = new FormData(form);
            const response = await fetch('/api/login', {{
                method: 'POST',
                body: new URLSearchParams(formData)
            }});
            if (response.redirected) {{
                window.location.href = response.url;
            }} else {{
                const error = await response.json();
                alert('Giriş Hatası: ' + error.detail);
            }}
        }});
        
        // ----- Sohbet İşlemleri -----

        function scrollToBottom() {{
            const chatContent = document.getElementById('chatContent');
            chatContent.scrollTop = chatContent.scrollHeight;
        }}
        
        // Sohbet baloncuğu ekle
        function addMessage(sender, content, isError = false, shouldScroll = true) {{
            const chatContent = document.getElementById('chatContent');
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('message');
            messageDiv.classList.add(sender === 'user' ? 'user-message' : 'ai-message');
            
            if (isError) {{
                 messageDiv.style.backgroundColor = '#dc3545';
                 messageDiv.style.color = 'white';
            }}

            messageDiv.textContent = content;
            chatContent.appendChild(messageDiv);
            if (shouldScroll) {{
                scrollToBottom();
            }}
        }}
        
        function addLoadingMessage() {{
            const chatContent = document.getElementById('chatContent');
            const loadingId = 'loading-' + Date.now();
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('message', 'ai-message');
            messageDiv.id = loadingId;
            messageDiv.innerHTML = '<span>AI düşünüyor...</span>';
            chatContent.appendChild(messageDiv);
            scrollToBottom();
            return loadingId;
        }}

        function removeMessage(id) {{
            const element = document.getElementById(id);
            if (element) {{
                element.remove();
            }}
        }}
        
        // Kullanıcıya özel geçmişi yükle
        async function loadChatHistory() {{
            const chatContent = document.getElementById('chatContent');
            chatContent.innerHTML = ''; // Önce temizle
            
            try {{
                const response = await fetch('/api/chat_history');
                if (!response.ok) {{
                    throw new Error("Geçmiş yüklenemedi.");
                }}
                const data = await response.json();
                
                data.history.forEach(msg => {{
                    // Tarihçe yüklenirken scroll yapma, en sonda bir kere yap
                    addMessage(msg.sender, msg.content, false, false); 
                }});
                scrollToBottom();
            }} catch (error) {{
                addMessage('ai', 'Sohbet geçmişiniz yüklenirken hata oluştu.', true);
                console.error('Chat history error:', error);
            }}
        }}


        // Sohbet formunu gönder
        document.getElementById('chatForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const input = document.getElementById('chatInput');
            const message = input.value.trim();
            if (!message) return;

            addMessage('user', message);
            input.value = '';
            
            const loadingMsgId = addLoadingMessage();
            
            try {{
                const formData = new FormData();
                formData.append('message', message);
                
                const response = await fetch('/api/chat', {{
                    method: 'POST',
                    body: formData
                }});

                const data = await response.json();
                
                removeMessage(loadingMsgId);
                
                addMessage('ai', data.ai_response);
                
            }} catch (error) {{
                removeMessage(loadingMsgId);
                addMessage('ai', 'Bağlantı veya sunucu hatası oluştu.', true);
                console.error('Chat error:', error);
            }}
        }});
        
        // ----- Admin Panel İşlemleri -----

        async function loadUserList() {{
            const userListElement = document.getElementById('userList');
            const adminMsg = document.getElementById('adminMessage');
            userListElement.innerHTML = '';
            adminMsg.textContent = 'Kullanıcılar yükleniyor...';

            try {{
                const response = await fetch('/api/admin/users');
                const result = await response.json();

                if (response.status === 403) {{
                    userListElement.innerHTML = '<li>Bu bölüme erişim yetkiniz yok.</li>';
                    adminMsg.textContent = result.detail || 'Erişim Hatası.';
                    return;
                }}
                
                if (!response.ok) {{
                    adminMsg.textContent = result.detail || 'Kullanıcı listesi yüklenirken bilinmeyen hata oluştu.';
                    return;
                }}
                
                const users = result.users || [];
                adminMsg.textContent = `Toplam ${{users.length}} kullanıcı bulundu.`;

                users.forEach(user => {{
                    const li = document.createElement('li');
                    li.innerHTML = `
                        <span>${{user.username}} (${{user.role}})</span>
                        <button class="delete-btn" data-username="${{user.username}}">Sil</button>
                    `;
                    userListElement.appendChild(li);
                }});

                userListElement.querySelectorAll('.delete-btn').forEach(button => {{
                    button.addEventListener('click', async (e) => {{
                        const usernameToDelete = e.target.getAttribute('data-username');
                        if (usernameToDelete === 'enes') {{
                             alert('Varsayılan Super Admin silinemez.');
                             return;
                        }}
                        if (confirm(`Kullanıcı ${{usernameToDelete}} silinsin mi?`)) {{
                            await deleteUser(usernameToDelete);
                        }}
                    }});
                }});


            } catch (error) {{
                adminMsg.textContent = 'Kullanıcı listesi yüklenirken ağ hatası oluştu.';
                console.error('Kullanıcı listesi hatası:', error);
            }}
        }}

        // Kullanıcı Ekleme Formu
        document.getElementById('addUserForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const form = e.target;
            const formData = new FormData(form);
            formData.append('action', 'add');
            
            const response = await fetch('/api/admin/user_action', {{
                method: 'POST',
                body: new URLSearchParams(formData)
            }});

            const result = await response.json();
            document.getElementById('adminMessage').textContent = result.message || result.detail;
            if (response.ok) {{
                form.reset();
                loadUserList();
            }} else {{
                 alert('Hata: ' + result.detail);
            }}
        }});

        // Kullanıcı Silme İşlemi
        async function deleteUser(username) {{
            const formData = new FormData();
            formData.append('action', 'delete');
            formData.append('username', username);

            const response = await fetch('/api/admin/user_action', {{
                method: 'POST',
                body: new URLSearchParams(formData)
            }});

            const result = await response.json();
            document.getElementById('adminMessage').textContent = result.message || result.detail;
            if (response.ok) {{
                loadUserList();
            }} else {{
                alert('Silme Hatası: ' + result.detail);
            }}
        }}

        window.onload = showDashboard;
        
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content, status_code=200)
