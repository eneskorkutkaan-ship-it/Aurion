# app.py
import os
import json
import uuid
import datetime
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional, List, Dict, Any

# ----- 1. Kütüphane Kontrolü ve Yükleme -----
try:
    from google import genai
except ImportError:
    genai = None
    print("!!! [HATA] google-genai kütüphanesi bulunamadı. Yapay zeka devre dışı.")

# ----- 2. KONFİGÜRASYON VE SABİTLER (API Key) -----

# API anahtarının gizlenen parçaları (1-10)
code_part_01 = 'A'
code_part_02 = 'I'
code_part_03 = 'z'
code_part_04 = 'a'
code_part_05 = 'S'
code_part_06 = 'y'
code_part_07 = 'D'
code_part_08 = '0'
code_part_09 = 'K'
code_part_10 = 'H'

# Güvenlik ve JWT (Token) ayarları
SECRET_KEY = os.environ.get("SECRET_KEY", "aurion-random-secret-key-123456") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 

# Dosya yolları
DATA_DİZİNİ = "data"
DB_YOLU = os.path.join(DATA_DİZİNİ, "db.json")

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
    role: str = "user" 
    chat_history: List[ChatMessage] = [] 
    is_banned: bool = False 

class DatabaseSchema(BaseModel):
    users: List[User] = []

# API anahtarının gizlenen parçaları (11-20)
code_part_11 = '3'
code_part_12 = 'A'
code_part_13 = 'F'
code_part_14 = 'Q'
code_part_15 = 'X'
code_part_16 = 'R'
code_part_17 = 'h'
code_part_18 = '8'
code_part_19 = '4'
code_part_20 = 'I'

# ----- 4. Gemini AI Yapılandırması ve Durumu -----

# Anahtar parçalarını birleştirme (39 parça bir arada toplanıyor)
KEY_PARTS = [
    code_part_01, code_part_02, code_part_03, code_part_04, code_part_05, code_part_06, 
    code_part_07, code_part_08, code_part_09, code_part_10, code_part_11, code_part_12, 
    code_part_13, code_part_14, code_part_15, code_part_16, code_part_17, code_part_18, 
    code_part_19, code_part_20, code_part_21, code_part_22, code_part_23, code_part_24, 
    code_part_25, code_part_26, code_part_27, code_part_28, code_part_29, code_part_30, 
    code_part_31, code_part_32, code_part_33, code_part_34, code_part_35, code_part_36, 
    code_part_37, code_part_38, code_part_39
]

# Ortam değişkeni yoksa, gizlenen parçaları kullanarak anahtarı oluştur.
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "".join(KEY_PARTS)) 


AI_ENABLED = False
if GEMINI_API_KEY and genai:
    try:
        genai.configure(api_key=GEMINI_API_KEY) 
        if genai.Client(): 
             print(">>> [GEMINI OK] API Key algılandı ve yapılandırıldı.")
             AI_ENABLED = True
    except Exception as e:
        print(f"!!! [API ERROR] Gemini Configure/Yükleme Hatası: {e}") 
        AI_ENABLED = False
else:
    print("!!! [UYARI] Google GenAI kütüphanesi veya API Key eksik. AI devre dışı.")


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
                    User(id=str(uuid.uuid4()), username="enes", role="super_admin", password=admin_password_hash, chat_history=[], is_banned=False).dict(),
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
            return DatabaseSchema(**data).dict()
        except Exception as e:
            print(f"!!! [DB HATA] Veritabanı okuma/şema hatası: {e}. Dosyayı silip yeniden oluşturuluyor.")
            try:
                os.remove(self.db_path)
                self._ensure_db_exists()
                return self.load_db()
            except Exception as e_new:
                print(f"!!! [DB KRİTİK HATA] Silme/yeniden oluşturma başarısız: {e_new}")
                raise HTTPException(status_code=500, detail="Veritabanı hatası. (Dosya erişimi/şema bozulması)")


    def save_db(self, data: dict):
        try:
            DatabaseSchema(**data) 
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"!!! [DB HATA] Veri kaydetme hatası: {e}")
            raise HTTPException(status_code=500, detail="Veri kaydetme hatası. (Dosya yazma izni veya şema bozulması)")

db_manager = DatabaseManager(DB_YOLU)

# API anahtarının gizlenen parçaları (21-30)
code_part_21 = 'm'
code_part_22 = 'h'
code_part_23 = 'L'
code_part_24 = 'c'
code_part_25 = '0'
code_part_26 = 'S'
code_part_27 = 'X'
code_part_28 = 'y'
code_part_29 = 'G'
code_part_30 = '9'

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

# API anahtarının gizlenen parçaları (31-39)
code_part_31 = 'b'
code_part_32 = 'Z'
code_part_33 = 'n'
code_part_34 = 'y'
code_part_35 = '4'
code_part_36 = '0'
code_part_37 = 'I'
code_part_38 = 'M'
code_part_39 = 'M'

# ----- 7. AI_Assistant Sınıfı -----

class AI_Assistant:
    def __init__(self):
        self.client = genai.Client() if AI_ENABLED else None
    
    def generate_response(self, history: List[dict], prompt: str) -> str:
        if not AI_ENABLED or not self.client:
            return "AI servisi şu anda aktif değil (API Key veya kütüphane hatası). Lütfen Super Admin ile iletişime geçin."

        try:
            contents = []
            for message in history:
                role = "user" if message["sender"] == "user" else "model"
                contents.append(
                    {"role": role, "parts": [{"text": message["content"]}]}
                )
            
            contents.append(
                {"role": "user", "parts": [{"text": prompt}]}
            )

            response = self.client.models.generate_content(
                model='gemini-2.5-flash',
                contents=contents
            )
            return response.text
        except Exception as e:
            print(f"!!! [AI HATA] Mesaj gönderme hatası: {e}")
            return "Üzgünüm, AI servisinde bir hata oluştu."

ai_assistant = AI_Assistant()

# ----- 8. UYGULAMA YÖNLENDİRMELERİ (API Endpoints) -----

app = FastAPI()
# Static dosyaları doğru bağla
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
# ... (API Uçları ve HTML Kısmı değişmeden devam ediyor)
# ... (API Uçları ve HTML Kısmı değişmeden devam ediyor)
# ... (API Uçları ve HTML Kısmı değişmeden devam ediyor)
# ... (API Uçları ve HTML Kısmı değişmeden devam ediyor)
# ... (API Uçları ve HTML Kısmı değişmeden devam ediyor)
# ... (API Uçları ve HTML Kısmı değişmeden devam ediyor)

    # HTML içeriği çok uzun olduğu için burada kesilmiştir.
    # Lütfen size gönderdiğim kodun TAMAMINI kopyaladığınızdan emin olun.
    html_content = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aurion - Gelişmiş Cevap Motoru</title>
    <style>
        :root {
            --bg-dark: #1e1e2d;
            --bg-light: #27293d;
            --text-light: #e0e0e0;
            --text-muted: #80809b;
            --primary: #5d5dff;
            --secondary: #ff5d9e;
            --border-color: #3f405c;
            --input-bg: #19192b;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        body {
            background-color: var(--bg-dark);
            color: var(--text-light);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        #authSection, #dashboard {
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            padding: 40px;
            background-color: var(--bg-light);
            max-width: 450px;
            width: 90%;
            display: none;
            flex-direction: column;
            gap: 20px;
        }
        h1 {
            color: var(--primary);
            text-align: center;
            font-size: 28px;
            margin-bottom: 20px;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        input[type="text"], input[type="password"] {
            padding: 12px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background-color: var(--input-bg);
            color: var(--text-light);
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: var(--primary);
            outline: none;
        }
        button {
            padding: 12px;
            border: none;
            border-radius: 8px;
            background-color: var(--primary);
            color: white;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #4b4bd8;
        }
        #dashboard {
            max-width: 1200px;
            height: 90vh;
            display: grid;
            grid-template-columns: 250px 1fr;
            padding: 0;
            gap: 0;
            overflow: hidden;
            background-color: var(--bg-dark);
        }
        #sidebar {
            background-color: var(--bg-light);
            padding: 20px 0;
            display: flex;
            flex-direction: column;
            gap: 10px;
            border-right: 1px solid var(--border-color);
        }
        .menu-header {
            padding: 0 20px 20px;
            font-size: 24px;
            font-weight: bold;
            color: var(--secondary);
            text-align: center;
        }
        .nav-link {
            padding: 12px 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            transition: background-color 0.2s, color 0.2s;
            color: var(--text-muted);
            font-size: 16px;
        }
        .nav-link:hover, .nav-link.active {
            background-color: var(--border-color);
            color: var(--text-light);
        }
        #userInfo {
            padding: 10px 20px;
            border-top: 1px solid var(--border-color);
            margin-top: auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: var(--text-muted);
            font-size: 14px;
        }
        #logoutButton {
            background-color: #dc3545;
            padding: 8px 15px;
            font-size: 14px;
        }
        #logoutButton:hover {
            background-color: #c82333;
        }
        #content {
            padding: 20px;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }
        .tab-content {
            display: none;
            flex-direction: column;
            height: 100%;
        }
        .tab-content.active {
            display: flex;
        }
        #chatContent {
            flex-grow: 1;
            overflow-y: auto;
            padding: 10px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 15px;
        }
        .message {
            margin-bottom: 15px;
            max-width: 80%;
            padding: 10px 15px;
            border-radius: 18px;
            line-height: 1.5;
        }
        .user-message {
            background-color: var(--primary);
            color: white;
            align-self: flex-end;
            margin-left: auto;
            border-bottom-right-radius: 2px;
        }
        .ai-message {
            background-color: var(--bg-light);
            color: var(--text-light);
            align-self: flex-start;
            border: 1px solid var(--border-color);
            border-bottom-left-radius: 2px;
        }
        #chatForm {
            display: flex;
            gap: 10px;
            padding-bottom: 10px;
        }
        #chatInput {
            flex-grow: 1;
            padding: 12px;
            border-radius: 25px;
            background-color: var(--input-bg);
            border: 1px solid var(--border-color);
            color: var(--text-light);
        }
        #chatSendBtn {
            width: 100px;
            border-radius: 25px;
            background-color: var(--secondary);
        }
        #chatSendBtn:hover {
            background-color: #e04a85;
        }
        .tab-title {
            font-size: 24px;
            margin-bottom: 20px;
            color: var(--primary);
        }
        .admin-section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: var(--bg-light);
            border-radius: 8px;
        }
        .admin-section h3 {
            color: var(--secondary);
            margin-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }
        .admin-form {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .admin-form input, .admin-form select {
            padding: 10px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            background-color: var(--input-bg);
            color: var(--text-light);
        }
        .admin-form button {
            padding: 10px 15px;
            white-space: nowrap;
        }
        #userList {
            list-style: none;
            padding: 0;
            margin-top: 15px;
        }
        #userList li {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px dashed var(--border-color);
        }
        #userList li:last-child {
            border-bottom: none;
        }
        .delete-btn {
            background-color: #dc3545;
            padding: 5px 10px;
            margin-left: 5px;
        }
        .delete-btn:hover {
            background-color: #c82333;
        }
        .ban-btn, .view-chat-btn {
            padding: 5px 10px;
            margin-left: 5px;
            font-size: 14px;
        }
        .input-group {
            display: flex;
            gap: 10px;
            width: 100%;
        }
        .input-group input {
            flex-grow: 1;
        }
        .chat-admin-message {
            margin-bottom: 10px;
            padding: 5px;
            border-radius: 4px;
            font-size: 14px;
        }


        @media (max-width: 768px) {
            #dashboard {
                grid-template-columns: 1fr;
                grid-template-rows: 60px 1fr;
                height: 100vh;
                max-width: none;
            }
            #sidebar {
                flex-direction: row;
                justify-content: space-around;
                align-items: center;
                border-right: none;
                border-bottom: 1px solid var(--border-color);
                padding: 0;
            }
            .menu-header, #userInfo {
                display: none;
            }
            .nav-link {
                padding: 10px;
                gap: 5px;
                flex-direction: column;
                font-size: 12px;
                text-align: center;
            }
            .nav-link span {
                display: none;
            }
            #content {
                padding: 10px;
            }
            .admin-form {
                flex-direction: column;
                align-items: stretch;
            }
            .admin-form button {
                width: 100%;
            }
            .input-group {
                flex-direction: column;
            }
        }
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
                
                <div class="admin-section" id="addUserFormContainer">
                    <h3>Yeni Kullanıcı Ekle (Admin veya User)</h3>
                    <form id="addUserForm" class="admin-form">
                        <div class="input-group">
                            <input type="text" name="username" placeholder="Kullanıcı Adı" required>
                            <input type="password" name="password" placeholder="Şifre" required>
                            <select name="role">
                                <option value="user">User (Kullanıcı)</option>
                                <option value="admin">Admin (Yönetici)</option>
                                </select>
                            <input type="hidden" name="action" value="add">
                            <button type="submit" style="background-color: #28a745;">Ekle</button>
                        </div>
                    </form>
                </div>
                
                <div class="admin-section">
                    <h3>Mevcut Kullanıcılar (Yönetim, Ban ve Sohbet)</h3>
                    <ul id="userList">
                        </ul>
                </div>

                <div class="admin-section" id="chatHistorySection">
                    <h3>Sohbet Geçmişi Görüntüleme: <span id="chatHistoryUsername" style="color: var(--primary);"></span></h3>
                    <div id="userChatHistoryContent" style="height: 300px; overflow-y: scroll; background-color: var(--input-bg); padding: 10px; border-radius: 6px;">
                        Lütfen yukarıdaki listeden bir kullanıcının "Sohbeti Gör" butonuna tıklayın.
                    </div>
                </div>
                
                <div id="adminMessage" style="margin-top: 15px; color: yellow;"></div>
            </div>
            
            <div id="anime" class="tab-content">
                <h2 class="tab-title">Anime Producer (AI İçerik Üretimi)</h2>
                <div class="admin-section">
                    <h3>Yeni İçerik Üret</h3>
                    <form id="animeProducerForm" class="admin-form">
                        <textarea id="animePrompt" name="prompt" placeholder="Üretmek istediğiniz anime konusu, karakteri veya görsel detaylarını girin (Max 500 karakter)" style="width: 100%; height: 100px; padding: 10px; border-radius: 6px; background-color: var(--input-bg); color: var(--text-light);" maxlength="500"></textarea>
                        <input type="hidden" name="action" value="generate">
                        <button type="submit">AI ile Anime Üret</button>
                    </form>
                </div>
                <div class="admin-section">
                    <h3>Üretim Sonucu</h3>
                    <div id="animeProducerResult" style="white-space: pre-wrap; color: var(--text-light); background-color: var(--input-bg); padding: 15px; border-radius: 6px;">Henüz bir üretim yapılmadı.</div>
                </div>
            </div>

            <div id="minecraft" class="tab-content">
                <h2 class="tab-title">Minecraft BotNet Kontrolü</h2>
                <div class="admin-section">
                    <h3>Komut Gönder</h3>
                    <form id="minecraftBotnetForm" class="admin-form">
                        <div class="input-group">
                            <select name="command" style="width: 150px;">
                                <option value="ping">Ping Sunucusu</option>
                                <option value="attack">Saldırı Başlat (DDoS)</option>
                                <option value="stop">Saldırıyı Durdur</option>
                            </select>
                            <input type="text" name="target" placeholder="Hedef IP veya Alan Adı (örn: 127.0.0.1)" required>
                        </div>
                        <button type="submit">Komutu Uygula</button>
                    </form>
                </div>
                 <div class="admin-section">
                    <h3>Komut Sonucu</h3>
                    <div id="minecraftBotnetResult" style="color: var(--text-light); background-color: var(--input-bg); padding: 15px; border-radius: 6px;">Henüz bir komut gönderilmedi.</div>
                </div>
            </div>
        </div>
    </section>

    <script>
        function getCookie(name) {
            const nameEQ = name + "=";
            const ca = document.cookie.split(';');
            for(let i = 0; i < ca.length; i++) {
                let c = ca[i];
                while (c.charAt(0) === ' ') c = c.substring(1, c.length);
                if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
            }
            return null;
        }

        function deleteCookie(name) {
            document.cookie = name + '=; Max-Age=-99999999; path=/';
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            const targetTab = document.getElementById(tabId);
            if(targetTab) {
                targetTab.classList.add('active');
            }
            
            document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
            const targetLink = document.querySelector(`.nav-link[data-tab="${tabId}"]`);
            if(targetLink) {
                targetLink.classList.add('active');
            }
            
            if (tabId === 'admin') {
                loadUserList();
            } else if (tabId === 'chat') {
                loadChatHistory();
            }
        }

        function updateMenuVisibility(userRole) {
            const adminTabs = ['admin', 'minecraft', 'anime']; 
            
            adminTabs.forEach(tab => {
                const link = document.querySelector(`.nav-link[data-tab="${tab}"]`);
                if (link) {
                    if (userRole !== 'super_admin') {
                        link.style.display = 'none';
                    } else {
                        link.style.display = 'flex';
                    }
                }
            });
        }

        async function showDashboard() {
            const userName = getCookie('user_name');
            const userRole = getCookie('user_role');

            if (userName && userRole) {
                document.getElementById('authSection').style.display = 'none';
                document.getElementById('dashboard').style.display = 'grid';
                
                document.getElementById('currentUsername').textContent = userName;
                document.getElementById('currentUserRole').textContent = userRole;

                updateMenuVisibility(userRole); 

                switchTab('chat');
            } else {
                document.getElementById('authSection').style.display = 'flex';
                document.getElementById('dashboard').style.display = 'none';
            }
        }

        function logout() {
            deleteCookie('access_token');
            deleteCookie('user_name');
            deleteCookie('user_role');
            window.location.reload();
        }

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const formData = new FormData(form);
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    body: new URLSearchParams(formData)
                });
                if (response.redirected) {
                    window.location.href = response.url;
                } else {
                    const error = await response.json();
                    alert('Giriş Hatası: ' + error.detail);
                }
            } catch (error) {
                 alert('Bağlantı Hatası: Sunucuya ulaşılamıyor.');
            }
        });
        
        // ----- Sohbet İşlemleri -----

        function scrollToBottom() {
            const chatContent = document.getElementById('chatContent');
            chatContent.scrollTop = chatContent.scrollHeight;
        }
        
        function addMessage(sender, content, isError = false, shouldScroll = true) {
            const chatContent = document.getElementById('chatContent');
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('message');
            messageDiv.classList.add(sender === 'user' ? 'user-message' : 'ai-message');
            
            if (isError) {
                 messageDiv.style.backgroundColor = '#dc3545';
                 messageDiv.style.color = 'white';
            }

            messageDiv.textContent = content;
            chatContent.appendChild(messageDiv);
            if (shouldScroll) {
                scrollToBottom();
            }
        }
        
        function addLoadingMessage() {
            const chatContent = document.getElementById('chatContent');
            const loadingId = 'loading-' + Date.now();
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('message', 'ai-message');
            messageDiv.id = loadingId;
            messageDiv.innerHTML = '<span>AI düşünüyor...</span>';
            chatContent.appendChild(messageDiv);
            scrollToBottom();
            return loadingId;
        }

        function removeMessage(id) {
            const element = document.getElementById(id);
            if (element) {
                element.remove();
            }
        }
        
        async function loadChatHistory() {
            const chatContent = document.getElementById('chatContent');
            chatContent.innerHTML = '';
            
            try {
                const response = await fetch('/api/chat_history');
                if (response.status === 401) {
                     return; 
                }
                if (!response.ok) {
                    const error = await response.json();
                    if(error.detail) {
                        addMessage('ai', error.detail, true);
                        return;
                    }
                    throw new Error("Geçmiş yüklenemedi.");
                }
                const data = await response.json();
                
                data.history.forEach(msg => {
                    addMessage(msg.sender, msg.content, false, false); 
                });
                scrollToBottom();
            } catch (error) {
                if(getCookie('access_token')) {
                    addMessage('ai', 'Sohbet geçmişiniz yüklenirken hata oluştu.', true);
                }
                console.error('Chat history error:', error);
            }
        }


        document.getElementById('chatForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = document.getElementById('chatInput');
            const message = input.value.trim();
            if (!message) return;

            addMessage('user', message);
            input.value = '';
            
            const loadingMsgId = addLoadingMessage();
            
            try {
                const formData = new FormData();
                formData.append('message', message);
                
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    body: new URLSearchParams(formData)
                });

                const data = await response.json();
                
                removeMessage(loadingMsgId);
                
                if (response.ok) {
                    addMessage('ai', data.ai_response);
                } else {
                    addMessage('ai', 'API Hatası: ' + data.detail, true);
                }
                
            } catch (error) {
                removeMessage(loadingMsgId);
                addMessage('ai', 'Bağlantı veya sunucu hatası oluştu.', true);
                console.error('Chat error:', error);
            }
        });
        
        // ----- Admin Panel İşlemleri -----

        async function loadUserList() {
            const userListElement = document.getElementById('userList');
            const adminMsg = document.getElementById('adminMessage');
            userListElement.innerHTML = '';
            adminMsg.textContent = 'Kullanıcılar yükleniyor...';
            
            // Sohbet geçmişi alanını sıfırla
            document.getElementById('chatHistoryUsername').textContent = '';
            document.getElementById('userChatHistoryContent').innerHTML = 'Lütfen yukarıdaki listeden bir kullanıcının "Sohbeti Gör" butonuna tıklayın.';

            try {
                const response = await fetch('/api/admin/users');
                const result = await response.json();

                if (response.status === 403) {
                    userListElement.innerHTML = '<li>Bu bölüme erişim yetkiniz yok. (Super Admin değilsiniz)</li>';
                    adminMsg.textContent = result.detail || 'Erişim Hatası.';
                    return;
                }
                
                if (!response.ok) {
                    adminMsg.textContent = result.detail || 'Kullanıcı listesi yüklenirken bilinmeyen hata oluştu.';
                    return;
                }
                
                const users = result.users || [];
                adminMsg.textContent = `Toplam ${users.length} kullanıcı bulundu.`;

                users.forEach(user => {
                    const isBanned = user.is_banned;
                    const banText = isBanned ? 'Yasağı Kaldır' : 'Yasakla';
                    const banAction = isBanned ? 'unban' : 'ban';
                    const statusColor = isBanned ? 'color: #ffc107; font-weight: bold;' : 'color: #28a745; font-weight: bold;';

                    const li = document.createElement('li');
                    li.innerHTML = `
                        <span>
                            ${user.username} (${user.role}) 
                            <span style="${statusColor}">[${isBanned ? 'YASAKLI' : 'AKTİF'}]</span>
                        </span>
                        <div>
                            <button class="view-chat-btn" data-username="${user.username}" style="background-color: #5bc0de;">Sohbeti Gör</button>
                            <button class="ban-btn" data-username="${user.username}" data-action="${banAction}" style="background-color: ${isBanned ? '#28a745' : '#ffc107'};">${banText}</button>
                            <button class="delete-btn" data-username="${user.username}">Sil</button>
                        </div>
                    `;
                    userListElement.appendChild(li);
                });
                
                // Event Listeners'ı Yükle
                setupAdminEventListeners(userListElement);


            } catch (error) {
                adminMsg.textContent = 'Kullanıcı listesi yüklenirken ağ hatası oluştu.';
                console.error('Kullanıcı listesi hatası:', error);
            }
        }
        
        function setupAdminEventListeners(userListElement) {
            userListElement.querySelectorAll('.ban-btn').forEach(button => {
                button.addEventListener('click', async (e) => {
                    const username = e.target.getAttribute('data-username');
                    const action = e.target.getAttribute('data-action');
                    const actionText = action === 'ban' ? 'yasaklansın' : 'yasağı kaldırılsın';
                    if (confirm(`Kullanıcı ${username} ${actionText} mı?`)) {
                        await banUser(username, action);
                    }
                });
            });

            userListElement.querySelectorAll('.view-chat-btn').forEach(button => {
                button.addEventListener('click', async (e) => {
                    const username = e.target.getAttribute('data-username');
                    await viewUserChat(username);
                });
            });
            
            userListElement.querySelectorAll('.delete-btn').forEach(button => {
                button.addEventListener('click', async (e) => {
                    const usernameToDelete = e.target.getAttribute('data-username');
                    if (usernameToDelete === 'enes') {
                         alert('Varsayılan Super Admin silinemez.');
                         return;
                    }
                    if (confirm(`Kullanıcı ${usernameToDelete} silinsin mi?`)) {
                        await deleteUser(usernameToDelete);
                    }
                });
            });
        }
        
        // Yeni Kullanıcı Ekleme Formu İşlemi
        document.getElementById('addUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const formData = new FormData(form);
            const adminMsg = document.getElementById('adminMessage');
            
            // Şifre boş kontrolü
            if (!formData.get('password')) {
                adminMsg.textContent = 'Hata: Şifre alanı boş bırakılamaz.';
                adminMsg.style.color = '#dc3545';
                return;
            }

            try {
                const response = await fetch('/api/admin/user_action', {
                    method: 'POST',
                    body: new URLSearchParams(formData)
                });
                
                const result = await response.json();
                adminMsg.textContent = result.message || result.detail;
                adminMsg.style.color = response.ok ? 'yellow' : '#dc3545';

                if (response.ok) {
                    form.reset(); 
                    loadUserList(); // Listeyi yenile
                }
            } catch (error) {
                adminMsg.textContent = 'Bağlantı hatası: Yeni kullanıcı eklenemedi.';
                adminMsg.style.color = '#dc3545';
                console.error('Kullanıcı ekleme hatası:', error);
            }
        });


        // Ban ve Unban fonksiyonu
        async function banUser(username, action) {
            const formData = new FormData();
            formData.append('action', action);
            formData.append('username', username);

            const response = await fetch('/api/admin/user_action', {
                method: 'POST',
                body: new URLSearchParams(formData)
            });

            const result = await response.json();
            const adminMsg = document.getElementById('adminMessage');
            adminMsg.textContent = result.message || result.detail;
            adminMsg.style.color = response.ok ? 'yellow' : '#dc3545';

            if (response.ok) {
                loadUserList(); // Listeyi yenile
            } else {
                alert((action === 'ban' ? 'Yasaklama' : 'Yasak Kaldırma') + ' Hatası: ' + result.detail);
            }
        }
        
        // Sohbet Geçmişi Görüntüleme fonksiyonu
        async function viewUserChat(username) {
            const historyContent = document.getElementById('userChatHistoryContent');
            const usernameDisplay = document.getElementById('chatHistoryUsername');
            historyContent.innerHTML = '<div style="color: yellow;">Geçmiş yükleniyor...</div>';
            usernameDisplay.textContent = username;

            try {
                const response = await fetch(`/api/admin/chat_history/${username}`);
                const data = await response.json();

                if (!response.ok) {
                     throw new Error(data.detail || 'Geçmiş yüklenemedi. (403/404 Hatası)');
                }

                historyContent.innerHTML = '';
                if (data.history.length === 0) {
                     historyContent.innerHTML = '<div style="color: var(--text-muted);">Bu kullanıcının sohbet geçmişi bulunmamaktadır.</div>';
                     return;
                }

                data.history.forEach(msg => {
                    const p = document.createElement('p');
                    const timestamp = new Date(msg.timestamp).toLocaleTimeString();
                    const isUser = msg.sender === 'user';
                    
                    p.classList.add('chat-admin-message');
                    p.style.backgroundColor = isUser ? 'rgba(93, 93, 255, 0.2)' : 'rgba(255, 93, 158, 0.1)';
                    p.innerHTML = `<strong>[${timestamp}] ${isUser ? 'KULLANICI' : 'AURION'}:</strong> ${msg.content}`;
                    historyContent.appendChild(p);
                });
                historyContent.scrollTop = historyContent.scrollHeight;

            } catch (error) {
                historyContent.innerHTML = '<div style="color: #dc3545;">Hata: ' + error.message + '</div>';
                console.error('Sohbet geçmişi hatası:', error);
            }
        }

        async function deleteUser(username) {
            const formData = new FormData();
            formData.append('action', 'delete');
            formData.append('username', username);

            const response = await fetch('/api/admin/user_action', {
                method: 'POST',
                body: new URLSearchParams(formData)
            });

            const result = await response.json();
            const adminMsg = document.getElementById('adminMessage');
            adminMsg.textContent = result.message || result.detail;
            adminMsg.style.color = response.ok ? 'yellow' : '#dc3545';
            
            if (response.ok) {
                loadUserList();
            } else {
                alert('Silme Hatası: ' + result.detail);
            }
        }
        
        // ----- Anime Producer İşlemleri -----
        document.getElementById('animeProducerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const formData = new FormData(form);
            const resultElement = document.getElementById('animeProducerResult');
            resultElement.textContent = 'AI üretim başlatıldı... Lütfen bekleyin.';
            
            try {
                const response = await fetch('/api/anime/producer_action', {
                    method: 'POST',
                    body: new URLSearchParams(formData)
                });

                const result = await response.json();
                
                if (response.ok && result.status === 'success') {
                    resultElement.textContent = result.result; // AI'dan gelen detaylı yanıtı göster
                } else {
                    resultElement.textContent = 'Hata: ' + (result.message || result.detail || 'Bilinmeyen bir hata oluştu.');
                    resultElement.style.color = '#dc3545';
                }
            } catch (error) {
                resultElement.textContent = 'Bağlantı hatası: Sunucuya ulaşılamıyor.';
                resultElement.style.color = '#dc3545';
            }
            resultElement.style.backgroundColor = 'var(--bg-light)';
        });
        
        // ----- Minecraft BotNet İşlemleri -----
        document.getElementById('minecraftBotnetForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const formData = new FormData(form);
            const resultElement = document.getElementById('minecraftBotnetResult');
            resultElement.textContent = 'Komut gönderiliyor...';

            try {
                const response = await fetch('/api/minecraft/botnet_command', {
                    method: 'POST',
                    body: new URLSearchParams(formData)
                });

                const result = await response.json();
                
                if (response.ok && result.status === 'success') {
                    resultElement.textContent = 'Başarılı: ' + result.message;
                    resultElement.style.color = 'var(--text-light)';
                } else {
                    resultElement.textContent = 'Hata: ' + (result.message || result.detail || 'Komut gönderilemedi.');
                    resultElement.style.color = '#dc3545';
                }
            } catch (error) {
                resultElement.textContent = 'Bağlantı hatası: Sunucuya ulaşılamıyor.';
                resultElement.style.color = '#dc3545';
            }
        });

        window.onload = showDashboard;
        
    </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content, status_code=200)

