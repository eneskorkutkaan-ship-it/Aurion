from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import json
import os
import uuid
import asyncio
import time
import random
from pathlib import Path

# =========================================================
# KÜTÜPHANE İÇE AKTARMA VE AYAR KONTROLÜ
# =========================================================

# Google Gemini AI - İçe Aktarma ve Yapılandırma
try:
    import google.generativeai as genai
    from google.generativeai.errors import APIError
except ImportError:
    genai = None
    APIError = Exception
    print("!!! [GEMINI] 'google-genai' kütüphanesi bulunamadı.")
    
# Text-to-Speech (pyttsx3) - İçe Aktarma Kontrolü
try:
    import pyttsx3
except ImportError:
    pyttsx3 = None
    print("!!! [TTS] 'pyttsx3' kütüphanesi bulunamadı. Ses özellikleri çalışmayabilir.")

# ====== KONFİGÜRASYON VE SABİTLER ======
SECRET_KEY = "aurion-super-secret-key-2025"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440 # 24 saat
DB_FILE = Path("aurion_db.json")

# Worker Ayarları (Simülasyon Hızları)
WORKER_LOOP_INTERVAL = 5 # Worker'ların çalışma sıklığı (saniye)
VIDEO_PRODUCTION_TIME = 90 # Tam Bölüm Üretim Simülasyonu (saniye)
MINECRAFT_ACTION_TIME = 15 # Minecraft görev simülasyonu (saniye)

# Super Admin Kullanıcı Bilgileri
SUPER_ADMIN_USERNAME = "enes"
SUPER_ADMIN_PASSWORD = "enes13579"

# Gemini API Kontrolü ve Yapılandırması
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if GEMINI_API_KEY and genai:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print(">>> [GEMINI OK] API Key algılandı ve yapılandırıldı.")
    except Exception as e:
        print(f"!!! [API ERROR] Gemini Configure Hatası: {e}")
else:
    print("!!! [GEMINI MISSING] GEMINI_API_KEY eksik veya genai yüklenemedi. AI özellikleri devre dışı.")


# =========================================================
# VERİTABANI SINIFI (ASENKRON GÜVENLİ)
# =========================================================

class Database:
    """Veritabanı işlemlerini asenkron olarak yöneten sınıf (JSON tabanlı)."""
    
    def __init__(self):
        self.data = self.load_sync()
        
    def load_sync(self):
        if DB_FILE.exists():
            try:
                with open(DB_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print("!!! [DB INIT ERROR] Veritabanı bozuk veya okunamıyor. Yeni veritabanı kuruluyor.")
                return self._default_data()
        print(">>> [DB INIT START] Veritabanı oluşturuluyor.")
        return self._default_data()

    def _default_data(self):
        return {
            "users": [],
            "chats": [],
            "commands": [],
            "bans": [],
            "minecraft_bots": [],
            "anime_videos": []
        }

    # Asenkron I/O işlemleri için helper fonksiyonlar
    async def load(self):
        return await asyncio.to_thread(self.load_sync) 

    def save_sync(self, data):
        """Veriyi senkron olarak JSON dosyasına kaydeder."""
        try:
            temp_file = DB_FILE.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            temp_file.replace(DB_FILE)
        except Exception as e:
            print(f"!!! [DB WRITE ERROR] Kayıt hatası: {e}")

    async def save(self):
        """Veriyi asenkron olarak kaydeder."""
        await asyncio.to_thread(self.save_sync, self.data.copy())
    
    # Veri Erişim Metotları (Basitlik İçin Asenkron Kalır)
    async def get_users(self):
        return self.data.get("users", [])

    async def get_user(self, username):
        for user in self.data["users"]:
            if user["username"] == username:
                return user
        return None
    
    async def add_user(self, user):
        if await self.get_user(user['username']):
            return False
        self.data["users"].append(user)
        await self.save()
        return True
    
    async def update_user(self, username, updates):
        for user in self.data["users"]:
            if user["username"] == username:
                user.update(updates)
                await self.save()
                return True
        return False
    
    async def is_banned(self, username):
        for ban in self.data["bans"]:
            if ban["username"] == username and ban["active"]:
                return True
        return False
    
    # ... (Diğer basit veritabanı metotları burada devam eder) ...
    async def add_chat(self, chat):
        self.data["chats"].append(chat)
        await self.save()
    
    async def get_chats(self, username):
        return [c for c in self.data["chats"] if c["username"] == username]
    
    async def clear_chats(self, username):
        self.data["chats"] = [c for c in self.data["chats"] if c["username"] != username]
        await self.save()

    async def add_command(self, command):
        self.data["commands"].append(command)
        await self.save()
    
    async def add_ban(self, ban):
        self.data["bans"].append(ban)
        await self.save()
    
    async def get_bans(self):
        return self.data["bans"]
    
    async def add_minecraft_bot(self, bot):
        bot["current_task"] = None
        bot["screen_url"] = None
        self.data["minecraft_bots"].append(bot)
        await self.save()
    
    async def update_minecraft_bot(self, bot_id, updates):
        for bot in self.data["minecraft_bots"]:
            if bot["id"] == bot_id:
                bot.update(updates)
                await self.save()
                return True
        return False
    
    async def get_minecraft_bots(self):
        return self.data.get("minecraft_bots", [])
    
    async def add_anime_video(self, video):
        if video.get("status") == "completed": 
            video["status"] = "video_pending"
        self.data["anime_videos"].append(video)
        await self.save()
    
    async def update_anime_video(self, video_id, updates):
        for video in self.data["anime_videos"]:
            if video["id"] == video_id:
                video.update(updates)
                await self.save()
                return True
        return False
    
    async def get_anime_videos(self, username):
        return [v for v in self.data["anime_videos"] if v["created_by"] == username]

db = Database()

# =========================================================
# GÜVENLİK, AUTH VE MODELLER
# =========================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """JWT token'ı doğrular ve mevcut kullanıcıyı döndürür."""
    token = credentials.credentials
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if await db.is_banned(username):
        raise HTTPException(status_code=403, detail="User is banned")
    
    user = await db.get_user(username)
    
    # Super Admin özel durumu
    if user is None and username == SUPER_ADMIN_USERNAME:
        return {
            "username": SUPER_ADMIN_USERNAME,
            "role": "super_admin",
            "created_at": datetime.utcnow().isoformat()
        }
    
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

# Pydantic Modelleri (API istek/yanıt tipleri)
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    message: str
    mode: Optional[str] = "arkadaş" # Varsayılan mod

class BanRequest(BaseModel):
    username: str
    reason: str

class CommandRequest(BaseModel):
    command: str
    args: Optional[List[str]] = []

class AnimeRequest(BaseModel):
    anime_name: str  
    episode_number: int
    character_name: Optional[str] = "Anime Karakteri"

class MinecraftBotCommand(BaseModel):
    bot_id: str
    command: str

class MinecraftBotCreate(BaseModel):
    bot_name: str
    server_ip: str
    server_port: int = 25565

# =========================================================
# AI VE TTS YARDIMCI SINIFLARI
# =========================================================

class AIAssistant:
    """Gemini AI ile sohbet ve içerik üretimi yapan sınıf."""
    def __init__(self):
        # Düşman modu kaldırıldı.
        self.modes = {
            "arkadaş": "Sen samimi, yardımsever ve eğlenceli bir arkadaşsın. Konuşmalarında emoji kullan ve sıcak ol.",
            "öğretmen": "Sen sabırlı, bilgili ve açıklayıcı bir öğretmensin. Her şeyi detaylı ve anlaşılır şekilde anlat."
        }
        self.chat_model = 'gemini-2.5-flash' 
    
    async def chat(self, message: str, mode: str = "arkadaş", history: List = []):
        if not genai or not GEMINI_API_KEY:
            return "❌ AI/Gemini entegrasyonu yüklenmedi veya API anahtarı eksik. Lütfen ortam değişkenlerini kontrol edin."
        
        # History formatı Gemini'ya uygun hale getiriliyor
        contents = []
        for h in history:
            contents.append({"role": "user", "parts": [{"text": h['message']}]})
            contents.append({"role": "model", "parts": [{"text": h['response']}]})
        
        contents.append({"role": "user", "parts": [{"text": message}]})

        try:
            # generate_content bir I/O işlemi olduğu için to_thread ile çalıştırılır.
            response = await asyncio.to_thread(
                genai.GenerativeModel(self.chat_model).generate_content,
                contents,
                config=genai.types.GenerateContentConfig(
                    system_instruction=self.modes.get(mode.lower(), self.modes["arkadaş"])
                )
            )
            return response.text
        except APIError as e:
            return f"❌ AI Modeli Hatası: Gemini API'dan yanıt alınamadı. Hata: {e}"
        except Exception as e:
            return f"❌ Genel Hata: {str(e)}"
            
    async def generate_full_episode_script(self, anime_name: str, episode_number: int, character_name: str):
        """Tam bir bölüm için uzun senaryo üretir (simülasyon için)."""
        if not genai or not GEMINI_API_KEY:
            return None, "❌ AI/Gemini entegrasyonu yüklenmedi veya API anahtarı eksik."
        
        prompt = (
            f"Sen bir senaryo yazarı ve dublaj yönetmenisin. Bana popüler anime '{anime_name}'in {episode_number}. bölümü için (veya bir bölümün önemli bir kısmı için), {character_name}'in başrolde olduğu, toplam **10-15 dakikalık bir seslendirme süresi** için uygun, detaylı ve uzun bir Türkçe dublaj senaryo metni oluştur. "
            "Metin içinde en az 5-6 farklı karakterin (örneğin: ANLATICI, KARAKTER A, KARAKTER B) diyalogları olsun. Sadece diyalog metnini ve karakter isimlerini 'KARAKTER: Diyalog' formatında ver. Başlık veya açıklama kullanma."
        )
        
        try:
            response = await asyncio.to_thread(
                genai.GenerativeModel(self.chat_model).generate_content,
                prompt,
                config=genai.types.GenerateContentConfig(
                    system_instruction="Sadece talep edilen uzun diyalog metnini, ek açıklama veya başlık olmadan döndür."
                )
            )
            
            script = response.text.strip()
            if len(script) > 500: # Uzun bir senaryo kontrolü
                 return script, None
            else:
                 return script, "⚠️ AI kısa veya anlamsız bir metin döndürdü. Daha detaylı deneme yapılabilir."
            
        except APIError as e:
            return None, f"❌ AI Modeli Hatası: Senaryo oluşturulamadı. {e}"
        except Exception as e:
            return None, f"❌ Genel Hata: {str(e)}"

ai_assistant = AIAssistant()

class TTSEngine:
    """pyttsx3 ile metinleri ses dosyasına dönüştüren sınıf."""
    def __init__(self):
        self.engine = None
        if pyttsx3:
            try:
                # pyttsx3 başlatma işlemi senkron olduğu için başlatma sırasında hata alabilir.
                self.engine = pyttsx3.init()
                # Ses ve Hız ayarları (varsa Türkçe ses seçimi)
                # ... (Önceki revizyondaki ayarlar) ...
                self.engine.setProperty('rate', 150)
            except Exception as e:
                self.engine = None
                print(f"!!! [TTS ERROR] pyttsx3 başlatılırken hata: {e}")
    
    def text_to_speech_file_sync(self, text: str, filename: str):
        """Metni dosyaya kaydeder (Senkron)."""
        if not self.engine:
            return False
        
        try:
            self.engine.save_to_file(text, filename)
            self.engine.runAndWait() # Bu bloklar, o yüzden to_thread içinde çalıştırılır.
            return True
        except Exception as e:
            print(f"!!! [TTS FAIL] Ses Kayıt Hatası: {e}")
            return False
    
    async def text_to_speech_file(self, text: str, filename: str):
        """Metni dosyaya kaydeder (Asenkron)."""
        return await asyncio.to_thread(self.text_to_speech_file_sync, text, filename)

tts_engine = TTSEngine()

# =========================================================
# FASTAPI UYGULAMASI VE WORKER LOGİĞİ
# =========================================================

app = FastAPI(title="AURION Project v18.0 - Hata Giderilmiş Final Sürüm", description="Super Admin Kontrol Merkezi")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ====== WORKER LOGİĞİ ======

async def minecraft_worker_logic():
    print("⛏️ Minecraft Bot Worker Başlatıldı.")
    while True:
        try:
            bots = await db.get_minecraft_bots()
            
            for bot in bots:
                bot_id = bot["id"]
                bot_name = bot.get("bot_name", "Bilinmeyen Bot")
                last_command = bot.get("last_command")
                
                # Botu online tut (Basit simülasyon)
                if bot.get("status") != "online":
                    await db.update_minecraft_bot(bot_id, {"status": "online"})
                
                # Komut varsa işleme başla (Canlı Görüntü Revizyonu burada başlar)
                if last_command:
                    print(f"--- ⛏️ [{bot_name}] Komut işleniyor: {last_command} ---")
                    
                    # Görev başladığı anda durumu ve Görüntüyü Güncelle (CANLI GÖRÜNTÜ Başlangıcı)
                    await db.update_minecraft_bot(bot_id, {
                        "last_command": None, # Komutu temizle
                        "current_task": f"İşleniyor: {last_command}",
                        "screen_url": f"/static/img/sim/screen_{bot_id}_{int(time.time())}_start.jpg" # Yeni ekran görüntüsü URL'si
                    })

                    # Komut simülasyonu
                    if "mine" in last_command.lower():
                        action_time = MINECRAFT_ACTION_TIME 
                        result = f"{int(action_time/3)} saniye içinde 16 birim elmas cevheri çıkarıldı."
                    elif "build" in last_command.lower():
                        action_time = MINECRAFT_ACTION_TIME * 1.5
                        result = "Karmaşık bir Kale inşa edildi."
                    else:
                        action_time = MINECRAFT_ACTION_TIME / 2
                        result = "Komut başarıyla çalıştırıldı ve sonuç alındı."

                    await asyncio.sleep(action_time)
                    
                    # Görev bittiği anda durumu ve Görüntüyü Güncelle (CANLI GÖRÜNTÜ Bitişi)
                    await db.update_minecraft_bot(bot_id, {
                        "current_task": f"Bitti: {result}",
                        "screen_url": f"/static/img/sim/screen_{bot_id}_{int(time.time())}_done.jpg" 
                    })
                    print(f"[{bot_name}] İşlem Tamamlandı. Sonuç: {result}")
                
                # Eğer komut yoksa, ekran URL'sini hafifçe güncelle (göz kırpma simülasyonu)
                if not bot.get("current_task") or "Rölanti" in bot.get("current_task"):
                     await db.update_minecraft_bot(bot_id, {
                        "screen_url": f"/static/img/sim/screen_{bot_id}_{int(time.time())}.jpg",
                        "current_task": "Rölanti - Yeni Komut Bekleniyor"
                    })


        except Exception as e:
            print(f"⛏️ Minecraft Worker'da Hata: {e}")
            
        await asyncio.sleep(WORKER_LOOP_INTERVAL) # Bot durumunu kontrol etme sıklığı


async def anime_producer_logic():
    print("🎬 Anime Producer Worker Başlatıldı.")
    while True:
        try:
            all_videos = await db.get_anime_videos(SUPER_ADMIN_USERNAME) 
            
            # Sadece video bekleyenleri seç
            pending_videos = [v for v in all_videos if v.get("status") == "video_pending"]
            
            for video in pending_videos:
                video_id = video["id"]
                
                print(f"--- 🎬 [Video ID: {video_id[:8]}] TAM BÖLÜM üretimine başlanıyor... ---")
                
                await db.update_anime_video(video_id, {"status": "producing", "start_time": datetime.utcnow().isoformat()})

                # Video üretim simülasyonu (Tam Bölüm süresi)
                await asyncio.sleep(VIDEO_PRODUCTION_TIME) 
                
                video_filename = f"anime_episode_{video_id}.mp4"
                video_url = f"/static/videos/{video_filename}"
                
                Path("static/videos").mkdir(parents=True, exist_ok=True)
                
                # Simülasyon amaçlı dosya yazma (içinde diyalog metni var)
                await asyncio.to_thread(
                    lambda: Path(f"static/videos/{video_filename}").write_text(f"Simüle Edilmiş TAM BÖLÜM İçeriği: {video['anime_name']} - Bölüm {video['episode_number']}\n\nSenaryo:\n{video['script']}", encoding='utf-8')
                )

                await db.update_anime_video(video_id, {
                    "status": "video_completed",
                    "video_url": video_url,
                    "completion_time": datetime.utcnow().isoformat()
                })
                
                print(f"[Video ID: {video_id[:8]}] Tam Bölüm Üretimi Tamamlandı! URL: {video_url}")

        except Exception as e:
            print(f"🎬 Anime Producer'da Hata: {e}")
            
        await asyncio.sleep(WORKER_LOOP_INTERVAL)


# =========================================================
# API ENDPOINT'LERİ
# =========================================================

# --- Auth ve Kullanıcı ---

@app.post("/api/register")
async def register(req: RegisterRequest):
    if await db.get_user(req.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    user = {
        "id": str(uuid.uuid4()),
        "username": req.username,
        "password_hash": get_password_hash(req.password),
        "role": "user",
        "created_at": datetime.utcnow().isoformat(),
        "mode": "arkadaş"
    }
    await db.add_user(user)
    token = create_access_token({"sub": req.username, "role": "user"})
    return {"token": token, "user": {"username": req.username, "role": "user"}}

@app.post("/api/login")
async def login(req: LoginRequest):
    # Super Admin için hızlı kontrol
    if req.username == SUPER_ADMIN_USERNAME and req.password == SUPER_ADMIN_PASSWORD:
        token = create_access_token({"sub": req.username, "role": "super_admin"})
        return {"token": token, "user": {"username": req.username, "role": "super_admin"}}
    
    user = await db.get_user(req.username)
    if not user or not verify_password(req.password, user["password_hash"]) or await db.is_banned(req.username):
        raise HTTPException(status_code=401, detail="Invalid credentials or user is banned")
    
    token = create_access_token({"sub": req.username, "role": user["role"]})
    return {"token": token, "user": {"username": req.username, "role": user["role"]}}

@app.get("/api/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

# --- Sohbet ve Komut ---

@app.post("/api/chat")
async def chat(req: ChatRequest, current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    history = await db.get_chats(username)
    user_mode = current_user.get("mode", "arkadaş")
    
    # AI Asistanını çağır
    ai_response = await ai_assistant.chat(req.message, req.mode or user_mode, history[-10:]) 
    
    chat_record = {
        "id": str(uuid.uuid4()),
        "username": username,
        "message": req.message,
        "response": ai_response,
        "mode": req.mode or user_mode,
        "timestamp": datetime.utcnow().isoformat()
    }
    await db.add_chat(chat_record)
    return {"response": ai_response, "mode": req.mode or user_mode}

@app.get("/api/chat/history")
async def get_chat_history(current_user: dict = Depends(get_current_user)):
    history = await db.get_chats(current_user["username"])
    return {"history": history}

@app.delete("/api/chat/history")
async def clear_chat_history(current_user: dict = Depends(get_current_user)):
    await db.clear_chats(current_user["username"])
    return {"message": "Chat history cleared"}

@app.post("/api/command")
async def execute_command(req: CommandRequest, current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    cmd = req.command.lower()
    
    result = {"success": False, "message": "Unknown command"}
    
    if cmd == "/mode":
        if len(req.args) > 0:
            new_mode = req.args[0].lower()
            # Düşman modu kaldırıldı
            if new_mode in ["arkadaş", "öğretmen"]:
                await db.update_user(username, {"mode": new_mode})
                result = {"success": True, "message": f"Mod değiştirildi: {new_mode}"}
            else:
                result = {"success": False, "message": "Geçersiz mod. (Mevcut modlar: arkadaş, öğretmen)"}
        else:
            user = await db.get_user(username)
            current_mode = user.get("mode", "arkadaş")
            result = {"success": True, "message": f"Mevcut mod: {current_mode}"}
    
    elif cmd == "/clear":
        await db.clear_chats(username)
        result = {"success": True, "message": "Sohbet geçmişi temizlendi"}
    
    cmd_record = {
        "id": str(uuid.uuid4()),
        "username": username,
        "command": cmd,
        "args": req.args,
        "result": result,
        "timestamp": datetime.utcnow().isoformat()
    }
    await db.add_command(cmd_record)
    return result

# --- Admin ---

@app.get("/api/admin/users")
async def get_all_users(current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Access denied")
    users = await db.get_users()
    safe_users = [{k: v for k, v in u.items() if k != "password_hash"} for u in users]
    return {"users": safe_users}

@app.post("/api/admin/ban")
async def ban_user(req: BanRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Access denied")
    ban_record = {
        "id": str(uuid.uuid4()),
        "username": req.username,
        "banned_by": current_user["username"],
        "reason": req.reason,
        "timestamp": datetime.utcnow().isoformat(),
        "active": True
    }
    await db.add_ban(ban_record)
    return {"message": f"User {req.username} has been banned"}

@app.get("/api/admin/bans")
async def get_all_bans(current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"bans": await db.get_bans()}

# --- Anime Üretim (Super Admin) ---

@app.post("/api/anime/generate")
async def generate_anime(req: AnimeRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admin can generate anime videos")
    
    # 1. AI ile uzun senaryoyu oluştur (Tam Bölüm Senaryosu)
    generated_script, ai_error = await ai_assistant.generate_full_episode_script(
        req.anime_name,
        req.episode_number,
        req.character_name
    )

    if generated_script is None:
        raise HTTPException(status_code=503, detail=f"AI Senaryo Oluşturma Hatası: {ai_error}")
    
    # 2. Senaryoyu ses dosyasına dönüştür
    audio_filename = f"anime_full_episode_audio_{uuid.uuid4()}.wav"
    audio_path = Path(f"static/audio/{audio_filename}")
    audio_path.parent.mkdir(parents=True, exist_ok=True)
    
    audio_success = await tts_engine.text_to_speech_file(generated_script, str(audio_path))
    
    # 3. Veritabanına kaydet
    video_record = {
        "id": str(uuid.uuid4()),
        "anime_name": req.anime_name,
        "episode_number": req.episode_number,
        "character": req.character_name,
        "script": generated_script, 
        "audio_url": f"/static/audio/{audio_filename}" if audio_success else None,
        "video_url": None,
        "created_by": current_user["username"],
        "created_at": datetime.utcnow().isoformat(),
        "status": "video_pending" if audio_success else "audio_failed" 
    }
    
    await db.add_anime_video(video_record)
    
    if audio_success:
        return {"video": video_record, "message": f"AI tarafından '{req.anime_name}' için TAM BÖLÜM senaryosu oluşturuldu. Ses dosyası hazırlandı. Video üretimi arka planda başlıyor (Simülasyon Süresi: {VIDEO_PRODUCTION_TIME} saniye)..."}
    else:
        return {"video": video_record, "message": "AI senaryo oluşturdu ancak ses dosyası oluşturulamadı (TTS Motoru Hatası).", "error": True}


@app.get("/api/anime/videos")
async def get_anime_videos(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    videos = await db.get_anime_videos(current_user["username"])
    return {"videos": videos}

# --- Minecraft Bot (Super Admin) ---

@app.post("/api/minecraft/bot/create")
async def create_minecraft_bot(req: MinecraftBotCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    bot = {
        "id": str(uuid.uuid4()),
        "bot_name": req.bot_name,
        "server_ip": req.server_ip,
        "server_port": req.server_port,
        "status": "offline",
        "last_command": None,
        "current_task": None,
        "screen_url": f"/static/img/sim/screen_{str(uuid.uuid4())}_default.png", # İlk default görüntü
        "created_by": current_user["username"],
        "created_at": datetime.utcnow().isoformat()
    }
    await db.add_minecraft_bot(bot)
    return {"bot": bot, "message": "Bot oluşturuldu. Worker'ımız otomatik bağlanacak."}

@app.get("/api/minecraft/bots")
async def get_minecraft_bots(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    bots = await db.get_minecraft_bots()
    return {"bots": bots}

@app.post("/api/minecraft/bot/command")
async def send_bot_command(req: MinecraftBotCommand, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    success = await db.update_minecraft_bot(req.bot_id, {
        "last_command": req.command,
        "last_command_time": datetime.utcnow().isoformat()
    })
    
    if not success:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    return {"message": "Komut gönderildi. Worker işleme başladı.", "command": req.command}

# =========================================================
# FRONTEND HTML VE BAŞLANGIÇ AYARLARI
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    # Frontend HTML içeriği (Önceki revizyonlardan gelen, güncel modları yansıtan HTML)
    html = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AURION Project v18.0 - Final</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap" rel="stylesheet">
        <style>
            /* Stil Kodları (Kısa tutuldu, önceki revizyonlarla aynıdır) */
            :root {{
                --primary: #667eea; 
                --primary-dark: #5869d8;
                --background: #1e1e2e; 
                --surface: #282a36; 
                --text: #f8f8f2;
                --text-light: #d0d0d6;
                --success: #50fa7b;
                --danger: #ff5555;
            }}
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{ font-family: 'Roboto', sans-serif; background-color: var(--background); color: var(--text); min-height: 100vh; display: flex; }}
            #authSection {{ width: 100%; display: flex; justify-content: center; align-items: center; }}
            .auth-card {{ max-width: 450px; width: 90%; margin: 50px auto; background-color: var(--surface); padding: 40px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5); text-align: center; }}
            .auth-card h2 {{ color: var(--primary); margin-bottom: 25px; }}
            .form-group {{ margin-bottom: 20px; text-align: left; }}
            .form-group input, .form-group textarea {{ width: 100%; padding: 12px; border: 1px solid #44475a; border-radius: 6px; background-color: #383a48; color: var(--text); font-size: 1rem; transition: border-color 0.3s; }}
            .btn {{ padding: 10px 20px; background-color: var(--primary); color: white; border: none; border-radius: 6px; font-size: 1rem; font-weight: 700; cursor: pointer; transition: background-color 0.2s; }}
            .btn-full {{ width: 100%; margin-top: 10px; }}
            .btn-secondary {{ background-color: #6c757d; }}
            .sidebar {{ width: 250px; background-color: var(--surface); padding: 20px 0; box-shadow: 2px 0 10px rgba(0, 0, 0, 0.4); flex-shrink: 0; }}
            .sidebar h1 {{ font-size: 1.5rem; text-align: center; margin-bottom: 30px; color: var(--primary); }}
            .user-info {{ padding: 0 20px 15px; border-bottom: 1px solid #44475a; margin-bottom: 15px; }}
            .nav-link {{ padding: 15px 20px; display: flex; align-items: center; gap: 10px; color: var(--text-light); text-decoration: none; cursor: pointer; border-left: 5px solid transparent; transition: background-color 0.3s, border-left-color 0.3s; }}
            .nav-link.active {{ background-color: #44475a; border-left-color: var(--primary); color: var(--text); font-weight: 700; }}
            .main-container {{ flex-grow: 1; padding: 30px; display: flex; flex-direction: column; }}
            h2 {{ color: var(--primary); margin-bottom: 20px; border-bottom: 1px solid #44475a; padding-bottom: 5px; }}
            .mode-selector {{ display: flex; gap: 15px; margin-bottom: 20px; }}
            .mode-btn {{ flex: 1; padding: 12px; background-color: #383a48; color: var(--text-light); border: 2px solid #44475a; border-radius: 8px; cursor: pointer; transition: all 0.3s; }}
            .mode-btn.active {{ background-color: var(--primary); color: white; border-color: var(--primary); }}
            .chat-box {{ background: #383a48; border-radius: 8px; padding: 15px; height: 600px; overflow-y: auto; margin-bottom: 20px; display: flex; flex-direction: column; }}
            .message {{ margin-bottom: 10px; padding: 10px 15px; border-radius: 15px; max-width: 80%; font-size: 0.95rem; white-space: pre-wrap; }}
            .message.user {{ background-color: var(--primary); color: white; align-self: flex-end; border-bottom-right-radius: 5px; }}
            .message.ai {{ background-color: #44475a; color: var(--text); align-self: flex-start; border-bottom-left-radius: 5px; }}
            .chat-input {{ display: flex; gap: 10px; }}
            .data-card {{ background-color: #383a48; padding: 15px; border-radius: 8px; border-left: 4px solid var(--primary); box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2); }}
            .card-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }}
            .bot-screen-img {{ width: 100%; height: auto; margin-top: 10px; border-radius: 4px; border: 1px solid #44475a; }}
            .anime-form-grid {{ display: grid; grid-template-columns: 2fr 1fr 1fr 150px; gap: 20px; }}
        </style>
    </head>
    <body>
        
        <div id="authSection">
            <div class="auth-card">
                <h2 id="authTitle">Giriş Yap</h2>
                <div class="form-group">
                    <label>Kullanıcı Adı</label>
                    <input type="text" id="username" placeholder="Kullanıcı adınız">
                </div>
                <div class="form-group">
                    <label>Şifre</label>
                    <input type="password" id="password" placeholder="Şifreniz">
                </div>
                <button class="btn btn-full" id="authPrimaryBtn" onclick="login()">Giriş Yap</button>
                <button class="btn btn-full btn-secondary" id="authSwitchBtn" onclick="toggleAuthMode()">Kayıt Sayfasına Git</button>
            </div>
        </div>

        <div id="dashboard" style="display: none; width: 100%;">
            <div class="sidebar">
                <h1>AURION ⚡</h1>
                <div class="user-info">
                    <span>Hoş Geldiniz, <strong id="currentUsernameDisplay"></strong></span>
                    <span>Rol: <strong class="role" id="currentRoleDisplay"></strong></span>
                    <button class="btn btn-full" style="background-color: var(--danger); margin-top: 10px;" onclick="logout()">Çıkış Yap</button>
                </div>
                <nav id="navLinks">
                    <a class="nav-link active" data-tab="chat" onclick="switchTab('chat')">💬 Sohbet</a>
                    <a class="nav-link" id="adminLink" data-tab="admin" onclick="switchTab('admin')" style="display: none;">👑 Admin Panel</a>
                    <a class="nav-link" id="animeLink" data-tab="anime" onclick="switchTab('anime')" style="display: none;">🎬 Anime Dublaj</a>
                    <a class="nav-link" id="minecraftLink" data-tab="minecraft" onclick="switchTab('minecraft')" style="display: none;">⛏️ Minecraft Bots</a>
                </nav>
            </div>
            
            <div class="main-container">
                <div id="chatTab" class="tab-content active">
                    <h2>💬 Gemini AI Sohbet</h2>
                    <div class="mode-selector">
                        <button class="mode-btn active" data-mode="arkadaş" onclick="selectMode('arkadaş')">😊 Arkadaş</button>
                        <button class="mode-btn" data-mode="öğretmen" onclick="selectMode('öğretmen')">👨‍🏫 Öğretmen</button>
                    </div>
                    
                    <div class="chat-box" id="chatBox"></div>
                    
                    <div class="chat-input">
                        <input type="text" id="messageInput" placeholder="Mesajınızı yazın..." onkeypress="if(event.key==='Enter') sendMessage()">
                        <button class="btn" style="width: auto;" onclick="sendMessage()">Gönder</button>
                    </div>
                </div>
                
                <div id="adminTab" class="tab-content">
                    <h2>👑 Kullanıcı Yönetimi</h2>
                    <div id="usersList" class="card-grid"></div>
                    
                    <h2 style="margin-top: 30px;">🚫 Yasaklanan Kullanıcılar</h2>
                    <div id="bansList" class="card-grid"></div>
                </div>
                
                <div id="animeTab" class="tab-content">
                    <h2>🎬 Anime TAM BÖLÜM Dublaj İşlemi (Simülasyon)</h2>
                    <p style="color: var(--text-light); margin-bottom: 15px;">AI, uzun bir bölüm senaryosu oluşturacak ve video üretimi başlayacaktır (Simülasyon Süresi: {VIDEO_PRODUCTION_TIME} saniye).</p>
                    <div class="anime-form-grid">
                        <div class="form-group"><label>Anime Adı</label><input type="text" id="animeName" placeholder="Naruto"></div>
                        <div class="form-group"><label>Bölüm No</label><input type="number" id="episodeNumber" placeholder="60" value="1"></div>
                        <div class="form-group"><label>Karakter Adı</label><input type="text" id="animeCharacter" placeholder="Sasuke" value="Anime Karakteri"></div>
                        <div class="form-group" style="align-self: flex-end;"><button class="btn btn-full" onclick="generateAnime()">Dublajı Başlat</button></div>
                    </div>

                    <h2 style="margin-top: 30px;">⏳ Üretim Geçmişi</h2>
                    <div id="animeHistory" class="card-grid"></div>
                </div>

                <div id="minecraftTab" class="tab-content">
                    <h2>⛏️ Yeni Bot Oluştur</h2>
                    <div class="card-grid" style="grid-template-columns: 1fr 1fr 1fr 1fr;">
                        <div class="form-group"><label>Bot Adı</label><input type="text" id="botName" placeholder="Bot_001"></div>
                        <div class="form-group"><label>Sunucu IP</label><input type="text" id="serverIp" placeholder="localhost"></div>
                        <div class="form-group"><label>Port</label><input type="number" id="serverPort" placeholder="25565" value="25565"></div>
                         <div class="form-group" style="align-self: flex-end;"><button class="btn btn-full" onclick="createBot()">Botu Kaydet</button></div>
                    </div>
                    
                    <h2 style="margin-top: 30px;">🤖 Mevcut Botlar (Canlı Görünüm)</h2>
                    <div id="botsList" class="card-grid"></div>
                </div>

            </div>
        </div>
        
        <script>
            let token = localStorage.getItem('aurionToken');
            let currentUser = JSON.parse(localStorage.getItem('aurionUser'));
            let currentMode = localStorage.getItem('aurionMode') || 'arkadaş';
            let updateInterval; 
            let isRegisterMode = false;
            
            // Genel API Çağrı Fonksiyonu (Aynı Kalır)
            async function apiCall(url, method = 'GET', body = null) {{
                const headers = {{
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${{token}}`
                }};
                
                try {{
                    const response = await fetch(url, {{
                        method: method,
                        headers: headers,
                        body: body ? JSON.stringify(body) : null
                    }});
                    
                    if (response.status === 204) return {{ message: "İşlem başarılı" }}; 

                    const data = await response.json();
                    
                    if (!response.ok) {{
                        alert('API Hatası: ' + (data.detail || data.message || 'Bilinmeyen Hata'));
                        if (response.status === 401 || response.status === 403) {{
                            logout();
                        }}
                        return null;
                    }}
                    return data;
                }} catch (error) {{
                    alert('Ağ Hatası: ' + error.message);
                    return null;
                }}
            }}
            
            // Auth Fonksiyonları (Aynı Kalır)
            function toggleAuthMode() {{
                isRegisterMode = !isRegisterMode;
                const title = document.getElementById('authTitle');
                const primaryBtn = document.getElementById('authPrimaryBtn');
                const switchBtn = document.getElementById('authSwitchBtn');
                
                if (isRegisterMode) {{
                    title.textContent = 'Kayıt Ol';
                    primaryBtn.textContent = 'Kayıt Ol';
                    primaryBtn.onclick = register;
                    switchBtn.textContent = 'Giriş Sayfasına Git';
                }} else {{
                    title.textContent = 'Giriş Yap';
                    primaryBtn.textContent = 'Giriş Yap';
                    primaryBtn.onclick = login;
                    switchBtn.textContent = 'Kayıt Sayfasına Git';
                }}
            }}

            async function login() {{
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const data = await apiCall('/api/login', 'POST', {{username, password}});
                
                if (data) {{
                    token = data.token;
                    currentUser = data.user;
                    localStorage.setItem('aurionToken', token);
                    localStorage.setItem('aurionUser', JSON.stringify(currentUser));
                    showDashboard();
                }}
            }}
            
            async function register() {{
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const data = await apiCall('/api/register', 'POST', {{username, password}});
                
                if (data) {{
                    token = data.token;
                    currentUser = data.user;
                    localStorage.setItem('aurionToken', token);
                    localStorage.setItem('aurionUser', JSON.stringify(currentUser));
                    showDashboard();
                }}
            }}
            
            function logout() {{
                localStorage.removeItem('aurionToken');
                localStorage.removeItem('aurionUser');
                localStorage.removeItem('aurionMode');
                token = null;
                currentUser = null;
                document.getElementById('authSection').style.display = 'flex';
                document.getElementById('dashboard').style.display = 'none';
                clearInterval(updateInterval); 
            }}
            
            function showDashboard() {{
                if (!token || !currentUser) {{
                    document.getElementById('authSection').style.display = 'flex'; 
                    document.getElementById('dashboard').style.display = 'none';
                    return;
                }}
                
                document.getElementById('authSection').style.display = 'none';
                document.getElementById('dashboard').style.display = 'flex';
                
                document.getElementById('currentUsernameDisplay').textContent = `${{currentUser.username}}`;
                document.getElementById('currentRoleDisplay').textContent = `${{currentUser.role}}`;
                
                const isSuperAdmin = currentUser.role === 'super_admin';
                const isAdmin = currentUser.role === 'admin' || isSuperAdmin;

                document.getElementById('adminLink').style.display = isAdmin ? 'flex' : 'none';
                document.getElementById('animeLink').style.display = isSuperAdmin ? 'flex' : 'none';
                document.getElementById('minecraftLink').style.display = isSuperAdmin ? 'flex' : 'none';

                switchTab('chat');
                selectMode(currentMode);
            }}

            // Tab Fonksiyonları (Aynı Kalır)
            function switchTab(tabName) {{
                document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
                
                const activeLink = document.querySelector(`.nav-link[data-tab="${{tabName}}"]`);
                const activeContent = document.getElementById(`${{tabName}}Tab`);

                if (activeLink) activeLink.classList.add('active');
                if (activeContent) activeContent.classList.add('active');

                clearInterval(updateInterval); 

                if (tabName === 'chat') loadChatHistory();
                else if (tabName === 'admin') loadAdminData();
                else if (tabName === 'minecraft') {{
                    loadBots();
                    // Canlı Görüntü: Worker 5 saniyede bir güncellediği için, frontend de 5 saniyede bir çeker
                    updateInterval = setInterval(loadBots, 5000); 
                }}
                else if (tabName === 'anime') {{
                    loadAnimeHistory();
                    updateInterval = setInterval(loadAnimeHistory, 10000); 
                }}
            }}

            // Chat Fonksiyonları (Düşman modu çıkarıldı)
            function selectMode(mode) {{
                currentMode = mode;
                localStorage.setItem('aurionMode', mode);
                document.querySelectorAll('.mode-btn').forEach(btn => {{
                    btn.classList.remove('active');
                    if (btn.dataset.mode === mode) {{
                        btn.classList.add('active');
                    }}
                }});
            }}
            
            async function sendMessage() {{
                const input = document.getElementById('messageInput');
                const message = input.value.trim();
                if (!message) return;
                
                // Komut kontrolü
                if (message.startsWith('/')) {{
                    const parts = message.substring(1).split(' ');
                    const cmd = parts[0];
                    const args = parts.slice(1);
                    
                    const cmdData = await apiCall('/api/command', 'POST', {{command: cmd, args: args}});

                    if (cmdData) {{
                        addMessageToChat(message, 'user');
                        addMessageToChat(cmdData.message, 'ai');
                        input.value = '';
                    }}
                    return;
                }}

                addMessageToChat(message, 'user');
                input.value = '';
                
                const data = await apiCall('/api/chat', 'POST', {{message, mode: currentMode}});
                
                if (data) {{
                    addMessageToChat(data.response, 'ai');
                }}
            }}
            
            function addMessageToChat(message, type) {{
                const chatBox = document.getElementById('chatBox');
                const messageDiv = document.createElement('div');
                messageDiv.className = `message ${{type}}`;
                messageDiv.textContent = message;
                chatBox.appendChild(messageDiv);
                chatBox.scrollTop = chatBox.scrollHeight;
            }}
            
            async function loadChatHistory() {{
                const data = await apiCall('/api/chat/history');
                
                if (data && data.history) {{
                    const chatBox = document.getElementById('chatBox');
                    chatBox.innerHTML = '';
                    data.history.forEach(chat => {{
                        addMessageToChat(chat.message, 'user');
                        addMessageToChat(chat.response, 'ai');
                    }});
                }}
            }}

            // Admin Fonksiyonları (Aynı Kalır)
            async function loadAdminData() {{
                const [usersData, bansData] = await Promise.all([
                    apiCall('/api/admin/users'),
                    apiCall('/api/admin/bans')
                ]);
                
                const usersList = document.getElementById('usersList');
                usersList.innerHTML = usersData ? usersData.users.map(user => `
                    <div class="data-card">
                        <strong>${{user.username}}</strong> (${{user.role}})<br>
                        <small style="color: var(--text-light);">Kayıt: ${{new Date(user.created_at).toLocaleString('tr-TR')}}</small>
                    </div>
                `).join('') : '<p style="color: var(--text-light);">Kullanıcı verisi yüklenemedi.</p>';
                
                const bansList = document.getElementById('bansList');
                bansList.innerHTML = bansData ? bansData.bans.filter(b => b.active).map(ban => `
                    <div class="data-card" style="border-left-color: var(--danger);">
                        <strong>${{ban.username}}</strong><br>
                        Sebep: ${{ban.reason}}<br>
                        Yasaklayan: <span style="color: var(--text-light);">${{ban.banned_by}}</span>
                        <small style="display: block; margin-top: 5px;">${{new Date(ban.timestamp).toLocaleString('tr-TR')}}</small>
                    </div>
                `).join('') || '<p style="color: var(--text-light);">Yasaklı kullanıcı yok</p>' : '<p style="color: var(--text-light);">Yasaklama verisi yüklenemedi.</p>';
            }}

            // Anime Fonksiyonları (Tam Bölüm Senaryosu)
            async function generateAnime() {{
                const animeName = document.getElementById('animeName').value;
                const episodeNumber = parseInt(document.getElementById('episodeNumber').value);
                const characterName = document.getElementById('animeCharacter').value;
                
                if (!animeName || isNaN(episodeNumber) || episodeNumber < 1) {{
                    alert('Lütfen geçerli bir Anime Adı ve Bölüm Numarası girin.');
                    return;
                }}
                
                const data = await apiCall('/api/anime/generate', 'POST', {{
                    anime_name: animeName, 
                    episode_number: episodeNumber,
                    character_name: characterName
                }});
                
                if (data) {{
                    alert(data.message);
                    loadAnimeHistory(); 
                }}
            }}

            async function loadAnimeHistory() {{
                const data = await apiCall('/api/anime/videos');
                
                const historyDiv = document.getElementById('animeHistory');
                historyDiv.innerHTML = '';
                
                if (data && data.videos.length > 0) {{
                    data.videos.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).forEach(video => {{
                        const card = document.createElement('div');
                        card.className = 'data-card anime-history-card';
                        
                        let statusText;
                        let statusColor;
                        let mediaContent = '';
                        
                        if (video.status === 'video_completed') {{
                            statusText = '✅ TAMAMLANDI';
                            statusColor = 'var(--success)';
                            mediaContent = `
                                <audio controls src="${{video.audio_url}}" style="width: 100%; margin-top: 10px;"></audio>
                                <video controls src="${{video.video_url}}" style="width: 100%; max-height: 200px; margin-top: 10px; background: black;"></video>
                            `;
                        }} else if (video.status === 'video_pending' || video.status === 'producing') {{
                            statusText = '⏳ ' + video.status.toUpperCase().replace('_', ' ');
                            statusColor = 'orange';
                            mediaContent = video.audio_url ? `<audio controls src="${{video.audio_url}}" style="width: 100%; margin-top: 10px;"></audio><p style="color: orange; margin-top: 10px;">Tam Bölüm üretimi sürüyor...</p>` : '';
                        }} else if (video.status === 'audio_failed') {{
                            statusText = '❌ SES HATASI';
                            statusColor = 'var(--danger)';
                            mediaContent = '<p style="color: var(--danger); margin-top: 10px;">Ses dosyası oluşturulamadı (TTS Hatası).</p>';
                        }} else {{
                             statusText = '❓ BİLİNMEYEN';
                            statusColor = 'gray';
                        }}
                        
                        card.style.borderLeftColor = statusColor;
                        card.innerHTML = `
                            <strong>${{video.anime_name}} - Bölüm ${{video.episode_number}}</strong><br>
                            <span style="color: ${{statusColor}};">(${{statusText}})</span> - Karakter: ${{video.character}}<br>
                            <small style="color: var(--text-light);">Oluşturma: ${{new Date(video.created_at).toLocaleString('tr-TR')}}</small>
                            <div class="script-display" style="background-color: #44475a; padding: 8px; border-radius: 4px; margin-top: 10px; font-size: 0.85rem; white-space: pre-wrap;">
                                ${{video.script.substring(0, 300)}}... (Tam Senaryo)
                            </div>
                            ${{mediaContent}}
                        `;
                        historyDiv.appendChild(card);
                    }});
                }} else {{
                    historyDiv.innerHTML = '<p style="color: var(--text-light);">Henüz oluşturulmuş dublaj yok.</p>';
                }}
            }}

            // Minecraft Fonksiyonları (Canlı Görüntü)
            async function createBot() {{
                const botName = document.getElementById('botName').value;
                const serverIp = document.getElementById('serverIp').value;
                const serverPort = document.getElementById('serverPort').value;
                
                if (!botName || !serverIp) {{
                    alert('Bot adı ve sunucu IP gerekli');
                    return;
                }}
                
                const data = await apiCall('/api/minecraft/bot/create', 'POST', {{
                    bot_name: botName,
                    server_ip: serverIp,
                    server_port: parseInt(serverPort)
                }});
                
                if (data) {{
                    alert(data.message);
                    loadBots(); 
                }}
            }}
            
            async function loadBots() {{
                const data = await apiCall('/api/minecraft/bots');
                
                const botsList = document.getElementById('botsList');
                botsList.innerHTML = '';

                if (data && data.bots.length > 0) {{
                    data.bots.forEach(bot => {{
                        const statusClass = bot.status === 'online' ? 'status-online' : 'status-offline';
                        const statusText = bot.status === 'online' ? '🟢 Online' : '🔴 Offline';
                        const commandInputId = 'cmd_' + bot.id; 
                        const statusColor = bot.status === 'online' ? 'var(--success)' : 'var(--danger)';
                        
                        // Ekran URL'sinin sonuna time damgası ekleyerek tarayıcının cache'ini bypass et (Canlı Görüntü)
                        const screenUrl = bot.screen_url ? `${{bot.screen_url}}?t=${{new Date().getTime()}}` : '/static/img/sim/default_screen.png';
                        const currentTask = bot.current_task || 'Rölanti';

                        const card = document.createElement('div');
                        card.className = 'data-card';
                        card.style.borderLeftColor = statusColor;
                        
                        card.innerHTML = `
                            <strong>${{bot.bot_name}}</strong>
                            <span class="${{statusClass}}">(${{statusText}})</span><br>
                            <small style="color: var(--text-light);">Sunucu: ${{bot.server_ip}}:${{bot.server_port}}</small><br>
                            <small>Görev: <span style="color: var(--primary);">${{currentTask}}</span></small>
                            <img src="${{screenUrl}}" class="bot-screen-img" alt="Bot Ekran Görüntüsü (Simüle)">
                            <div class="bot-command-input" style="display: flex; gap: 5px; margin-top: 10px;">
                                <input type="text" id="${{commandInputId}}" placeholder="Komut (mine, build...)" style="flex: 1;">
                                <button class="btn" style="padding: 8px 15px; background-color: var(--primary);" onclick="sendBotCommand('${{bot.id}}', '${{commandInputId}}')">▶️</button>
                            </div>
                        `;
                        botsList.appendChild(card);
                    }});
                }} else {{
                    botsList.innerHTML = '<p style="color: var(--text-light);">Henüz bot yok.</p>';
                }}
            }}
            
            async function sendBotCommand(botId, inputId) {{
                const command = document.getElementById(inputId).value;
                
                if (!command) {{
                    alert('Komut girin');
                    return;
                }}
                
                const data = await apiCall('/api/minecraft/bot/command', 'POST', {{bot_id: botId, command}});
                
                if (data) {{
                    alert(data.message);
                    document.getElementById(inputId).value = '';
                    loadBots(); // Komut gönderildiğinde hemen listeyi yenile (görev başlangıcını görmek için)
                }}
            }}

            // Init
            document.addEventListener('DOMContentLoaded', () => {{
                showDashboard();
            }});

        </script>
    </body>
    </html>
    """
    return html

# Statik dosyalar için dizinlerin oluşturulması ve montajı
Path("static/audio").mkdir(parents=True, exist_ok=True)
Path("static/img/sim").mkdir(parents=True, exist_ok=True) 
Path("static/videos").mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")

# =========================================================
# UYGULAMA BAŞLANGIÇ OLAYLARI
# =========================================================

@app.on_event("startup")
async def start_workers():
    """Uygulama açılırken çalışacak asenkron görevleri başlatır."""
    print("🚀 [AURION START OK] Uygulama başlatılıyor.")
    
    # Super Admin'i kontrol et ve ekle/güncelle
    super_admin_data = {
        "id": str(uuid.uuid4()),
        "username": SUPER_ADMIN_USERNAME,
        "password_hash": get_password_hash(SUPER_ADMIN_PASSWORD),
        "role": "super_admin",
        "created_at": datetime.utcnow().isoformat(),
        "mode": "arkadaş"
    }
    
    # Hata: Eğer get_user None dönerse (yani yoksa) ekle
    if not await db.get_user(SUPER_ADMIN_USERNAME):
        print(">>> [DB INIT] Super Admin veritabanına ekleniyor.")
        await db.add_user(super_admin_data)
    else:
        # Şifrenin güncel olduğundan emin ol
        await db.update_user(SUPER_ADMIN_USERNAME, {"password_hash": super_admin_data["password_hash"]})

    
    # AI kütüphanesi yüklenmişse worker'ları başlat
    if genai and GEMINI_API_KEY:
        asyncio.create_task(minecraft_worker_logic())
        asyncio.create_task(anime_producer_logic())
        print(">>> [WORKERS STARTED] Arka plan işleyicileri (Minecraft/Anime) başlatıldı.")
    else:
        print("!!! [WORKERS SKIP] AI entegrasyonu (Gemini/API Key) eksik olduğu için worker'lar başlatılmadı. Lütfen GEMINI_API_KEY'i tanımlayın.")


if __name__ == "__main__":
    import uvicorn
    
    print("🚀 AURION Project v18.0 (Final Yama) başlatılıyor...")
    print(f"🔐 Super Admin: {SUPER_ADMIN_USERNAME} / {SUPER_ADMIN_PASSWORD}")
    
    # Localde çalışırken --reload kullanılması önerilir.
    uvicorn.run(app, host="0.0.0.0", port=8000)
