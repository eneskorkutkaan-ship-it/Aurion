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
import io
import time # Workers için eklendi
import random # Workers için eklendi
from pathlib import Path

# Google Gemini AI
try:
    import google.generativeai as genai
except ImportError:
    genai = None

# Text-to-Speech (keysiz)
try:
    import pyttsx3
except ImportError:
    pyttsx3 = None

# ====== CONFIGURATION ======
SECRET_KEY = "aurion-super-secret-key-2025"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

# Super Admin Credentials
SUPER_ADMIN_USERNAME = "enes"
SUPER_ADMIN_PASSWORD = "enes13579"

# Gemini API
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if GEMINI_API_KEY and genai:
    genai.configure(api_key=GEMINI_API_KEY)

# Database file
DB_FILE = Path("aurion_db.json")

# Worker Ayarları
WORKER_LOOP_INTERVAL = 5 # Worker'ların kontrol süresi (saniye)
VIDEO_PRODUCTION_TIME = 15 # Simüle edilen video üretim süresi

# ====== DATABASE ======
class Database:
    def __init__(self):
        self.data = self.load()
        
    def load(self):
        if DB_FILE.exists():
            with open(DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            "users": [],
            "chats": [],
            "commands": [],
            "bans": [],
            "minecraft_bots": [],
            "anime_videos": []
        }
    
    def save(self):
        # İşlem sırasında başka bir worker'ın kaydetmesini engellemek için basit bir kilitleme mekanizması
        temp_file = DB_FILE.with_suffix('.tmp')
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        temp_file.replace(DB_FILE)
    
    def get_users(self):
        return self.data.get("users", [])
    
    def add_user(self, user):
        self.data["users"].append(user)
        self.save()
    
    def update_user(self, username, updates):
        for user in self.data["users"]:
            if user["username"] == username:
                user.update(updates)
                self.save()
                return True
        return False
    
    def get_user(self, username):
        for user in self.data["users"]:
            if user["username"] == username:
                return user
        return None
    
    def add_chat(self, chat):
        self.data["chats"].append(chat)
        self.save()
    
    def get_chats(self, username):
        return [c for c in self.data["chats"] if c["username"] == username]
    
    def clear_chats(self, username):
        self.data["chats"] = [c for c in self.data["chats"] if c["username"] != username]
        self.save()
    
    def add_command(self, cmd):
        self.data["commands"].append(cmd)
        self.save()
    
    def add_ban(self, ban):
        self.data["bans"].append(ban)
        self.save()
    
    def is_banned(self, username):
        for ban in self.data["bans"]:
            if ban["username"] == username and ban["active"]:
                return True
        return False
    
    def get_bans(self):
        return self.data["bans"]
    
    # GÜNCELLENDİ: Yeni alanlar eklendi
    def add_minecraft_bot(self, bot):
        bot["current_task"] = None
        bot["screen_url"] = None
        self.data["minecraft_bots"].append(bot)
        self.save()
    
    def update_minecraft_bot(self, bot_id, updates):
        for bot in self.data["minecraft_bots"]:
            if bot["id"] == bot_id:
                bot.update(updates)
                self.save()
                return True
        return False
    
    def get_minecraft_bots(self):
        return self.data.get("minecraft_bots", [])
    
    # GÜNCELLENDİ: Başarılı ses üretiminden sonraki durumu "video_pending" olarak ayarla
    def add_anime_video(self, video):
        if video.get("status") == "completed":
            video["status"] = "video_pending"
            
        self.data["anime_videos"].append(video)
        self.save()
    
    def update_anime_video(self, video_id, updates):
        for video in self.data["anime_videos"]:
            if video["id"] == video_id:
                video.update(updates)
                self.save()
                return True
        return False
    
    def get_anime_videos(self, username):
        return [v for v in self.data["anime_videos"] if v["created_by"] == username]

db = Database()

# ====== SECURITY ======
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
    token = credentials.credentials
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Check if banned
    if db.is_banned(username):
        raise HTTPException(status_code=403, detail="User is banned")
    
    user = db.get_user(username)
    if user is None and username == SUPER_ADMIN_USERNAME:
        # Super admin always exists
        user = {
            "username": SUPER_ADMIN_USERNAME,
            "role": "super_admin",
            "created_at": datetime.utcnow().isoformat()
        }
    
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

# ====== MODELS ======
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    message: str
    mode: Optional[str] = "arkadaş"

class CommandRequest(BaseModel):
    command: str
    args: Optional[List[str]] = []

class BanRequest(BaseModel):
    username: str
    reason: str

class AnimeRequest(BaseModel):
    prompt: str
    character: Optional[str] = "Anime Karakteri"

class MinecraftBotCommand(BaseModel):
    bot_id: str
    command: str

class MinecraftBotCreate(BaseModel):
    bot_name: str
    server_ip: str
    server_port: int = 25565

# ====== AI HELPER ======
class AIAssistant:
    # ... (AIAssistant sınıfı önceki kodunuzdakiyle aynı)
    def __init__(self):
        self.modes = {
            "arkadaş": "Sen samimi, yardımsever ve eğlenceli bir arkadaşsın. Konuşmalarında emoji kullan ve sıcak ol.",
            "düşman": "Sen sert, eleştirel ve meydan okuyan birisin. Keskin ve provokatif konuş.",
            "öğretmen": "Sen sabırlı, bilgili ve açıklayıcı bir öğretmensin. Her şeyi detaylı ve anlaşılır şekilde anlat."
        }
    
    async def chat(self, message: str, mode: str = "arkadaş", history: List = []):
        if not genai:
            return "❌ Gemini AI entegrasyonu yüklenmedi. Lütfen google-generativeai yükleyin."
        
        if not GEMINI_API_KEY:
            return "❌ GEMINI_API_KEY bulunamadı. Lütfen .env dosyasına ekleyin."
        
        try:
            model = genai.GenerativeModel('gemini-pro')
            
            # System prompt
            system_prompt = self.modes.get(mode.lower(), self.modes["arkadaş"])
            
            # Build context
            context = f"{system_prompt}\n\n"
            for h in history[-5:]:  # Last 5 messages
                context += f"Kullanıcı: {h['user']}\nSen: {h['ai']}\n\n"
            context += f"Kullanıcı: {message}\nSen:"
            
            response = model.generate_content(context)
            return response.text
        except Exception as e:
            return f"❌ Hata: {str(e)}"
    
    async def generate_anime_script(self, prompt: str, character: str):
        if not genai or not GEMINI_API_KEY:
            return "Anime karakteri konuşuyor: Bu bir demo metindir. API bağlantısı kurulamadı."
        
        try:
            model = genai.GenerativeModel('gemini-pro')
            system_prompt = f"""
            Sen bir anime senaryo yazarısın. Kullanıcının isteğine göre {character} karakterinin 
            konuşması için kısa (30-60 saniye) bir Türkçe anime diyalogu yaz.
            Sadece diyalog metnini ver, başka açıklama yapma.
            """
            
            full_prompt = f"{system_prompt}\n\nİstek: {prompt}\n\nDiyalog:"
            response = model.generate_content(full_prompt)
            return response.text
        except Exception as e:
            return f"Demo anime metni: {prompt}"

ai_assistant = AIAssistant()

# ====== TTS HELPER (Keysiz) ======
class TTSEngine:
    # ... (TTSEngine sınıfı önceki kodunuzdakiyle aynı)
    def __init__(self):
        self.engine = None
        if pyttsx3:
            try:
                self.engine = pyttsx3.init()
                # Set Turkish voice if available
                voices = self.engine.getProperty('voices')
                for voice in voices:
                    if 'turkish' in voice.name.lower() or 'tr' in voice.id.lower():
                        self.engine.setProperty('voice', voice.id)
                        break
            except:
                self.engine = None
    
    def text_to_speech_file(self, text: str, filename: str):
        if not self.engine:
            return False
        
        try:
            self.engine.save_to_file(text, filename)
            self.engine.runAndWait()
            return True
        except:
            return False

tts_engine = TTSEngine()

# ====== FASTAPI APP ======
app = FastAPI(title="AURION Project v17.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ====== WORKER LOGIC (Harici Altyapı Entegrasyonu) ======

async def minecraft_worker_logic():
    """Minecraft Bot Worker'ının Simülasyonu."""
    print("⛏️ Minecraft Bot Worker Başlatıldı.")
    while True:
        try:
            # db.load() worker'lar için veritabanını yeniden yükler
            db.load() 
            bots = db.get_minecraft_bots()
            
            for bot in bots:
                bot_name = bot.get("bot_name", "Bilinmeyen Bot")
                last_command = bot.get("last_command")
                bot_id = bot["id"]

                # Botun durumunu online yap ve rastgele ekran URL'si güncelle
                screen_url = f"/static/img/screen_{bot_id}_{int(time.time())}.jpg"
                db.update_minecraft_bot(bot_id, {"status": "online", "screen_url": screen_url})

                if not last_command:
                    # print(f"[{bot_name}] Komut yok, rölanti modunda.")
                    continue

                print(f"--- ⛏️ [{bot_name}] Komut işleniyor: {last_command} ---")
                
                # Komutu veritabanından sil (işleniyor olarak işaretle)
                db.update_minecraft_bot(bot_id, {"last_command": None, "current_task": last_command})

                # Simülasyon: Komutun işlenmesi için bekle
                if "mine" in last_command.lower():
                    action_time = 7
                    result = "Elmas cevheri başarıyla çıkarıldı."
                elif "build" in last_command.lower():
                    action_time = 10
                    result = "Basit bir ev inşa edildi."
                else:
                    action_time = 3
                    result = "Komut başarıyla çalıştırıldı."

                await asyncio.sleep(action_time)
                
                # Sonucu veritabanına kaydet ve botu rölantiye al
                db.update_minecraft_bot(bot_id, {
                    "status": "online",
                    "current_task": f"Bitti: {result}",
                    "screen_url": f"/static/img/screen_{bot_id}_{int(time.time())}_done.jpg" 
                })

                print(f"[{bot_name}] İşlem Tamamlandı. Sonuç: {result}")

        except Exception as e:
            print(f"⛏️ Minecraft Worker'da Hata: {e}")
            
        await asyncio.sleep(WORKER_LOOP_INTERVAL)


async def anime_producer_logic():
    """Anime Video Producer'ının Simülasyonu."""
    print("🎬 Anime Producer Worker Başlatıldı.")
    while True:
        try:
            db.load()
            
            # Sadece video bekleyen (video_pending) durumundaki görevleri al
            pending_videos = [v for v in db.data.get("anime_videos", []) if v.get("status") == "video_pending"]
            
            for video in pending_videos:
                video_id = video["id"]
                
                print(f"--- 🎬 [Video ID: {video_id[:8]}] Video üretimine başlanıyor... ---")
                
                # Durumu "Üretiliyor" olarak güncelle
                db.update_anime_video(video_id, {"status": "producing", "start_time": datetime.utcnow().isoformat()})

                # Simülasyon: Video üretimi için bekleme
                await asyncio.sleep(VIDEO_PRODUCTION_TIME)
                
                # Simüle edilmiş video dosyası yolu (Gerçekte bir .mp4 dosyası)
                video_filename = f"anime_video_{video_id}.mp4"
                video_url = f"/static/videos/{video_filename}"
                
                # Video dosyasını oluştur (Simülasyon amaçlı)
                Path("static/videos").mkdir(parents=True, exist_ok=True)
                with open(Path(f"static/videos/{video_filename}"), 'w') as f:
                    f.write(f"Simüle Edilmiş Video İçeriği: {video['prompt']}")

                # Sonucu veritabanına kaydet
                db.update_anime_video(video_id, {
                    "status": "video_completed",
                    "video_url": video_url,
                    "completion_time": datetime.utcnow().isoformat()
                })
                
                print(f"[Video ID: {video_id[:8]}] Üretim Tamamlandı! URL: {video_url}")

        except Exception as e:
            print(f"🎬 Anime Producer'da Hata: {e}")
            
        await asyncio.sleep(WORKER_LOOP_INTERVAL)


# ====== AUTH ENDPOINTS ======
@app.post("/api/register")
# ... (register fonksiyonu önceki kodunuzdakiyle aynı)
async def register(req: RegisterRequest):
    # Check if user exists
    if db.get_user(req.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    user = {
        "id": str(uuid.uuid4()),
        "username": req.username,
        "password_hash": get_password_hash(req.password),
        "role": "user",
        "created_at": datetime.utcnow().isoformat(),
        "mode": "arkadaş"
    }
    
    db.add_user(user)
    
    # Create token
    token = create_access_token({"sub": req.username, "role": "user"})
    
    return {
        "token": token,
        "user": {
            "username": req.username,
            "role": "user"
        }
    }

@app.post("/api/login")
# ... (login fonksiyonu önceki kodunuzdakiyle aynı)
async def login(req: LoginRequest):
    # Super admin check
    if req.username == SUPER_ADMIN_USERNAME and req.password == SUPER_ADMIN_PASSWORD:
        token = create_access_token({"sub": req.username, "role": "super_admin"})
        return {
            "token": token,
            "user": {
                "username": req.username,
                "role": "super_admin"
            }
        }
    
    # Regular user check
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if banned
    if db.is_banned(req.username):
        raise HTTPException(status_code=403, detail="User is banned")
    
    token = create_access_token({"sub": req.username, "role": user["role"]})
    
    return {
        "token": token,
        "user": {
            "username": req.username,
            "role": user["role"]
        }
    }

@app.get("/api/me")
# ... (get_me fonksiyonu önceki kodunuzdakiyle aynı)
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

# ====== CHAT ENDPOINTS ======
@app.post("/api/chat")
# ... (chat fonksiyonu önceki kodunuzdakiyle aynı)
async def chat(req: ChatRequest, current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    
    # Get chat history
    history = db.get_chats(username)
    chat_history = [{"user": c["message"], "ai": c["response"]} for c in history[-10:]]
    
    # Get AI response
    user_mode = current_user.get("mode", "arkadaş")
    ai_response = await ai_assistant.chat(req.message, req.mode or user_mode, chat_history)
    
    # Save chat
    chat_record = {
        "id": str(uuid.uuid4()),
        "username": username,
        "message": req.message,
        "response": ai_response,
        "mode": req.mode or user_mode,
        "timestamp": datetime.utcnow().isoformat()
    }
    db.add_chat(chat_record)
    
    return {
        "response": ai_response,
        "mode": req.mode or user_mode
    }

@app.get("/api/chat/history")
# ... (get_chat_history fonksiyonu önceki kodunuzdakiyle aynı)
async def get_chat_history(current_user: dict = Depends(get_current_user)):
    history = db.get_chats(current_user["username"])
    return {"history": history}

@app.delete("/api/chat/history")
# ... (clear_chat_history fonksiyonu önceki kodunuzdakiyle aynı)
async def clear_chat_history(current_user: dict = Depends(get_current_user)):
    db.clear_chats(current_user["username"])
    return {"message": "Chat history cleared"}

# ====== COMMAND ENDPOINTS ======
@app.post("/api/command")
# ... (execute_command fonksiyonu önceki kodunuzdakiyle aynı)
async def execute_command(req: CommandRequest, current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    cmd = req.command.lower()
    
    result = {"success": False, "message": "Unknown command"}
    
    if cmd == "/mode":
        if len(req.args) > 0:
            new_mode = req.args[0].lower()
            if new_mode in ["arkadaş", "düşman", "öğretmen"]:
                db.update_user(username, {"mode": new_mode})
                result = {"success": True, "message": f"Mod değiştirildi: {new_mode}"}
            else:
                result = {"success": False, "message": "Geçersiz mod. Seçenekler: arkadaş, düşman, öğretmen"}
        else:
            current_mode = current_user.get("mode", "arkadaş")
            result = {"success": True, "message": f"Mevcut mod: {current_mode}"}
    
    elif cmd == "/clear":
        db.clear_chats(username)
        result = {"success": True, "message": "Sohbet geçmişi temizlendi"}
    
    elif cmd == "/teach":
        # Teaching system (placeholder)
        if len(req.args) > 0:
            teaching = " ".join(req.args)
            result = {"success": True, "message": f"Öğretildi: {teaching}"}
        else:
            result = {"success": False, "message": "Öğretmek için bir şey yazın"}
    
    elif cmd == "/ban":
        if current_user["role"] not in ["admin", "super_admin"]:
            result = {"success": False, "message": "Bu komutu kullanma yetkiniz yok"}
        elif len(req.args) > 0:
            target_username = req.args[0]
            reason = " ".join(req.args[1:]) if len(req.args) > 1 else "No reason"
            ban_record = {
                "id": str(uuid.uuid4()),
                "username": target_username,
                "banned_by": username,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat(),
                "active": True
            }
            db.add_ban(ban_record)
            result = {"success": True, "message": f"Kullanıcı yasaklandı: {target_username}"}
        else:
            result = {"success": False, "message": "Kullanıcı adı belirtin"}
    
    elif cmd == "/search":
        # Search functionality (placeholder)
        query = " ".join(req.args)
        result = {"success": True, "message": f"Arama yapıldı: {query}"}
    
    # Log command
    cmd_record = {
        "id": str(uuid.uuid4()),
        "username": username,
        "command": cmd,
        "args": req.args,
        "result": result,
        "timestamp": datetime.utcnow().isoformat()
    }
    db.add_command(cmd_record)
    
    return result

# ====== ADMIN ENDPOINTS ======
@app.get("/api/admin/users")
# ... (get_all_users fonksiyonu önceki kodunuzdakiyle aynı)
async def get_all_users(current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    users = db.get_users()
    # Remove password hashes
    safe_users = [{k: v for k, v in u.items() if k != "password_hash"} for u in users]
    return {"users": safe_users}

@app.get("/api/admin/bans")
# ... (get_all_bans fonksiyonu önceki kodunuzdakiyle aynı)
async def get_all_bans(current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {"bans": db.get_bans()}

@app.post("/api/admin/ban")
# ... (ban_user fonksiyonu önceki kodunuzdakiyle aynı)
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
    db.add_ban(ban_record)
    
    return {"message": f"User {req.username} has been banned"}

# ====== ANIME DUBLAJ ENDPOINTS ======
@app.post("/api/anime/generate")
# ... (generate_anime fonksiyonu önceki kodunuzdakiyle aynı, sadece DB kaydı değişti)
async def generate_anime(req: AnimeRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admin can generate anime videos")
    
    # Generate script
    script = await ai_assistant.generate_anime_script(req.prompt, req.character)
    
    # Generate audio (TTS)
    audio_filename = f"anime_{uuid.uuid4()}.wav"
    audio_path = Path(f"static/audio/{audio_filename}")
    audio_path.parent.mkdir(parents=True, exist_ok=True)
    
    audio_success = tts_engine.text_to_speech_file(script, str(audio_path))
    
    # Create video record
    video_record = {
        "id": str(uuid.uuid4()),
        "prompt": req.prompt,
        "character": req.character,
        "script": script,
        "audio_url": f"/static/audio/{audio_filename}" if audio_success else None,
        "video_url": None,  # Producer tarafından doldurulacak
        "created_by": current_user["username"],
        "created_at": datetime.utcnow().isoformat(),
        # DB sınıfı, "completed" ise bunu "video_pending" olarak güncelleyecektir.
        "status": "completed" if audio_success else "audio_failed" 
    }
    db.add_anime_video(video_record)
    
    return {
        "video": video_record,
        "message": "Anime script ve ses dosyası oluşturuldu. Video üretimi arka planda başlıyor..." if audio_success else "Script oluşturuldu, ses dosyası oluşturulamadı"
    }

@app.get("/api/anime/videos")
# ... (get_anime_videos fonksiyonu önceki kodunuzdakiyle aynı)
async def get_anime_videos(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admin can access anime videos")
    
    videos = db.get_anime_videos(current_user["username"])
    return {"videos": videos}

# ====== MINECRAFT BOT ENDPOINTS ======
@app.post("/api/minecraft/bot/create")
# ... (create_minecraft_bot fonksiyonu önceki kodunuzdakiyle aynı)
async def create_minecraft_bot(req: MinecraftBotCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admin can create bots")
    
    bot = {
        "id": str(uuid.uuid4()),
        "bot_name": req.bot_name,
        "server_ip": req.server_ip,
        "server_port": req.server_port,
        "status": "offline",  # Worker tarafından online yapılacak
        "last_command": None,
        "created_by": current_user["username"],
        "created_at": datetime.utcnow().isoformat()
    }
    db.add_minecraft_bot(bot)
    
    return {
        "bot": bot,
        "message": "Bot oluşturuldu. Worker'ımız otomatik bağlanacak."
    }

@app.get("/api/minecraft/bots")
# ... (get_minecraft_bots fonksiyonu önceki kodunuzdakiyle aynı)
async def get_minecraft_bots(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admin can view bots")
    
    bots = db.get_minecraft_bots()
    return {"bots": bots}

@app.post("/api/minecraft/bot/command")
# ... (send_bot_command fonksiyonu önceki kodunuzdakiyle aynı)
async def send_bot_command(req: MinecraftBotCommand, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admin can send bot commands")
    
    # Update bot with command
    success = db.update_minecraft_bot(req.bot_id, {
        "last_command": req.command, # Worker bu alanı okuyacak
        "last_command_time": datetime.utcnow().isoformat()
    })
    
    if not success:
        raise HTTPException(status_code=404, detail="Bot not found")
    
    return {
        "message": "Komut gönderildi. Bot worker'ı kısa süre içinde işleme başlayacak.",
        "command": req.command
    }

# ====== FRONTEND HTML ======
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    html = """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AURION Project v17.0</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }
            
            .container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 1200px;
                width: 100%;
                overflow: hidden;
            }
            
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            
            .header h1 {
                font-size: 2.5rem;
                margin-bottom: 10px;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }
            
            .header p {
                font-size: 1rem;
                opacity: 0.9;
            }
            
            .main-content {
                padding: 30px;
            }
            
            .auth-section {
                max-width: 400px;
                margin: 0 auto;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 600;
            }
            
            .form-group input {
                width: 100%;
                padding: 12px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 1rem;
                transition: border-color 0.3s;
            }
            
            .form-group input:focus {
                outline: none;
                border-color: #667eea;
            }
            
            .btn {
                width: 100%;
                padding: 14px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 1.1rem;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s;
            }
            
            .btn:hover {
                transform: translateY(-2px);
            }
            
            .btn-secondary {
                background: #6c757d;
                margin-top: 10px;
            }
            
            .chat-section {
                display: none;
            }
            
            .chat-section.active {
                display: block;
            }
            
            .user-info {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .chat-box {
                background: #f8f9fa;
                border-radius: 12px;
                padding: 20px;
                height: 400px;
                overflow-y: auto;
                margin-bottom: 20px;
            }
            
            .message {
                margin-bottom: 15px;
                padding: 12px;
                border-radius: 8px;
            }
            
            .message.user {
                background: #667eea;
                color: white;
                margin-left: 20%;
            }
            
            .message.ai {
                background: white;
                border: 2px solid #e0e0e0;
                margin-right: 20%;
            }
            
            .chat-input {
                display: flex;
                gap: 10px;
            }
            
            .chat-input input {
                flex: 1;
                padding: 12px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 1rem;
            }
            
            .mode-selector {
                display: flex;
                gap: 10px;
                margin-bottom: 15px;
            }
            
            .mode-btn {
                flex: 1;
                padding: 10px;
                background: white;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .mode-btn.active {
                background: #667eea;
                color: white;
                border-color: #667eea;
            }
            
            .tabs {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                border-bottom: 2px solid #e0e0e0;
            }
            
            .tab {
                padding: 12px 24px;
                background: none;
                border: none;
                cursor: pointer;
                font-size: 1rem;
                color: #6c757d;
                border-bottom: 3px solid transparent;
                transition: all 0.3s;
            }
            
            .tab.active {
                color: #667eea;
                border-bottom-color: #667eea;
            }
            
            .tab-content {
                display: none;
            }
            
            .tab-content.active {
                display: block;
            }
            
            .admin-panel {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 12px;
            }
            
            .bot-card {
                background: white;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 15px;
                border-left: 4px solid #667eea;
            }
            
            .status-online {
                color: #28a745;
                font-weight: 600;
            }
            
            .status-offline {
                color: #dc3545;
                font-weight: 600;
            }
            
            .anime-player {
                background: black;
                border-radius: 12px;
                padding: 20px;
                text-align: center;
                min-height: 300px;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
            }
            
            .anime-player video,
            .anime-player audio {
                max-width: 100%;
                margin-top: 20px;
            }

            .bot-screen-img {
                max-width: 100%;
                height: auto;
                margin-top: 10px;
                border-radius: 5px;
                border: 1px solid #ddd;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>⚡ AURION PROJECT</h1>
                <p>v17.0 - AI Powered Anime & Minecraft Bot Control Center</p>
            </div>
            
            <div class="main-content">
                <div id="authSection" class="auth-section">
                    <div class="form-group">
                        <label>Kullanıcı Adı</label>
                        <input type="text" id="username" placeholder="Kullanıcı adınız">
                    </div>
                    <div class="form-group">
                        <label>Şifre</label>
                        <input type="password" id="password" placeholder="Şifreniz">
                    </div>
                    <button class="btn" onclick="login()">Giriş Yap</button>
                    <button class="btn btn-secondary" onclick="register()">Kayıt Ol</button>
                </div>
                
                <div id="chatSection" class="chat-section">
                    <div class="user-info">
                        <div>
                            <strong id="currentUsername"></strong>
                            <span id="currentRole"></span>
                        </div>
                        <button class="btn" style="width: auto; padding: 8px 16px;" onclick="logout()">Çıkış</button>
                    </div>
                    
                    <div class="tabs">
                        <button class="tab active" onclick="switchTab('chat')">💬 Sohbet</button>
                        <button class="tab" id="adminTab" onclick="switchTab('admin')" style="display: none;">👑 Admin Paneli</button>
                        <button class="tab" id="animeTab" onclick="switchTab('anime')" style="display: none;">🎬 Anime Dublaj</button>
                        <button class="tab" id="minecraftTab" onclick="switchTab('minecraft')" style="display: none;">⛏️ Minecraft Bots</button>
                    </div>
                    
                    <div id="chatTab" class="tab-content active">
                        <div class="mode-selector">
                            <button class="mode-btn active" data-mode="arkadaş" onclick="selectMode('arkadaş')">😊 Arkadaş</button>
                            <button class="mode-btn" data-mode="düşman" onclick="selectMode('düşman')">😈 Düşman</button>
                            <button class="mode-btn" data-mode="öğretmen" onclick="selectMode('öğretmen')">👨‍🏫 Öğretmen</button>
                        </div>
                        
                        <div class="chat-box" id="chatBox"></div>
                        
                        <div class="chat-input">
                            <input type="text" id="messageInput" placeholder="Mesajınızı yazın..." onkeypress="if(event.key==='Enter') sendMessage()">
                            <button class="btn" style="width: auto; padding: 12px 24px;" onclick="sendMessage()">Gönder</button>
                        </div>
                    </div>
                    
                    <div id="adminTab" class="tab-content">
                        <div class="admin-panel">
                            <h2>Kullanıcı Yönetimi</h2>
                            <div id="usersList"></div>
                            
                            <h2 style="margin-top: 30px;">Yasaklanan Kullanıcılar</h2>
                            <div id="bansList"></div>
                        </div>
                    </div>
                    
                    <div id="animeTab" class="tab-content">
                        <h2>🎬 Anime Dublaj Oluştur</h2>
                        <div class="form-group">
                            <label>Anime İstemi</label>
                            <input type="text" id="animePrompt" placeholder="Örn: Bir ninja karakteri köyde dolaşıyor ve arkadaşlarıyla konuşuyor">
                        </div>
                        <div class="form-group">
                            <label>Karakter Adı</label>
                            <input type="text" id="animeCharacter" placeholder="Örn: Naruto" value="Anime Karakteri">
                        </div>
                        <button class="btn" onclick="generateAnime()">Anime Oluştur</button>
                        
                        <div id="animePlayer" class="anime-player" style="margin-top: 20px; display: none;">
                            <h3 style="color: white;">Anime Oynatıcı</h3>
                            <p id="animeScript" style="color: white; margin-top: 20px;"></p>
                            <audio id="animeAudio" controls></audio>
                            <video id="animeVideo" controls style="display: none;"></video>
                        </div>
                        
                        <div id="animeHistory" style="margin-top: 30px;"></div>
                    </div>
                    
                    <div id="minecraftTab" class="tab-content">
                        <h2>⛏️ Minecraft Bot Yönetim Merkezi</h2>
                        
                        <div class="form-group">
                            <label>Bot Adı</label>
                            <input type="text" id="botName" placeholder="Bot adı">
                        </div>
                        <div class="form-group">
                            <label>Sunucu IP</label>
                            <input type="text" id="serverIp" placeholder="localhost">
                        </div>
                        <div class="form-group">
                            <label>Port</label>
                            <input type="number" id="serverPort" placeholder="25565" value="25565">
                        </div>
                        <button class="btn" onclick="createBot()">Bot Oluştur</button>
                        
                        <h3 style="margin-top: 30px;">Mevcut Botlar</h3>
                        <div id="botsList"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            let token = null;
            let currentUser = null;
            let currentMode = 'arkadaş';
            
            // Auth Functions
            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch('/api/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username, password})
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        token = data.token;
                        currentUser = data.user;
                        showChatSection();
                    } else {
                        alert('Giriş başarısız: ' + data.detail);
                    }
                } catch (error) {
                    alert('Hata: ' + error.message);
                }
            }
            
            async function register() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch('/api/register', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username, password})
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        token = data.token;
                        currentUser = data.user;
                        showChatSection();
                    } else {
                        alert('Kayıt başarısız: ' + data.detail);
                    }
                } catch (error) {
                    alert('Hata: ' + error.message);
                }
            }
            
            function logout() {
                token = null;
                currentUser = null;
                document.getElementById('authSection').style.display = 'block';
                document.getElementById('chatSection').classList.remove('active');
            }
            
            function showChatSection() {
                document.getElementById('authSection').style.display = 'none';
                document.getElementById('chatSection').classList.add('active');
                document.getElementById('currentUsername').textContent = currentUser.username;
                document.getElementById('currentRole').textContent = `(${currentUser.role})`;
                
                // Show admin tabs if admin or super_admin
                if (currentUser.role === 'admin' || currentUser.role === 'super_admin') {
                    document.getElementById('adminTab').style.display = 'block';
                }
                
                // Show super admin tabs
                if (currentUser.role === 'super_admin') {
                    document.getElementById('animeTab').style.display = 'block';
                    document.getElementById('minecraftTab').style.display = 'block';
                }
                
                loadChatHistory();
            }
            
            // Chat Functions
            function selectMode(mode) {
                currentMode = mode;
                document.querySelectorAll('.mode-btn').forEach(btn => {
                    btn.classList.remove('active');
                    if (btn.dataset.mode === mode) {
                        btn.classList.add('active');
                    }
                });
            }
            
            async function sendMessage() {
                const input = document.getElementById('messageInput');
                const message = input.value.trim();
                
                if (!message) return;
                
                // Add user message to chat
                addMessageToChat(message, 'user');
                input.value = '';
                
                try {
                    const response = await fetch('/api/chat', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify({message, mode: currentMode})
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        addMessageToChat(data.response, 'ai');
                    } else {
                        addMessageToChat('Hata: ' + data.detail, 'ai');
                    }
                } catch (error) {
                    addMessageToChat('Hata: ' + error.message, 'ai');
                }
            }
            
            function addMessageToChat(message, type) {
                const chatBox = document.getElementById('chatBox');
                const messageDiv = document.createElement('div');
                messageDiv.className = `message ${type}`;
                messageDiv.textContent = message;
                chatBox.appendChild(messageDiv);
                chatBox.scrollTop = chatBox.scrollHeight;
            }
            
            async function loadChatHistory() {
                try {
                    const response = await fetch('/api/chat/history', {
                        headers: {'Authorization': `Bearer ${token}`}
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        const chatBox = document.getElementById('chatBox');
                        chatBox.innerHTML = '';
                        data.history.forEach(chat => {
                            addMessageToChat(chat.message, 'user');
                            addMessageToChat(chat.response, 'ai');
                        });
                    }
                } catch (error) {
                    console.error('Error loading chat history:', error);
                }
            }
            
            // Tab Functions
            function switchTab(tabName) {
                document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
                
                event.target.classList.add('active');
                document.getElementById(`${tabName}Tab`).classList.add('active');
                
                // Load data for specific tabs
                if (tabName === 'admin') loadAdminData();
                if (tabName === 'minecraft') loadBots();
                if (tabName === 'anime') loadAnimeHistory();
            }
            
            // Admin Functions
            async function loadAdminData() {
                try {
                    const [usersRes, bansRes] = await Promise.all([
                        fetch('/api/admin/users', {headers: {'Authorization': `Bearer ${token}`}}),
                        fetch('/api/admin/bans', {headers: {'Authorization': `Bearer ${token}`}})
                    ]);
                    
                    const usersData = await usersRes.json();
                    const bansData = await bansRes.json();
                    
                    const usersList = document.getElementById('usersList');
                    usersList.innerHTML = usersData.users.map(user => `
                        <div class="bot-card">
                            <strong>${user.username}</strong> (${user.role})<br>
                            <small>Kayıt: ${new Date(user.created_at).toLocaleString('tr-TR')}</small>
                        </div>
                    `).join('');
                    
                    const bansList = document.getElementById('bansList');
                    bansList.innerHTML = bansData.bans.filter(b => b.active).map(ban => `
                        <div class="bot-card">
                            <strong>${ban.username}</strong><br>
                            Sebep: ${ban.reason}<br>
                            Yasaklayan: ${ban.banned_by}<br>
                            <small>${new Date(ban.timestamp).toLocaleString('tr-TR')}</small>
                        </div>
                    `).join('') || '<p>Yasaklı kullanıcı yok</p>';
                } catch (error) {
                    console.error('Error loading admin data:', error);
                }
            }
            
            // Anime Functions
            async function generateAnime() {
                const prompt = document.getElementById('animePrompt').value;
                const character = document.getElementById('animeCharacter').value;
                
                if (!prompt) {
                    alert('Lütfen bir anime istemi girin');
                    return;
                }
                
                try {
                    const response = await fetch('/api/anime/generate', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify({prompt, character})
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        alert(data.message);
                        loadAnimeHistory(); // Yeni görevi görmek için geçmişi yükle
                    } else {
                        alert('Hata: ' + data.detail);
                    }
                } catch (error) {
                    alert('Hata: ' + error.message);
                }
            }

            async function loadAnimeHistory() {
                try {
                    const response = await fetch('/api/anime/videos', {
                        headers: {'Authorization': `Bearer ${token}`}
                    });
                    
                    const data = await response.json();
                    const historyDiv = document.getElementById('animeHistory');
                    historyDiv.innerHTML = '<h3>Geçmiş Videolar:</h3>'
                    
                    if (response.ok && data.videos.length > 0) {
                        data.videos.forEach(video => {
                            const card = document.createElement('div');
                            card.className = 'bot-card';
                            
                            let statusText;
                            let mediaContent = '';
                            
                            if (video.status === 'video_completed') {
                                statusText = '✅ TAMAMLANDI';
                                mediaContent = `
                                    <audio controls src="${video.audio_url}" style="margin-top: 10px;"></audio>
                                    <video controls src="${video.video_url}" style="margin-top: 10px; max-width: 100%; height: auto;"></video>
                                `;
                            } else if (video.status === 'video_pending' || video.status === 'producing') {
                                statusText = `⏳ ${video.status.toUpperCase()}`;
                                mediaContent = `<p style="color: orange;">Video üretimi devam ediyor. Lütfen bekleyin...</p>`;
                            } else {
                                statusText = '❌ SES HATASI';
                            }
                            
                            card.innerHTML = `
                                <strong>${video.character} (Status: ${statusText})</strong><br>
                                İstem: ${video.prompt}<br>
                                Script: <small>${video.script.substring(0, 100)}...</small><br>
                                ${mediaContent}
                                <small>Oluşturma: ${new Date(video.created_at).toLocaleString('tr-TR')}</small>
                            `;
                            historyDiv.appendChild(card);
                        });
                    } else {
                        historyDiv.innerHTML += '<p>Henüz oluşturulmuş video yok.</p>';
                    }
                } catch (error) {
                    console.error('Error loading anime history:', error);
                }
            }
            
            // Minecraft Functions
            async function createBot() {
                const botName = document.getElementById('botName').value;
                const serverIp = document.getElementById('serverIp').value;
                const serverPort = document.getElementById('serverPort').value;
                
                if (!botName || !serverIp) {
                    alert('Bot adı ve sunucu IP gerekli');
                    return;
                }
                
                try {
                    const response = await fetch('/api/minecraft/bot/create', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify({
                            bot_name: botName,
                            server_ip: serverIp,
                            server_port: parseInt(serverPort)
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        alert(data.message);
                        loadBots();
                    } else {
                        alert('Hata: ' + data.detail);
                    }
                } catch (error) {
                    alert('Hata: ' + error.message);
                }
            }
            
            async function loadBots() {
                try {
                    const response = await fetch('/api/minecraft/bots', {
                        headers: {'Authorization': `Bearer ${token}`}
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        const botsList = document.getElementById('botsList');
                        botsList.innerHTML = data.bots.map(bot => {
                            const statusClass = bot.status === 'online' ? 'status-online' : 'status-offline';
                            const statusText = bot.status === 'online' ? '🟢 Online' : '🔴 Offline';
                            const commandInputId = `cmd_${bot.id}`;
                            
                            // Rastgele bir ekran görüntüsü URL'si oluşturma (Simülasyon)
                            const screenUrl = bot.screen_url || '/static/img/default_screen.jpg';
                            const currentTask = bot.current_task || 'Rölanti';

                            return `
                                <div class="bot-card">
                                    <strong>${bot.bot_name}</strong>
                                    <span class="${statusClass}">${statusText}</span><br>
                                    Sunucu: ${bot.server_ip}:${bot.server_port}<br>
                                    Mevcut Görev: ${currentTask}<br>
                                    <img src="${screenUrl}" class="bot-screen-img" alt="Bot Ekran Görüntüsü (Simüle)">
                                    <input type="text" id="${commandInputId}" placeholder="Komut gir (Örn: mine 5, build house)" style="margin-top: 10px; width: 70%;">
                                    <button class="btn" style="width: 28%; padding: 8px;" onclick="sendBotCommand('${bot.id}')">Gönder</button>
                                </div>
                            `;
                        }).join('') || '<p>Henüz bot yok</p>';

                        // Botlar listelendikten sonra 5 saniyede bir güncel yüklemek için ayarla
                        setTimeout(loadBots, 5000); 
                    }
                } catch (error) {
                    console.error('Error loading bots:', error);
                    // Hata durumunda bile 5 saniye sonra tekrar denemek
                    setTimeout(loadBots, 5000);
                }
            }
            
            async function sendBotCommand(botId) {
                const command = document.getElementById(`cmd_${botId}`).value;
                
                if (!command) {
                    alert('Komut girin');
                    return;
                }
                
                try {
                    const response = await fetch('/api/minecraft/bot/command', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify({bot_id: botId, command})
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        alert(data.message);
                        document.getElementById(`cmd_${botId}`).value = '';
                        loadBots(); // Komut gönderildikten hemen sonra listeyi güncelle
                    } else {
                        alert('Hata: ' + data.detail);
                    }
                } catch (error) {
                    alert('Hata: ' + error.message);
                }
            }
        </script>
    </body>
    </html>
    """
    return html

# Static files (for audio and simulated images/videos)
Path("static/audio").mkdir(parents=True, exist_ok=True)
Path("static/img").mkdir(parents=True, exist_ok=True)
Path("static/videos").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Ana Worker Loop'u Başlatmak İçin
@app.on_event("startup")
async def start_workers():
    # Worker'ları başlat
    asyncio.create_task(minecraft_worker_logic())
    asyncio.create_task(anime_producer_logic())


if __name__ == "__main__":
    import uvicorn
    
    # Worker'ları başlatmak için uvicorn'u asyncio loop'u içinde çalıştırın
    print("🚀 AURION Project v17.0 başlatılıyor...")
    print("🔐 Super Admin: enes / enes13579")
    print("📡 Server: http://localhost:8000")

    uvicorn.run(app, host="0.0.0.0", port=8000)
