import os
import time
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

# FastAPI ve Kütüphaneler
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext

# AI ve TTS Simülasyonları
try:
    # Google GenAI'ı kontrol et
    from google import genai
except ImportError:
    genai = None

# =========================================================
# KONFİGÜRASYON VE SABİTLER
# =========================================================

# JWT Ayarları
SECRET_KEY = os.environ.get("SECRET_KEY", "aurion-super-secret-key-2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 saat
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simülasyon Süreleri
VIDEO_PRODUCTION_TIME = 15  # Anime video üretimi (saniye)
BOT_TASK_TIME = 10          # Minecraft bot görev süresi (saniye)

# Veritabanı Dosya Yolu
DB_PATH = Path("data/db.json")

# Gemini API Kontrolü ve Yapılandırması
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
key_length = len(GEMINI_API_KEY)

if GEMINI_API_KEY and genai:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print(f">>> [GEMINI OK] API Key algılandı ve yapılandırıldı. (Uzunluk: {key_length})")
        AI_ENABLED = True
    except Exception as e:
        print(f"!!! [API ERROR] Gemini Configure Hatası: {e}")
        AI_ENABLED = False
else:
    print(f"!!! [GEMINI MISSING] GEMINI_API_KEY eksik veya genai yüklenemedi. AI özellikleri devre dışı. (Key Uzunluğu: {key_length})")
    AI_ENABLED = False


# =========================================================
# TEMEL SINIFLAR VE ARAÇLAR
# =========================================================

# Pydantic Modelleri
class User(BaseModel):
    username: str
    password: Optional[str] = None
    role: str = "user"
    is_banned: bool = False

class AnimeRequest(BaseModel):
    anime_name: str
    episode_number: int
    character_name: str

class BotRequest(BaseModel):
    server_ip: str
    server_port: Optional[int] = 25565
    count: int = 1

# Database İşlemleri
class DatabaseManager:
    """JSON dosyasını veritabanı olarak kullanan basit bir sınıf."""
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.db_path.exists():
            # İlk şifre hash'lenerek kaydedilir.
            initial_data = {
                "users": [
                    User(username="admin", password=_get_password_hash("admin"), role="super_admin").dict(),
                ],
                "chat_history": {},
                "minecraft_bots": [],
                "anime_videos": [],
            }
            with open(self.db_path, "w") as f:
                json.dump(initial_data, f, indent=4)

    def _read_db(self):
        try:
            with open(self.db_path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("!!! HATA: DB dosyası bozuk veya boş.")
            return {"users": [], "chat_history": {}, "minecraft_bots": [], "anime_videos": []}

    def _write_db(self, data):
        with open(self.db_path, "w") as f:
            json.dump(data, f, indent=4)

    # Kullanıcı İşlemleri
    def get_user(self, username: str):
        data = self._read_db()
        for user in data["users"]:
            if user["username"] == username:
                return user
        return None
    
    def get_all_users(self):
        return self._read_db().get("users", [])

    def update_user(self, username: str, updates: dict):
        data = self._read_db()
        for user in data["users"]:
            if user["username"] == username:
                user.update(updates)
                break
        self._write_db(data)
        
    # Chat İşlemleri
    def get_chat_history(self, username: str) -> List[dict]:
        return self._read_db().get("chat_history", {}).get(username, [])

    def add_chat_message(self, username: str, message: dict):
        data = self._read_db()
        if username not in data["chat_history"]:
            data["chat_history"][username] = []
        data["chat_history"][username].append(message)
        self._write_db(data)

    # Bot işlemleri
    def add_minecraft_bot(self, bot_data):
        data = self._read_db()
        data["minecraft_bots"].append(bot_data)
        self._write_db(data)

    def get_minecraft_bots(self):
        return self._read_db().get("minecraft_bots", [])

    def update_bot_status(self, bot_id: str, updates: dict):
        data = self._read_db()
        found = False
        for bot in data["minecraft_bots"]:
            if bot["id"] == bot_id:
                bot.update(updates)
                found = True
                break
        if found:
            self._write_db(data)
    
    # Anime işlemleri
    def add_anime_video(self, video_data):
        data = self._read_db()
        data["anime_videos"].append(video_data)
        self._write_db(data)

    def get_anime_videos(self):
        return self._read_db().get("anime_videos", [])

    def update_anime_video_status(self, video_id: str, updates: dict):
        data = self._read_db()
        found = False
        for video in data["anime_videos"]:
            if video["id"] == video_id:
                video.update(updates)
                found = True
                break
        if found:
            self._write_db(data)

db = DatabaseManager(DB_PATH)

# Yetkilendirme ve Güvenlik
def _get_password_hash(password):
    return pwd_context.hash(password)

def _verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = db.get_user(username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        if user["is_banned"]:
            raise HTTPException(status_code=403, detail="User is banned")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# AI Yardımcısı Sınıfı
class AIAssistant:
    def __init__(self):
        self.client = genai
        self.model = 'gemini-2.5-flash'
        self.system_instructions = "Sen, AURION projesinin özel yapay zekasısın. Kısa, net ve ilgili AI moduna uygun cevaplar ver. Asla kod yazma, sadece konuşma. Cevabın 2 cümleyi geçmesin."

    async def generate_response(self, prompt: str, history: List[dict], mode: str = "Friend") -> str:
        if not AI_ENABLED:
            return "❌ AI servisi şu anda aktif değil. Lütfen Super Admin ile iletişime geçin."
        
        # Mode'a göre talimatları ayarla
        mode_map = {
            "Teacher": "Öğretmen modundasın. Detaylı ve eğitici cevaplar ver. Cevabın 3 cümleyi geçmesin.",
            "Friend": "Dostça ve sıcak bir arkadaş modundasın. Samimi ve kısa cevaplar ver."
        }
        mode_instruction = mode_map.get(mode, self.system_instructions)
        full_instructions = f"{self.system_instructions} {mode_instruction}"
        
        # Tarihçeyi Gemini formatına çevir
        contents = [{"role": "user" if msg["sender"] == "user" else "model", "parts": [{"text": msg["content"]}]} for msg in history]
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=contents,
                config=genai.types.GenerateContentConfig(
                    system_instruction=full_instructions
                )
            )
            return response.text
        except Exception as e:
            print(f"Gemini API Error: {e}")
            return f"Üzgünüm, bir yapay zeka hatası oluştu: {e}"

    async def generate_full_episode_script(self, anime_name: str, episode_number: int, character_name: str) -> tuple[Optional[str], Optional[str]]:
        if not AI_ENABLED:
            return None, "AI Servisi Devre Dışı"
        
        script_prompt = (
            f"'{anime_name}' adlı animenin, {episode_number}. bölümü için '{character_name}' karakterinin 1 dakikalık Türkçe dublaj senaryosunu (Monolog veya Diyalog) oluştur. "
            f"Senaryo en az 200 kelime ve en fazla 300 kelime uzunluğunda olsun. Sadece senaryoyu döndür."
        )
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=[script_prompt]
            )
            return response.text, None
        except Exception as e:
            return None, str(e)

ai_assistant = AIAssistant()

# TTS (Metin Okuma) Motoru Simülasyonu
class TTS:
    async def text_to_speech_file(self, text: str, output_path: str) -> bool:
        """Gerçek TTS yerine dosya oluşturma simülasyonu."""
        try:
            # Basit bir dosya oluşturup başarılı döndür
            with open(output_path, "w") as f:
                f.write("Simulated WAV content for TTS.")
            return True
        except Exception as e:
            print(f"TTS Simülasyon Dosya Hatası: {e}")
            return False

tts_engine = TTS()

# Worker Simülasyon Mantığı
def get_new_screen_url(command: str) -> str:
    """Komuta göre yeni simülasyon ekranı URL'si döndürür."""
    cmd = command.lower()
    if "mine" in cmd or "kaz" in cmd:
        return "/static/img/sim/screen_mine.png"
    elif "build" in cmd or "yap" in cmd:
        return "/static/img/sim/screen_build.png"
    elif "follow" in cmd or "takip" in cmd:
        return "/static/img/sim/screen_follow.png"
    else:
        return "/static/img/sim/screen_default.png"

def minecraft_worker_logic():
    """Botların durumunu ve komutlarını günceller."""
    bots = db.get_minecraft_bots()
    for bot in bots:
        # Görev bitiş kontrolü
        if bot.get("current_task") and "Çalışıyor" in bot["current_task"] and bot.get("task_start_time"):
            if time.time() - bot.get("task_start_time", 0) > BOT_TASK_TIME:
                db.update_bot_status(bot["id"], {
                    "current_task": "Rölanti - Görev Tamamlandı",
                    "screen_url": get_new_screen_url("default"),
                    "last_command": None,
                    "task_start_time": None
                })
        
        # Yeni komut işleme
        elif bot.get("last_command"):
            command = bot["last_command"]
            task_description = command
            
            # Görevi Başlat
            db.update_bot_status(bot["id"], {
                "current_task": f"Çalışıyor: {task_description}",
                "task_start_time": time.time(),
                "screen_url": get_new_screen_url(command),
                "last_command": None # Komut işlendi
            })

def anime_producer_logic():
    """Anime video üretim sürecini simüle eder."""
    videos = db.get_anime_videos()
    for video in videos:
        if video.get("status") == "video_pending":
            created_time = datetime.fromisoformat(video["created_at"]).timestamp()
            if time.time() - created_time > VIDEO_PRODUCTION_TIME:
                # Video üretimi tamamlandı
                db.update_anime_video_status(video["id"], {
                    "status": "video_completed",
                    "video_url": "/static/img/sim/simulated_video.mp4" 
                })


# =========================================================
# FASTAPI UYGULAMASI VE ROUTE TANIMLAMALARI
# =========================================================

app = FastAPI()

# Statik Dosyalar için dizinlerin oluşturulması
Path("static/img/sim").mkdir(parents=True, exist_ok=True)
Path("static/audio").mkdir(parents=True, exist_ok=True)

# Simülasyon resimlerini ve dosyalarını oluşturun
for img in ["screen_mine.png", "screen_build.png", "screen_follow.png", "screen_default.png"]:
    file_path = Path(f"static/img/sim/{img}")
    if not file_path.exists():
        with open(file_path, "w") as f:
            f.write(f"Placeholder content for {img}")

if not Path("static/img/sim/simulated_video.mp4").exists():
    with open("static/img/sim/simulated_video.mp4", "w") as f:
        f.write("Placeholder content for video file.")


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
async def startup_event():
    # Başlangıçta 3 simülasyon botu oluşturun (Eğer DB boşsa)
    if len(db.get_minecraft_bots()) < 3:
        for i in range(1, 4):
            bot_data = {
                "id": str(uuid.uuid4()),
                "bot_name": f"AURIONBot_{i}",
                "server_ip": "127.0.0.1",
                "server_port": 25565,
                "status": "online",
                "current_task": "Sistem Başlatılıyor...",
                "last_command": None,
                "task_start_time": time.time() - 5, # Başlangıçta görevde olsun
                "screen_url": "/static/img/sim/screen_default.png"
            }
            db.add_minecraft_bot(bot_data)
        print(">>> [INIT] 3 adet varsayılan Minecraft botu oluşturuldu.")

# Worker logic'i Middleware içinde çalıştırılır.
@app.middleware("http")
async def worker_middleware(request: Request, call_next):
    # Bu, her API isteğinde simülasyonu günceller.
    minecraft_worker_logic()
    anime_producer_logic()
    response = await call_next(request)
    return response


# =========================================================
# AUTHENTICATION ROUTES
# =========================================================

@app.post("/api/auth/login")
async def login(response: JSONResponse, username: str = Form(...), password: str = Form(...)):
    user = db.get_user(username)
    if not user or not _verify_password(password, user["password"]):
        raise HTTPException(status_code=400, detail="Yanlış kullanıcı adı veya şifre.")
    
    if user["is_banned"]:
        raise HTTPException(status_code=403, detail="Hesabınız askıya alınmıştır.")

    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    
    response = JSONResponse(content={"message": "Giriş başarılı", "user": user["username"], "role": user["role"]})
    
    # Cookie'leri set et ve kullanıcı bilgisini JS'in okuması için ekle
    response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60) 
    response.set_cookie(key="user_name", value=user["username"], max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60) 
    response.set_cookie(key="user_role", value=user["role"], max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60) 
    
    return response

@app.post("/api/auth/register")
async def register(username: str = Form(...), password: str = Form(...)):
    if db.get_user(username):
        raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten kullanılıyor.")

    new_user_data = User(
        username=username,
        password=_get_password_hash(password),
        role="user",
        is_banned=False
    ).dict()
    new_user_data["password"] = _get_password_hash(password) # Şifreyi hash'lenmiş olarak kaydet

    if db.add_user(new_user_data):
        return {"message": "Kayıt başarılı. Lütfen giriş yapın."}
    raise HTTPException(status_code=500, detail="Kayıt sırasında bir hata oluştu.")

@app.get("/api/auth/logout")
async def logout(response: JSONResponse):
    response = JSONResponse(content={"message": "Çıkış başarılı"})
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="user_name")
    response.delete_cookie(key="user_role")
    return response

# =========================================================
# CHAT ROUTES
# =========================================================

@app.get("/api/chat/history")
async def get_history(current_user: dict = Depends(get_current_user)):
    history = db.get_chat_history(current_user["username"])
    return {"history": history}

@app.post("/api/chat")
async def chat(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    prompt = data.get("prompt")
    mode = data.get("mode", "Friend")
    
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt alanı boş olamaz.")

    history = db.get_chat_history(current_user["username"])
    
    # Kullanıcı mesajını kaydet
    user_msg = {"sender": "user", "content": prompt, "timestamp": datetime.utcnow().isoformat()}
    db.add_chat_message(current_user["username"], user_msg)
    
    # AI yanıtını al
    ai_response_text = await ai_assistant.generate_response(prompt, history, mode)
    
    # AI mesajını kaydet
    ai_msg = {"sender": "ai", "content": ai_response_text, "timestamp": datetime.utcnow().isoformat()}
    db.add_chat_message(current_user["username"], ai_msg)
    
    return {"response": ai_response_text}

# =========================================================
# ADMIN ROUTES
# =========================================================

@app.get("/api/admin/users")
async def get_admin_data(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    users = db.get_all_users()
    # Şifre alanını güvenlik için çıkar
    safe_users = [{k: v for k, v in user.items() if k != 'password'} for user in users]
    return {"users": safe_users}

@app.post("/api/admin/ban")
async def ban_user(request: Request, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    data = await request.json()
    target_username = data.get("username")
    
    if target_username == current_user["username"]:
        raise HTTPException(status_code=400, detail="Kendinizi yasaklayamazsınız.")

    db.update_user(target_username, {"is_banned": True})
    return {"message": f"{target_username} kullanıcısı yasaklandı."}

@app.post("/api/admin/unban")
async def unban_user(request: Request, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    data = await request.json()
    target_username = data.get("username")

    db.update_user(target_username, {"is_banned": False})
    return {"message": f"{target_username} kullanıcısının yasağı kaldırıldı."}

# =========================================================
# ANIME ROUTES
# =========================================================

@app.post("/api/anime/generate")
async def generate_anime(req: AnimeRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    generated_script, ai_error = await ai_assistant.generate_full_episode_script(
        req.anime_name,
        req.episode_number,
        req.character_name
    )

    if generated_script is None:
        raise HTTPException(status_code=503, detail=f"AI Senaryo Oluşturma Hatası: {ai_error}")
    
    record_id = str(uuid.uuid4())
    audio_filename = f"anime_full_episode_audio_{record_id}.wav"
    audio_path = Path(f"static/audio/{audio_filename}")
    audio_path.parent.mkdir(parents=True, exist_ok=True)
    
    audio_success = await tts_engine.text_to_speech_file(generated_script, str(audio_path))
    
    video_record = {
        "id": record_id,
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
    
    db.add_anime_video(video_record)
    
    if audio_success:
        return {"video": video_record, "message": f"'{req.anime_name}' Senaryo ve ses hazırlandı. Video üretimi başladı. (~{VIDEO_PRODUCTION_TIME} sn)"}
    else:
        return {"video": video_record, "message": "AI senaryo oluşturdu ancak ses dosyası oluşturulamadı.", "error": True}

@app.get("/api/anime/videos")
async def get_anime_videos(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    videos = db.get_anime_videos()
    return {"videos": videos}

# =========================================================
# MINECRAFT ROUTES
# =========================================================

@app.post("/api/minecraft/bot/create")
async def create_minecraft_bot(req: BotRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    current_bots = db.get_minecraft_bots()
    last_bot_num = int(current_bots[-1]['bot_name'].split('_')[-1]) if current_bots else 0
    
    created_bots = []
    for i in range(req.count):
        bot_id = str(uuid.uuid4())
        new_bot_num = last_bot_num + 1 + i
        bot_data = {
            "id": bot_id,
            "bot_name": f"AURIONBot_{new_bot_num}",
            "server_ip": req.server_ip,
            "server_port": req.server_port,
            "status": "online",
            "current_task": "Yeni Sunucuya Bağlanıyor",
            "last_command": None,
            "task_start_time": time.time(),
            "screen_url": "/static/img/sim/screen_default.png"
        }
        db.add_minecraft_bot(bot_data)
        created_bots.append(bot_data)

    return {"bots": created_bots, "message": f"{req.count} adet bot oluşturuldu ve {req.server_ip}:{req.server_port} sunucusuna bağlanma simülasyonu başlatıldı."}

@app.get("/api/minecraft/bots")
async def get_minecraft_bots(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {"bots": db.get_minecraft_bots()}

@app.post("/api/minecraft/bot/command")
async def send_bot_command(request: Request, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    data = await request.json()
    bot_id = data.get("bot_id")
    command = data.get("command")
    
    if not bot_id or not command:
        raise HTTPException(status_code=400, detail="Bot ID ve komut alanı boş olamaz.")
        
    # Komutu veritabanına yaz
    db.update_bot_status(bot_id, {"last_command": command, "current_task": f"Komut Alındı: {command}"})
    
    return {"message": f"Komut ('{command}') bota gönderildi. İşleniyor..."}

# =========================================================
# FRONTEND HTML VE BAŞLANGIÇ AYARLARI (AURION DESIGN)
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    
    html = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AURION Project - Super Admin Control</title>
        <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            /* >>>>>>>>>>>>>>>>> AURION GÖRSEL REVİZYONU - CSS BAŞLANGIÇ <<<<<<<<<<<<<<<<< */
            :root {{
                --bg-color: #0d1117; /* Koyu Mavi/Gri */
                --surface-color: #161b22; /* Orta Koyu Yüzey */
                --card-color: #21262d; /* Kart Arka Planı */
                --primary-color: #58a6ff; /* Mavi Vurgu */
                --secondary-color: #8b949e; /* Açık Gri Metin */
                --accent-color: #ff7aa2; /* Pembe/Mor Vurgu */
                --text-color: #c9d1d9; /* Açık Metin */
                --danger-color: #f85149;
                --success-color: #3fb950;
                --border-radius: 8px;
                --padding-unit: 15px;
            }}
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{ 
                font-family: 'Space Mono', monospace; 
                background-color: var(--bg-color); 
                color: var(--text-color); 
                min-height: 100vh; 
                display: flex;
                flex-direction: column;
            }}
            /* GENEL KONTROL YAPISI */
            #authSection {{ width: 100%; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
            .auth-card {{ max-width: 400px; width: 90%; background-color: var(--card-color); padding: 30px; border-radius: var(--border-radius); box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4); text-align: center; border: 1px solid #30363d; }}
            .auth-card h2 {{ color: var(--primary-color); margin-bottom: 25px; font-weight: 700; }}

            /* FORM VE INPUTLAR */
            .form-group {{ margin-bottom: 15px; text-align: left; }}
            .form-group input, .form-group textarea {{ 
                width: 100%; 
                padding: 10px; 
                border: 1px solid #30363d; 
                border-radius: 4px; 
                background-color: var(--surface-color); 
                color: var(--text-color); 
                font-size: 0.9rem; 
                transition: border-color 0.3s; 
            }}
            .btn {{ 
                padding: 10px 15px; 
                background-color: var(--primary-color); 
                color: var(--bg-color); 
                border: none; 
                border-radius: 4px; 
                font-size: 0.95rem; 
                font-weight: 700; 
                cursor: pointer; 
                transition: background-color 0.2s, transform 0.1s; 
            }}
            .btn:hover {{ background-color: #79c0ff; }}
            .btn:active {{ transform: scale(0.98); }}
            .btn-full {{ width: 100%; margin-top: 10px; }}
            .btn-secondary {{ background-color: var(--card-color); color: var(--text-color); border: 1px solid #30363d; }}
            .btn-secondary:hover {{ background-color: #30363d; }}
            .error-message {{ color: var(--danger-color); margin-top: 10px; font-size: 0.85rem; }}

            /* DASHBOARD YAPISI */
            #dashboard {{ display: flex; width: 100%; }}
            .sidebar {{ 
                width: 250px; 
                background-color: var(--card-color); 
                padding: 20px 0; 
                box-shadow: 2px 0 10px rgba(0, 0, 0, 0.5); 
                flex-shrink: 0;
                min-height: 100vh;
                border-right: 1px solid #30363d;
            }}
            .sidebar h1 {{ 
                font-size: 1.5rem; 
                text-align: center; 
                margin-bottom: 30px; 
                color: var(--accent-color); 
                border-bottom: 1px solid #30363d;
                padding-bottom: 15px;
            }}
            .user-info {{ 
                padding: 0 var(--padding-unit) 15px; 
                border-bottom: 1px solid #30363d; 
                margin-bottom: 15px; 
                font-size: 0.9rem;
            }}
            .nav-link {{ 
                padding: 12px var(--padding-unit); 
                display: flex; 
                align-items: center; 
                gap: 12px; 
                color: var(--secondary-color); 
                text-decoration: none; 
                cursor: pointer; 
                border-left: 4px solid transparent; 
                transition: background-color 0.3s, border-left-color 0.3s;
                font-weight: 400;
            }}
            .nav-link:hover {{ background-color: #30363d; }}
            .nav-link.active {{ 
                background-color: #30363d; 
                border-left-color: var(--primary-color); 
                color: var(--text-color); 
                font-weight: 700; 
            }}
            .nav-link.super-admin-link {{ color: var(--accent-color); font-weight: 700; }}

            /* ANA İÇERİK */
            .main-container {{ 
                flex-grow: 1; 
                padding: 40px; 
                background-color: var(--bg-color); 
                width: calc(100% - 250px);
            }} 
            .tab-content {{ display: none; }} 
            .tab-content.active {{ display: block; }} 

            h2 {{ color: var(--primary-color); margin-bottom: 25px; border-bottom: 1px solid #30363d; padding-bottom: 5px; font-size: 1.8rem; }}
            .sub-heading {{ color: var(--secondary-color); margin-top: 20px; margin-bottom: 10px; font-size: 1.2rem; }}

            /* KART YAPISI (Çoklu İçerik Alanı) */
            .card-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }}
            .data-card {{ 
                background-color: var(--card-color); 
                padding: var(--padding-unit); 
                border-radius: var(--border-radius); 
                border: 1px solid #30363d;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2); 
            }}

            /* CHAT STİLLERİ */
            .mode-selector {{ display: flex; gap: 15px; margin-bottom: 20px; }}
            .mode-btn {{ flex: 1; padding: 10px; background-color: var(--card-color); color: var(--secondary-color); border: 1px solid #30363d; border-radius: 4px; cursor: pointer; transition: all 0.3s; }}
            .mode-btn.active {{ background-color: var(--primary-color); color: var(--bg-color); border-color: var(--primary-color); }}
            
            .chat-box {{ background: var(--surface-color); border-radius: var(--border-radius); padding: var(--padding-unit); height: 600px; overflow-y: auto; margin-bottom: 20px; display: flex; flex-direction: column; border: 1px solid #30363d; }}
            .message {{ margin-bottom: 10px; padding: 10px 15px; border-radius: 12px; max-width: 75%; font-size: 0.9rem; white-space: pre-wrap; }}
            .message.user {{ background-color: var(--primary-color); color: var(--bg-color); align-self: flex-end; border-bottom-right-radius: 4px; }}
            .message.ai {{ background-color: #30363d; color: var(--text-color); align-self: flex-start; border-bottom-left-radius: 4px; }}
            .chat-input {{ display: flex; gap: 10px; }}
            .chat-input input {{ flex-grow: 1; }}

            /* MINECRAFT VE ANIME STİLLERİ */
            .anime-form-grid {{ display: grid; grid-template-columns: 2fr 1fr 1fr 150px; gap: 20px; }}
            .bot-screen-img {{ 
                width: 100%; 
                height: auto; 
                margin-top: 10px; 
                border-radius: 4px; 
                border: 2px solid var(--primary-color); 
                background-color: black;
                object-fit: cover;
            }}
            .bot-command-input {{ display: flex; gap: 5px; margin-top: 10px; }}
            .status-online {{ color: var(--success-color) !important; }}
            .status-offline {{ color: var(--danger-color) !important; }}

            /* Anime Media Oynatıcıları */
            .anime-history-card video, .anime-history-card audio {{
                 width: 100%; 
                 margin-top: 10px; 
                 border-radius: 4px;
                 background-color: black;
            }}
            .anime-history-card video {{ height: 250px; border: 1px solid #30363d; }}
            /* >>>>>>>>>>>>>>>>> AURION GÖRSEL REVİZYONU - CSS BİTİŞ <<<<<<<<<<<<<<<<< */
        </style>
    </head>
    <body>
        
        <div id="authSection">
            <div class="auth-card">
                <h2 id="auth-title">AURION: Super Admin Girişi</h2>
                <div class="form-group">
                    <input type="text" id="username" placeholder="Kullanıcı Adı (admin)" required>
                </div>
                <div class="form-group">
                    <input type="password" id="password" placeholder="Şifre (admin)" required>
                </div>
                <button class="btn btn-full" onclick="handleAuth('login')">Giriş Yap</button>
                <p class="error-message" id="auth-message"></p>
                <hr style="border-top: 1px solid #30363d; margin: 20px 0;">
                <button class="btn btn-full btn-secondary" onclick="handleAuth('register')">Kayıt Ol</button>
            </div>
        </div>

        <div id="dashboard" style="display: none; width: 100%;">
            <div class="sidebar">
                <h1>AURION 🌐</h1>
                <div class="user-info">
                    Kullanıcı: <strong id="currentUsername"></strong><br>
                    Rol: <strong id="currentUserRole" style="color: var(--accent-color);"></strong>
                </div>
                <nav>
                    <a class="nav-link active" data-tab="chat" onclick="switchTab('chat')">💬 Chat & AI</a>
                    <a class="nav-link" data-tab="admin" onclick="switchTab('admin')">👤 Users</a>
                    <a class="nav-link" data-tab="minecraft" onclick="switchTab('minecraft')">⛏️ Minecraft BotNet</a>
                    <a class="nav-link super-admin-link" data-tab="anime" onclick="switchTab('anime')">🎬 Anime Producer</a>
                    <a class="nav-link" onclick="logout()">➡️ Logout</a>
                </nav>
            </div>
            
            <div class="main-container">
                
                <div id="chatTab" class="tab-content active">
                    <h2>💬 AI Assistant</h2>
                    <div class="mode-selector">
                        <button class="mode-btn active" data-mode="Friend" onclick="setMode('Friend')">🤖 FRIEND Mode</button>
                        <button class="mode-btn" data-mode="Teacher" onclick="setMode('Teacher')">👨‍🏫 TEACHER Mode</button>
                    </div>
                    <div class="chat-box" id="chatHistory">
                        </div>
                    <div class="chat-input">
                        <input type="text" id="chatInput" placeholder="Mesajınızı yazın..." onkeypress="if(event.key === 'Enter') sendChat()">
                        <button class="btn" onclick="sendChat()">Gönder</button>
                    </div>
                    <p id="chatStatus" style="color: var(--secondary-color); margin-top: 10px; font-size: 0.85rem;"></p>
                </div>
                
                <div id="adminTab" class="tab-content">
                    <h2>👤 User & Admin Panel</h2>
                    <p style="color: var(--secondary-color); margin-bottom: 20px;">Super Admin olarak kullanıcıları yönetin ve durumlarını kontrol edin.</p>
                    <div id="adminData" class="card-grid">
                        </div>
                </div>

                <div id="animeTab" class="tab-content">
                    <h2>🎬 Anime Dublaj ve Video Üretim Simülasyonu</h2>
                    <p style="color: var(--secondary-color); margin-bottom: 20px;">AI tarafından tam bölüm senaryosu oluşturun, seslendirin ve video üretimini simüle edin.</p>

                    <div class="data-card">
                        <div class="anime-form-grid">
                            <input type="text" id="animeName" placeholder="Anime Adı (Örn: One Piece)" required>
                            <input type="number" id="episodeNumber" placeholder="Bölüm No" min="1" value="1" required>
                            <input type="text" id="characterName" placeholder="Karakter Adı" required>
                            <button class="btn" onclick="generateAnime()">▶️ Başlat</button>
                        </div>
                        <p id="animeStatus" style="color: var(--primary-color); margin-top: 10px; font-size: 0.85rem;"></p>
                    </div>

                    <h2 class="sub-heading">Üretim Geçmişi</h2>
                    <div id="animeHistory" class="card-grid">
                        </div>
                </div>

                <div id="minecraftTab" class="tab-content">
                    <h2>⛏️ Minecraft BotNet Kontrolü</h2>
                    <p style="color: var(--secondary-color); margin-bottom: 20px;">Bot oluşturun, sunucuya bağlayın ve her bota özel komutlar gönderin.</p>
                    
                    <div class="data-card" style="margin-bottom: 30px;">
                        <div style="display: flex; gap: 20px;">
                            <input type="text" id="serverIP" placeholder="Sunucu IP (Örn: 127.0.0.1)" style="flex: 3;" required>
                            <input type="number" id="botCount" placeholder="Bot Sayısı" min="1" value="1" style="flex: 1;" required>
                            <button class="btn" style="flex: 1.5;" onclick="createBots()">➕ Bot Oluştur</button>
                        </div>
                        <p id="botCreateStatus" style="color: var(--primary-color); margin-top: 10px; font-size: 0.85rem;"></p>
                    </div>

                    <h2 class="sub-heading">🤖 Mevcut Botlar (Canlı Görünüm)</h2>
                    <p style="color: var(--secondary-color); margin-bottom: 15px;">Toplam Aktif Bot: <strong id="botCountDisplay" style="color: var(--success-color);">0</strong></p> 
                    
                    <div id="botsList" class="card-grid">
                        </div>
                </div>

            </div>
        </div>
        
        <script>
            // Global Değişkenler
            let currentMode = 'Friend';
            let updateInterval = null;
            const VIDEO_PRODUCTION_TIME = {VIDEO_PRODUCTION_TIME}; 

            // Hata Yönetimli API Çağrısı
            async function apiCall(endpoint, method = 'GET', data = null) {{
                try {{
                    const options = {{
                        method: method,
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                    }};
                    if (data && method !== 'GET') {{
                        options.body = JSON.stringify(data);
                    }}
                    
                    const response = await fetch(endpoint, options);
                    const contentType = response.headers.get("content-type");

                    if (response.status === 401 || response.status === 403) {{
                         alert("Oturum süreniz doldu veya yetkiniz yok. Lütfen tekrar giriş yapın.");
                         window.location.reload();
                         return {{ error: true }};
                    }}

                    if (contentType && contentType.indexOf("application/json") !== -1) {{
                        const json = await response.json();
                        if (!response.ok) {{
                            throw new Error(json.detail || json.message || 'API hatası');
                        }}
                        return json;
                    }} else {{
                        if (!response.ok) {{
                            throw new Error('API hatası: Sunucu yanıtı JSON değil.');
                        }}
                        return {{ message: "İşlem başarılı" }};
                    }}
                }} catch (error) {{
                    console.error("API Çağrısı Hatası:", error);
                    return {{ error: true, message: error.message }};
                }}
            }}

            // Auth İşlemleri
            function getCookie(name) {{
                const value = `; ${{document.cookie}}`;
                const parts = value.split(`; ${{name}}=`);
                if (parts.length === 2) return parts.pop().split(';').shift();
                return null;
            }}

            async function handleAuth(type) {{
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const messageEl = document.getElementById('auth-message');
                messageEl.textContent = '';

                if (!username || !password) {{
                    messageEl.textContent = 'Kullanıcı adı ve şifre gereklidir.';
                    return;
                }}

                const formData = new FormData();
                formData.append('username', username);
                formData.append('password', password);

                try {{
                    const response = await fetch(`/api/auth/${{type}}`, {{
                        method: 'POST',
                        body: formData,
                    }});
                    
                    const result = await response.json();
                    
                    if (response.ok) {{
                        messageEl.textContent = result.message;
                        if (type === 'login') {{
                             // Giriş başarılıysa dashboard'a geç
                             setTimeout(showDashboard, 100); 
                        }}
                    }} else {{
                        messageEl.textContent = result.detail || result.message || 'Bir hata oluştu.';
                    }}
                }} catch (error) {{
                    messageEl.textContent = 'Sunucuya bağlanılamadı.';
                }}
            }}

            function logout() {{
                apiCall('/api/auth/logout', 'GET').then(() => {{
                    window.location.reload();
                }});
            }}
            
            async function showDashboard() {{
                // Token ve kullanıcı bilgisi kontrolü
                const userName = getCookie('user_name');
                const userRole = getCookie('user_role');

                if (userName && userRole) {{
                    document.getElementById('authSection').style.display = 'none';
                    document.getElementById('dashboard').style.display = 'flex';
                    
                    document.getElementById('currentUsername').textContent = userName;
                    document.getElementById('currentUserRole').textContent = userRole;

                    switchTab('chat');
                }} else {{
                    document.getElementById('authSection').style.display = 'flex';
                    document.getElementById('dashboard').style.display = 'none';
                }}
            }}

            // Tab Yönetimi
            function switchTab(tabName) {{
                clearInterval(updateInterval); 

                document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
                
                document.querySelectorAll('.tab-content').forEach(content => {{
                    content.classList.remove('active');
                    content.style.display = 'none'; 
                }});
                
                const activeLink = document.querySelector(`.nav-link[data-tab="${{tabName}}"]`);
                const activeContent = document.getElementById(`${{tabName}}Tab`);

                if (activeLink) activeLink.classList.add('active');
                if (activeContent) {{
                    activeContent.classList.add('active');
                    activeContent.style.display = 'block';
                }}

                if (tabName === 'chat') loadChatHistory();
                else if (tabName === 'admin') loadAdminData();
                else if (tabName === 'minecraft') {{
                    loadBots();
                    updateInterval = setInterval(loadBots, 5000); 
                }}
                else if (tabName === 'anime') {{
                    loadAnimeHistory();
                    updateInterval = setInterval(loadAnimeHistory, 10000); 
                }}
            }}
            
            // AI Mode ve Chat Fonksiyonları (Önceki mantık korundu)
            function setMode(mode) {{
                currentMode = mode;
                document.querySelectorAll('.mode-btn').forEach(btn => {{
                    if (btn.getAttribute('data-mode') === mode) {{
                        btn.classList.add('active');
                    }} else {{
                        btn.classList.remove('active');
                    }}
                }});
                loadChatHistory();
            }}
            
            async function sendChat() {{
                const input = document.getElementById('chatInput');
                const prompt = input.value.trim();
                const statusEl = document.getElementById('chatStatus');

                if (!prompt) return;

                input.value = '';
                statusEl.textContent = 'AI yanıt bekleniyor...';
                
                appendMessage('user', prompt, true);

                const data = await apiCall('/api/chat', 'POST', {{ prompt: prompt, mode: currentMode }});
                
                if (data.error) {{
                    statusEl.textContent = data.message;
                    appendMessage('ai', 'Yanıt alınamadı: ' + data.message);
                }} else {{
                    statusEl.textContent = 'Yanıt geldi.';
                    appendMessage('ai', data.response);
                }}
            }}

            function appendMessage(sender, content, isTemporary = false) {{
                const chatHistoryEl = document.getElementById('chatHistory');
                const messageDiv = document.createElement('div');
                messageDiv.className = `message ${{sender}} ${{isTemporary ? 'temp' : ''}}`;
                messageDiv.textContent = content;
                chatHistoryEl.appendChild(messageDiv);
                
                chatHistoryEl.scrollTop = chatHistoryEl.scrollHeight;
            }}

            async function loadChatHistory() {{
                const data = await apiCall('/api/chat/history');
                const chatHistoryEl = document.getElementById('chatHistory');
                chatHistoryEl.innerHTML = ''; 

                if (data && data.history) {{
                    data.history.forEach(msg => {{
                        appendMessage(msg.sender, msg.content);
                    }});
                }}
                
                if (chatHistoryEl.children.length === 0) {{
                     appendMessage('ai', `Merhaba! Ben AURION AI. ${{currentMode}} modunda size yardımcı olacağım.`);
                }}
            }}

            // Admin Fonksiyonları (Önceki mantık korundu)
            async function loadAdminData() {{
                const data = await apiCall('/api/admin/users');
                const adminDataEl = document.getElementById('adminData');
                adminDataEl.innerHTML = '';
                
                if (data && data.users) {{
                    const currentUsername = getCookie('user_name');
                    data.users.forEach(user => {{
                        const card = document.createElement('div');
                        card.className = 'data-card';
                        
                        const statusColor = user.is_banned ? 'var(--danger-color)' : 'var(--success-color)';
                        const statusText = user.is_banned ? 'Yasaklı 🔴' : 'Aktif 🟢';
                        
                        card.style.borderLeft = `4px solid ${{statusColor}}`;
                        let buttons = '';

                        if (user.username !== currentUsername && user.role !== 'super_admin') {{
                            buttons = user.is_banned 
                                ? `<button class="btn btn-secondary" onclick="toggleBan('${{user.username}}', false)">Yasağı Kaldır</button>` 
                                : `<button class="btn btn-secondary" onclick="toggleBan('${{user.username}}', true)" style="background-color: var(--danger-color); color: white;">Yasakla</button>`;
                        }}

                        card.innerHTML = `
                            <strong>Kullanıcı: ${{user.username}}</strong><br>
                            <small>Rol: ${{user.role}}</small><br>
                            <small style="color: ${{statusColor}};">Durum: ${{statusText}}</small>
                            <div style="margin-top: 10px;">${{buttons}}</div>
                        `;
                        adminDataEl.appendChild(card);
                    }});
                }}
            }}

            function toggleBan(username, banStatus) {{
                const endpoint = banStatus ? '/api/admin/ban' : '/api/admin/unban';
                apiCall(endpoint, 'POST', {{ username: username }}).then(data => {{
                    alert(data.message || 'İşlem başarısız');
                    loadAdminData(); 
                }});
            }}

            // Anime Fonksiyonları (Önceki mantık korundu)
            async function generateAnime() {{
                const name = document.getElementById('animeName').value.trim();
                const episode = parseInt(document.getElementById('episodeNumber').value.trim());
                const character = document.getElementById('characterName').value.trim();
                const statusEl = document.getElementById('animeStatus');

                if (!name || isNaN(episode) || !character) {{
                    statusEl.textContent = 'Lütfen tüm alanları doldurun.';
                    return;
                }}
                
                statusEl.textContent = 'Üretim başlatılıyor...';
                
                const data = await apiCall('/api/anime/generate', 'POST', {{ 
                    anime_name: name, 
                    episode_number: episode, 
                    character_name: character 
                }});

                if (data.error) {{
                    statusEl.textContent = data.message;
                }} else {{
                    statusEl.textContent = data.message;
                    loadAnimeHistory(); 
                }}
            }}

            async function loadAnimeHistory() {{
                const data = await apiCall('/api/anime/videos');
                
                const historyDiv = document.getElementById('animeHistory');
                historyDiv.innerHTML = '';
                
                if (data && data.videos && data.videos.length > 0) {{
                    data.videos.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).forEach(video => {{
                        const card = document.createElement('div');
                        card.className = 'data-card anime-history-card';
                        
                        let statusText;
                        let statusColor;
                        let mediaContent = '';
                        
                        let timeSinceCreation = (new Date().getTime() - new Date(video.created_at).getTime()) / 1000;
                        let remainingTime = Math.max(0, VIDEO_PRODUCTION_TIME - timeSinceCreation);
                        let remainingTimeText = remainingTime > 0 ? `~${{Math.ceil(remainingTime)}} sn kaldı` : 'Hemen yüklenecek.';
                        
                        if (video.status === 'video_completed') {{
                            statusText = '✅ TAMAMLANDI';
                            statusColor = 'var(--success-color)';
                            mediaContent = `
                                <audio controls src="${{video.audio_url}}" style="width: 100%; margin-top: 10px;"></audio>
                                <video controls autoplay muted src="${{video.video_url}}" style="width: 100%; height: 250px; margin-top: 10px; background: black; border-radius: 4px;">
                                    Tarayıcınız video etiketini desteklemiyor.
                                </video>
                                <p style="color: var(--secondary-color); margin-top: 5px; font-size: 0.8rem;">(Video/Ses simülasyonu)</p>
                            `;
                        }} else if (video.status === 'video_pending' || video.status === 'producing') {{
                            statusText = `⏳ ÜRETİLİYOR (${{remainingTimeText}})`;
                            statusColor = 'var(--primary-color)';
                            mediaContent = video.audio_url ? `<audio controls src="${{video.audio_url}}" style="width: 100%; margin-top: 10px;"></audio><p style="color: var(--primary-color); margin-top: 10px;">Tam Bölüm üretimi sürüyor...</p>` : '';
                        }} else if (video.status === 'audio_failed') {{
                            statusText = '❌ SES HATASI';
                            statusColor = 'var(--danger-color)';
                            mediaContent = '<p style="color: var(--danger-color); margin-top: 10px;">Ses dosyası oluşturulamadı (TTS Hatası).</p>';
                        }} else {{
                            statusText = '❓ BİLİNMEYEN';
                            statusColor = 'var(--secondary-color)';
                        }}
                        
                        card.style.borderLeft = `4px solid ${{statusColor}}`;
                        card.innerHTML = `
                            <strong style="color: var(--accent-color);">${{video.anime_name}}</strong> - Bölüm ${{video.episode_number}}<br>
                            <span style="color: ${{statusColor}}; font-size: 0.9rem;">${{statusText}}</span> - Karakter: ${{video.character}}<br>
                            <small style="color: var(--secondary-color); font-size: 0.75rem;">Oluşturma: ${{new Date(video.created_at).toLocaleString('tr-TR')}}</small>
                            <div style="background-color: var(--surface-color); padding: 8px; border-radius: 4px; margin-top: 10px; font-size: 0.8rem; white-space: pre-wrap; max-height: 100px; overflow: hidden;">
                                ${{video.script.substring(0, 200)}}... (Tam Senaryo)
                            </div>
                            ${{mediaContent}}
                        `;
                        historyDiv.appendChild(card);
                    }});
                }} else {{
                    historyDiv.innerHTML = '<p style="color: var(--secondary-color);">Henüz oluşturulmuş dublaj yok.</p>';
                }}
            }}

            // Minecraft Fonksiyonları (Sıfır Hata ve Komut Mantığı)
            async function createBots() {{
                const ip = document.getElementById('serverIP').value.trim();
                const count = parseInt(document.getElementById('botCount').value.trim());
                const statusEl = document.getElementById('botCreateStatus');

                if (!ip || isNaN(count) || count < 1) {{
                    statusEl.textContent = 'Lütfen IP ve geçerli bot sayısını girin.';
                    return;
                }}
                
                statusEl.textContent = 'Botlar oluşturuluyor ve bağlanıyor...';

                const data = await apiCall('/api/minecraft/bot/create', 'POST', {{ 
                    server_ip: ip, 
                    count: count, 
                    server_port: 25565
                }});

                if (data.error) {{
                    statusEl.textContent = data.message;
                }} else {{
                    statusEl.textContent = data.message;
                    loadBots();
                }}
            }}

            async function sendBotCommand(botId, inputId) {{
                const commandInput = document.getElementById(inputId);
                const command = commandInput.value.trim();
                
                if (!command) {{
                    alert("Lütfen bir komut girin.");
                    return;
                }}
                
                commandInput.value = '';

                const data = await apiCall('/api/minecraft/bot/command', 'POST', {{ 
                    bot_id: botId, 
                    command: command 
                }});

                if (data.error) {{
                    alert(`Hata: ${{data.message}}`);
                }} else {{
                    // Komut gönderildi, worker çalışacak. 
                    // Hemen arayüzü güncelle (Komut Alındı durumunu göstermek için)
                    loadBots(); 
                }}
            }}

            async function loadBots() {{
                const data = await apiCall('/api/minecraft/bots');
                
                const botsList = document.getElementById('botsList');
                botsList.innerHTML = '';
                
                const botCountDisplay = document.getElementById('botCountDisplay');
                botCountDisplay.textContent = data && data.bots ? data.bots.length : 0; 
                botCountDisplay.style.color = data && data.bots && data.bots.length > 0 ? 'var(--success-color)' : 'var(--danger-color)';

                if (data && data.bots && data.bots.length > 0) {{
                    data.bots.forEach(bot => {{
                        const statusColor = bot.status === 'online' ? 'var(--success-color)' : 'var(--danger-color)';
                        const statusText = bot.status === 'online' ? '🟢 Online' : '🔴 Offline';
                        const commandInputId = 'cmd_' + bot.id; 
                        
                        const screenUrl = bot.screen_url ? `${{bot.screen_url}}?t=${{new Date().getTime()}}` : '/static/img/sim/screen_default.png';
                        const currentTask = bot.current_task || 'Rölanti';

                        const card = document.createElement('div');
                        card.className = 'data-card';
                        card.style.borderLeft = `4px solid ${{statusColor}}`;
                        
                        card.innerHTML = `
                            <strong style="color: var(--primary-color);">${{bot.bot_name}}</strong>
                            <span style="color: ${{statusColor}}; font-size: 0.9rem;">(${{statusText}})</span><br>
                            <small style="color: var(--secondary-color);">IP: ${{bot.server_ip}}:${{bot.server_port}}</small><br>
                            <small style="color: var(--text-color);">Görev: <span style="font-weight: 700;">${{currentTask}}</span></small>
                            
                            <img src="${{screenUrl}}" class="bot-screen-img" alt="Bot Ekran Görüntüsü (Simüle)">
                            
                            <div class="bot-command-input">
                                <input type="text" id="${{commandInputId}}" placeholder="mine 10, follow PlayerX, build house..." style="flex: 1;">
                                <button class="btn" style="padding: 8px 15px; background-color: var(--accent-color);" onclick="sendBotCommand('${{bot.id}}', '${{commandInputId}}')">GO</button>
                            </div>
                        `;
                        botsList.appendChild(card);
                    }});
                }} else {{
                    botsList.innerHTML = '<p style="color: var(--secondary-color);">Henüz bot yok. Lütfen yukarıdan oluşturun.</p>';
                }}
            }}


            // Init - Sayfa Yüklendiğinde
            document.addEventListener('DOMContentLoaded', () => {{
                showDashboard(); 
            }});

        </script>
    </body>
    </html>
    """
    return html

