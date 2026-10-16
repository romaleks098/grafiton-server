import os
import json
import sqlite3
import jwt
import datetime
import uuid
import shutil
from typing import Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import passlib.hash as hasher

SECRET_KEY = os.getenv("SECRET_KEY", "grafiton-super-secret-key-render-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

DB_FILE = os.getenv("DB_FILE", "grafiton.db")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(title="Графитон API", version="1.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        nickname TEXT NOT NULL,
        avatar_color TEXT NOT NULL,
        bio TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute("PRAGMA table_info(users)")
    user_cols = [col[1] for col in cursor.fetchall()]
    if "bio" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER,
        chat_id TEXT NOT NULL,
        content TEXT NOT NULL,
        msg_type TEXT DEFAULT 'text',
        media_url TEXT DEFAULT '',
        duration INTEGER DEFAULT 0,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id)
    )
    """)
    cursor.execute("PRAGMA table_info(messages)")
    msg_cols = [col[1] for col in cursor.fetchall()]
    if "msg_type" not in msg_cols:
        cursor.execute("ALTER TABLE messages ADD COLUMN msg_type TEXT DEFAULT 'text'")
    if "media_url" not in msg_cols:
        cursor.execute("ALTER TABLE messages ADD COLUMN media_url TEXT DEFAULT ''")
    if "duration" not in msg_cols:
        cursor.execute("ALTER TABLE messages ADD COLUMN duration INTEGER DEFAULT 0")
    if "is_read" not in msg_cols:
        cursor.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS channels (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        type TEXT DEFAULT 'group',
        owner_id INTEGER NOT NULL,
        avatar_color TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users (id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS channel_members (
        channel_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member',
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (channel_id, user_id),
        FOREIGN KEY (channel_id) REFERENCES channels (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)

    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Pydantic models
class UserRegister(BaseModel):
    username: str
    password: str
    nickname: Optional[str] = None

class UserProfileUpdate(BaseModel):
    nickname: Optional[str] = None
    bio: Optional[str] = None
    avatar_color: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    nickname: str
    avatar_color: str
    bio: Optional[str] = ""

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class MessageSend(BaseModel):
    receiver_id: Optional[int] = None
    chat_id: str = "general"
    content: str = ""
    msg_type: Optional[str] = "text"
    media_url: Optional[str] = ""
    duration: Optional[int] = 0

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    sender_name: str
    sender_avatar_color: Optional[str] = "#5288c1"
    receiver_id: Optional[int]
    chat_id: str
    content: str
    msg_type: str
    media_url: str
    duration: int
    is_read: int
    created_at: str

class ChannelCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    type: Optional[str] = "group"
    avatar_color: Optional[str] = None
    member_ids: Optional[List[int]] = []

class ChannelResponse(BaseModel):
    id: str
    name: str
    description: str
    type: str
    owner_id: int
    avatar_color: str
    members_count: int
    created_at: str

class MarkReadRequest(BaseModel):
    chat_id: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), conn: sqlite3.Connection = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось подтвердить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, nickname, avatar_color, bio FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if row is None:
        raise credentials_exception
    return dict(row)

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, list[WebSocket]] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)

    def disconnect(self, user_id: int, websocket: WebSocket):
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]

    async def broadcast_to_chat(self, chat_id: str, message: dict, sender_id: int, receiver_id: Optional[int] = None):
        data = json.dumps({"type": "new_message", "message": message})
        if chat_id == "general":
            for uid, connections in list(self.active_connections.items()):
                for ws in connections:
                    try:
                        await ws.send_text(data)
                    except Exception:
                        pass
        elif chat_id.startswith("direct_"):
            target_ids = {sender_id}
            if receiver_id:
                target_ids.add(receiver_id)
            for uid in target_ids:
                if uid in self.active_connections:
                    for ws in self.active_connections[uid]:
                        try:
                            await ws.send_text(data)
                        except Exception:
                            pass
        else:
            # Group or channel chat
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT user_id FROM channel_members WHERE channel_id = ?", (chat_id,))
            members = [row[0] for row in cur.fetchall()]
            conn.close()
            target_ids = set(members)
            target_ids.add(sender_id)
            for uid in target_ids:
                if uid in self.active_connections:
                    for ws in self.active_connections[uid]:
                        try:
                            await ws.send_text(data)
                        except Exception:
                            pass

    async def broadcast_typing(self, chat_id: str, sender_id: int, sender_name: str, receiver_id: Optional[int] = None):
        data = json.dumps({
            "type": "user_typing",
            "chat_id": chat_id,
            "user_id": sender_id,
            "user_name": sender_name
        })
        await self._broadcast_event(chat_id, data, exclude_user_id=sender_id, receiver_id=receiver_id)

    async def broadcast_read(self, chat_id: str, reader_id: int, receiver_id: Optional[int] = None):
        data = json.dumps({
            "type": "messages_read",
            "chat_id": chat_id,
            "reader_id": reader_id
        })
        await self._broadcast_event(chat_id, data, exclude_user_id=reader_id, receiver_id=receiver_id)

    async def _broadcast_event(self, chat_id: str, data: str, exclude_user_id: int, receiver_id: Optional[int] = None):
        if chat_id == "general":
            for uid, connections in list(self.active_connections.items()):
                if uid == exclude_user_id:
                    continue
                for ws in connections:
                    try:
                        await ws.send_text(data)
                    except Exception:
                        pass
        elif chat_id.startswith("direct_"):
            target_ids = set()
            if receiver_id:
                target_ids.add(receiver_id)
            else:
                parts = chat_id.replace("direct_", "").split("_")
                for p in parts:
                    if p.isdigit():
                        uid = int(p)
                        if uid != exclude_user_id:
                            target_ids.add(uid)
            for uid in target_ids:
                if uid in self.active_connections:
                    for ws in self.active_connections[uid]:
                        try:
                            await ws.send_text(data)
                        except Exception:
                            pass
        else:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT user_id FROM channel_members WHERE channel_id = ?", (chat_id,))
            members = [row[0] for row in cur.fetchall()]
            conn.close()
            for uid in members:
                if uid == exclude_user_id:
                    continue
                if uid in self.active_connections:
                    for ws in self.active_connections[uid]:
                        try:
                            await ws.send_text(data)
                        except Exception:
                            pass

manager = ConnectionManager()

# Routes
@app.get("/")
def read_root():
    return {
        "app": "Графитон (Grafiton) Messenger API",
        "status": "online",
        "version": "1.3.0"
    }

@app.head("/")
def head_root():
    return {}

@app.post("/api/auth/register", response_model=TokenResponse)
def register(user: UserRegister, conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (user.username.lower(),))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Пользователь с таким логином уже существует")

    nickname = user.nickname.strip() if user.nickname else user.username
    colors = ["#4A90E2", "#50E3C2", "#B8E986", "#F5A623", "#E94E77", "#9013FE", "#7ED321"]
    avatar_color = colors[hash(user.username) % len(colors)]
    password_hash = hasher.pbkdf2_sha256.hash(user.password)

    cursor.execute(
        "INSERT INTO users (username, password_hash, nickname, avatar_color, bio) VALUES (?, ?, ?, ?, ?)",
        (user.username.lower(), password_hash, nickname, avatar_color, "Привет, я в Графитоне!")
    )
    conn.commit()
    user_id = cursor.lastrowid

    token = create_access_token({"sub": user.username.lower(), "user_id": user_id})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "username": user.username.lower(),
            "nickname": nickname,
            "avatar_color": avatar_color,
            "bio": "Привет, я в Графитоне!"
        }
    }

@app.post("/api/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (form_data.username.lower(),))
    user = cursor.fetchone()
    if not user or not hasher.pbkdf2_sha256.verify(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Неверный логин или пароль")

    token = create_access_token({"sub": user["username"], "user_id": user["id"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "nickname": user["nickname"],
            "avatar_color": user["avatar_color"],
            "bio": user["bio"] if "bio" in user.keys() else ""
        }
    }

@app.get("/api/users", response_model=List[UserResponse])
def get_all_users(current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, nickname, avatar_color, bio FROM users ORDER BY nickname ASC")
    return [dict(row) for row in cursor.fetchall()]

@app.put("/api/users/profile", response_model=UserResponse)
def update_profile(profile_data: UserProfileUpdate, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    nickname = profile_data.nickname.strip() if profile_data.nickname else current_user["nickname"]
    bio = profile_data.bio if profile_data.bio is not None else current_user.get("bio", "")
    avatar_color = profile_data.avatar_color if profile_data.avatar_color else current_user["avatar_color"]

    cursor.execute("""
        UPDATE users SET nickname = ?, bio = ?, avatar_color = ? WHERE id = ?
    """, (nickname, bio, avatar_color, current_user["id"]))
    conn.commit()

    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "nickname": nickname,
        "avatar_color": avatar_color,
        "bio": bio
    }

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    ext = os.path.splitext(file.filename)[1].lower() if file.filename else ""
    if not ext:
        if file.content_type and "audio" in file.content_type:
            ext = ".webm"
        elif file.content_type and "image" in file.content_type:
            ext = ".jpg"
        else:
            ext = ".bin"
    
    unique_name = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(UPLOAD_DIR, unique_name)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    return {
        "url": f"/uploads/{unique_name}",
        "filename": unique_name,
        "content_type": file.content_type
    }

# Channels & Groups API
@app.post("/api/channels", response_model=ChannelResponse)
def create_channel(ch: ChannelCreate, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    prefix = "group" if ch.type == "group" else "channel"
    channel_id = f"{prefix}_{uuid.uuid4().hex[:10]}"
    colors = ["#2b5278", "#5288c1", "#3b82f6", "#10b981", "#8b5cf6", "#ec4899", "#f59e0b"]
    avatar_color = ch.avatar_color or colors[hash(ch.name) % len(colors)]

    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO channels (id, name, description, type, owner_id, avatar_color)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (channel_id, ch.name.strip(), ch.description.strip(), ch.type, current_user["id"], avatar_color))

    # Add owner
    cursor.execute("""
        INSERT INTO channel_members (channel_id, user_id, role)
        VALUES (?, ?, 'owner')
    """, (channel_id, current_user["id"]))

    # Add invited members
    for uid in ch.member_ids or []:
        if uid != current_user["id"]:
            cursor.execute("""
                INSERT OR IGNORE INTO channel_members (channel_id, user_id, role)
                VALUES (?, ?, 'member')
            """, (channel_id, uid))

    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM channel_members WHERE channel_id = ?", (channel_id,))
    members_count = cursor.fetchone()[0]

    return {
        "id": channel_id,
        "name": ch.name.strip(),
        "description": ch.description.strip(),
        "type": ch.type,
        "owner_id": current_user["id"],
        "avatar_color": avatar_color,
        "members_count": members_count,
        "created_at": datetime.datetime.utcnow().isoformat()
    }

@app.get("/api/channels", response_model=List[ChannelResponse])
def get_user_channels(current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.id, c.name, c.description, c.type, c.owner_id, c.avatar_color, c.created_at,
               (SELECT COUNT(*) FROM channel_members cm WHERE cm.channel_id = c.id) as members_count
        FROM channels c
        WHERE c.id IN (SELECT channel_id FROM channel_members WHERE user_id = ?)
           OR c.type = 'channel'
        ORDER BY c.created_at DESC
    """, (current_user["id"],))
    rows = cursor.fetchall()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "description": r["description"] or "",
            "type": r["type"],
            "owner_id": r["owner_id"],
            "avatar_color": r["avatar_color"],
            "members_count": r["members_count"],
            "created_at": str(r["created_at"])
        }
        for r in rows
    ]

@app.post("/api/channels/{channel_id}/join")
def join_channel(channel_id: str, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM channels WHERE id = ?", (channel_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Канал или группа не найдена")

    cursor.execute("""
        INSERT OR IGNORE INTO channel_members (channel_id, user_id, role)
        VALUES (?, ?, 'member')
    """, (channel_id, current_user["id"]))
    conn.commit()
    return {"status": "joined", "channel_id": channel_id}

@app.get("/api/channels/{channel_id}/members", response_model=List[UserResponse])
def get_channel_members(channel_id: str, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.nickname, u.avatar_color, u.bio
        FROM users u
        JOIN channel_members cm ON u.id = cm.user_id
        WHERE cm.channel_id = ?
        ORDER BY u.nickname ASC
    """, (channel_id,))
    return [dict(r) for r in cursor.fetchall()]

# Messages API
@app.get("/api/messages/{chat_id}", response_model=List[MessageResponse])
def get_chat_messages(chat_id: str, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT m.id, m.sender_id, u.nickname as sender_name, u.avatar_color as sender_avatar_color,
               m.receiver_id, m.chat_id, m.content,
               COALESCE(m.msg_type, 'text') as msg_type,
               COALESCE(m.media_url, '') as media_url,
               COALESCE(m.duration, 0) as duration,
               COALESCE(m.is_read, 0) as is_read,
               m.created_at
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.chat_id = ?
        ORDER BY m.id ASC
        LIMIT 150
    """, (chat_id,))
    rows = cursor.fetchall()
    return [dict(r) for r in rows]

@app.post("/api/messages", response_model=MessageResponse)
async def send_message(msg: MessageSend, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, chat_id, content, msg_type, media_url, duration, is_read)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    """, (
        current_user["id"],
        msg.receiver_id,
        msg.chat_id,
        msg.content or "",
        msg.msg_type or "text",
        msg.media_url or "",
        msg.duration or 0
    ))
    conn.commit()
    msg_id = cursor.lastrowid
    
    cursor.execute("""
        SELECT m.id, m.sender_id, u.nickname as sender_name, u.avatar_color as sender_avatar_color,
               m.receiver_id, m.chat_id, m.content,
               COALESCE(m.msg_type, 'text') as msg_type,
               COALESCE(m.media_url, '') as media_url,
               COALESCE(m.duration, 0) as duration,
               COALESCE(m.is_read, 0) as is_read,
               m.created_at
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.id = ?
    """, (msg_id,))
    res = dict(cursor.fetchone())

    # Broadcast via WebSocket
    await manager.broadcast_to_chat(msg.chat_id, res, current_user["id"], msg.receiver_id)
    return res

@app.post("/api/messages/read")
async def mark_messages_read(req: MarkReadRequest, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE messages
        SET is_read = 1
        WHERE chat_id = ? AND sender_id != ? AND is_read = 0
    """, (req.chat_id, current_user["id"]))
    conn.commit()

    await manager.broadcast_read(req.chat_id, current_user["id"])
    return {"status": "ok", "chat_id": req.chat_id}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        username = payload.get("sub")
        if not user_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(user_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg_json = json.loads(data)
                mtype = msg_json.get("type")
                if mtype == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif mtype == "typing":
                    chat_id = msg_json.get("chat_id")
                    user_name = msg_json.get("user_name", username)
                    receiver_id = msg_json.get("receiver_id")
                    if chat_id:
                        await manager.broadcast_typing(chat_id, user_id, user_name, receiver_id)
                elif mtype == "read_messages":
                    chat_id = msg_json.get("chat_id")
                    receiver_id = msg_json.get("receiver_id")
                    if chat_id:
                        conn = sqlite3.connect(DB_FILE)
                        cur = conn.cursor()
                        cur.execute("""
                            UPDATE messages SET is_read = 1
                            WHERE chat_id = ? AND sender_id != ? AND is_read = 0
                        """, (chat_id, user_id))
                        conn.commit()
                        conn.close()
                        await manager.broadcast_read(chat_id, user_id, receiver_id)
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)
