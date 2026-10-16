import os
import json
import sqlite3
import jwt
import datetime
from typing import Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import passlib.hash as hasher

SECRET_KEY = os.getenv("SECRET_KEY", "grafiton-super-secret-key-render-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

DB_FILE = os.getenv("DB_FILE", "grafiton.db")

app = FastAPI(title="Графитон API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    # Check if bio column exists in case upgrading from v1.0
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if "bio" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER, -- NULL if public/channel
        chat_id TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id)
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
    content: str

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    sender_name: str
    receiver_id: Optional[int]
    chat_id: str
    content: str
    created_at: str

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
        else:
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

manager = ConnectionManager()

# Routes
@app.get("/")
def read_root():
    return {
        "app": "Графитон (Grafiton) Messenger API",
        "status": "online",
        "version": "1.1.0"
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

@app.get("/api/messages/{chat_id}", response_model=List[MessageResponse])
def get_chat_messages(chat_id: str, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT m.id, m.sender_id, u.nickname as sender_name, m.receiver_id, m.chat_id, m.content, m.created_at
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.chat_id = ?
        ORDER BY m.id ASC
        LIMIT 100
    """, (chat_id,))
    rows = cursor.fetchall()
    return [dict(r) for r in rows]

@app.post("/api/messages", response_model=MessageResponse)
async def send_message(msg: MessageSend, current_user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, chat_id, content)
        VALUES (?, ?, ?, ?)
    """, (current_user["id"], msg.receiver_id, msg.chat_id, msg.content))
    conn.commit()
    msg_id = cursor.lastrowid
    
    cursor.execute("""
        SELECT m.id, m.sender_id, u.nickname as sender_name, m.receiver_id, m.chat_id, m.content, m.created_at
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.id = ?
    """, (msg_id,))
    res = dict(cursor.fetchone())

    # Broadcast via WebSocket
    await manager.broadcast_to_chat(msg.chat_id, res, current_user["id"], msg.receiver_id)
    return res

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
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
                if msg_json.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)
