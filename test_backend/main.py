from fastapi import FastAPI, Request
from pydantic import BaseModel
import sqlite3
import subprocess
import pickle
import jwt

app = FastAPI()

class UserLogin(BaseModel):
    username: str
    password: str

# 1. SQL Injection vulnerability
@app.post("/login")
def login(user: UserLogin):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: string concatenation directly into SQL query
    query = f"SELECT * FROM users WHERE username='{user.username}' AND password='{user.password}'"
    cursor.execute(query)
    record = cursor.fetchone()
    conn.close()
    
    if record:
        # 2. Hardcoded / Weak JWT Secret
        token = jwt.encode({"user": user.username}, "secret", algorithm="HS256")
        return {"token": token}
    return {"error": "Invalid credentials"}

# 3. Command Injection vulnerability
@app.get("/ping")
def ping_ip(ip: str):
    # Vulnerable: unsanitized input passed directly to OS shell
    result = subprocess.run(f"ping -c 1 {ip}", shell=True, capture_output=True, text=True)
    return {"output": result.stdout}

# 4. Insecure Deserialization
@app.post("/upload_profile")
async def upload_profile(request: Request):
    data = await request.body()
    # Vulnerable: Pickling untrusted data can lead to arbitrary code execution
    profile = pickle.loads(data)
    return {"status": "Profile updated", "profile": str(profile)}

# 5. Template Injection / XSS in HTML Response
@app.get("/greet")
def greet(name: str):
    from fastapi.responses import HTMLResponse
    # Vulnerable: rendering unsanitized name directly as HTML
    html_content = f"<html><body><h1>Hello, {name}!</h1></body></html>"
    return HTMLResponse(content=html_content)
