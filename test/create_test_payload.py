import os
import zipfile

# Define the project structure and content
project_files = {
    # --- CONFIGURATION (Vulnerable: Hardcoded Secrets) ---
    "app/core/config.py": """
from pydantic import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "MegaCorp API"
    # VULNERABILITY: Hardcoded Secret
    SECRET_KEY: str = "django-insecure-j$@*!&(@#)(@!)*#(!@)*#(!@)"
    # VULNERABILITY: Hardcoded Database Password
    DATABASE_URL: str = "postgresql://admin:Password123@localhost:5432/db"

settings = Settings()
""",

    # --- DATABASE LAYER (Vulnerable: SQL Injection) ---
    "app/db/repository.py": """
import sqlite3

def get_user_by_email(email: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABILITY: SQL Injection
    # User input is concatenated directly into the query
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(keyword: str):
    conn = sqlite3.connect("products.db")
    # VULNERABILITY: SQL Injection
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    conn.execute(query)
""",

    # --- AUTHENTICATION (Vulnerable: Weak Hashing) ---
    "app/api/auth.py": """
from fastapi import APIRouter, Depends
import hashlib

router = APIRouter()

@router.post("/login")
def login(password: str):
    # VULNERABILITY: Weak Hashing Algorithm (MD5)
    # MD5 is broken and should not be used for passwords
    hashed_pw = hashlib.md5(password.encode()).hexdigest()
    
    if hashed_pw == "5f4dcc3b5aa765d61d8327deb882cf99": # 'password'
        return {"token": "admin-token"}
    return {"error": "Invalid credentials"}
""",

    # --- USER CONTROLLER (Vulnerable: Command Injection) ---
    "app/api/users.py": """
from fastapi import APIRouter
import os

router = APIRouter()

@router.post("/backup_user_data")
def backup_user(user_id: str):
    # VULNERABILITY: Command Injection
    # If user_id is "; rm -rf /", this executes malicious commands
    os.system(f"tar -czf backups/{user_id}.tar.gz /data/{user_id}")
    return {"status": "Backup started"}
""",

    # --- FILE SERVER (Vulnerable: Path Traversal) ---
    "app/api/files.py": """
from fastapi import APIRouter
from fastapi.responses import FileResponse
import os

router = APIRouter()

@router.get("/download")
def download_file(filename: str):
    # VULNERABILITY: Path Traversal
    # Attackers can send filename="../../etc/passwd" to read system files
    file_path = os.path.join("uploads", filename)
    return FileResponse(file_path)
""",

    # --- MAIN ENTRY POINT ---
    "app/main.py": """
from fastapi import FastAPI
from app.api import auth, users, files
from app.core.config import settings

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(auth.router, prefix="/auth")
app.include_router(users.router, prefix="/users")
app.include_router(files.router, prefix="/files")

@app.get("/")
def health():
    return {"status": "online", "version": "1.0.0"}
"""
}

# Create the Zip File
zip_filename = "large_scale_test.zip"
with zipfile.ZipFile(zip_filename, 'w') as zipf:
    for path, content in project_files.items():
        zipf.writestr(path, content.strip())

print(f"✅ Generated '{zip_filename}'")
print(f"📂 Includes modules: Auth, DB, Files, Users, Config.")
print(f"🚀 Drag and drop this file into Sentry Agent to test scaling.")