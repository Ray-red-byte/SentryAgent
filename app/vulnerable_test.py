import os
import sqlite3
from fastapi import FastAPI, HTTPException, Depends
from typing import Dict, Any

app = FastAPI()

async def get_current_user():
    return {"username": "authenticated_user", "id": "123"} 

LOG_BASE_DIR = "logs" 
os.makedirs(LOG_BASE_DIR, exist_ok=True)

@app.get("/delete_logs")
def delete_logs(filename: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")

    log_file_path = os.path.join(LOG_BASE_DIR, filename)
    abs_log_file_path = os.path.abspath(log_file_path)
    abs_base_dir = os.path.abspath(LOG_BASE_DIR)

    if not abs_log_file_path.startswith(abs_base_dir):
        raise HTTPException(status_code=400, detail="Access denied.")

    if os.path.isfile(abs_log_file_path):
        os.remove(abs_log_file_path)
    else:
        raise HTTPException(status_code=400, detail="File not found.")

    return {"status": "deleted", "filename": filename}

@app.get("/get_user")
def get_user(user_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    try:
        user_id_int = int(user_id)
        conn = sqlite3.connect("db.sqlite")
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE id = ?"
        cursor.execute(query, (user_id_int,))
        user_data = cursor.fetchone()
        conn.close()
        return {"user_data": user_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Server error")