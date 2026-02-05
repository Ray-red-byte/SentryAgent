import os
import shutil
import uuid
import zipfile
from pathlib import Path
from fastapi import UploadFile, HTTPException

WORKSPACE_DIR = Path("temp_workspaces")

class WorkspaceManager:
    def __init__(self):
        # Ensure the main workspace folder exists
        WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    def create_workspace(self) -> str:
        """Generates a unique session ID and creates a folder for it."""
        session_id = str(uuid.uuid4())
        session_path = WORKSPACE_DIR / session_id
        session_path.mkdir()
        return session_id

    async def save_and_extract_code(self, session_id: str, file: UploadFile):
        """
        Saves the uploaded ZIP file to the session folder and extracts it.
        """
        session_path = WORKSPACE_DIR / session_id
        zip_path = session_path / "codebase.zip"

        try:
            # 1. Save the ZIP file
            with open(zip_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # 2. Extract the ZIP file
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(session_path)

            # 3. Clean up (remove the zip file to save space)
            os.remove(zip_path)

            return {"status": "success", "files": [f.name for f in session_path.glob("**/*") if f.is_file()]}

        except Exception as e:
            # Cleanup on failure
            shutil.rmtree(session_path, ignore_errors=True)
            raise HTTPException(status_code=500, detail=f"Failed to process upload: {str(e)}")

    def get_workspace_path(self, session_id: str) -> Path:
        """Returns the valid path for a given session ID."""
        path = WORKSPACE_DIR / session_id
        if not path.exists():
            raise HTTPException(status_code=404, detail="Session expired or not found.")
        return path

    def cleanup_workspace(self, session_id: str):
        """Deletes the session data."""
        path = WORKSPACE_DIR / session_id
        if path.exists():
            shutil.rmtree(path)