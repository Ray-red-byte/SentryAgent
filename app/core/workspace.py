import os
import re
import shutil
import uuid
import zipfile
from pathlib import Path
from fastapi import UploadFile, HTTPException

WORKSPACE_DIR = Path(os.getenv("WORKSPACE_DIR", "temp_workspaces"))

# Max upload size: 50 MB
MAX_ZIP_SIZE_BYTES = 50 * 1024 * 1024

# Valid UUID pattern to prevent session_id path injection
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _validate_session_id(session_id: str) -> None:
    """Raise 400 if session_id is not a canonical UUID v4 string."""
    if not _UUID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format.")


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

        Security controls:
        - Enforces maximum file size (50 MB).
        - Prevents Zip Slip: all extracted members must resolve inside the session dir.
        """
        _validate_session_id(session_id)
        session_path = WORKSPACE_DIR / session_id
        zip_path = session_path / "codebase.zip"

        try:
            # 1. Save the ZIP file with a size cap
            bytes_written = 0
            with open(zip_path, "wb") as buffer:
                chunk_size = 65536  # 64 KB chunks
                while True:
                    chunk = await file.read(chunk_size)
                    if not chunk:
                        break
                    bytes_written += len(chunk)
                    if bytes_written > MAX_ZIP_SIZE_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"Upload exceeds the {MAX_ZIP_SIZE_BYTES // (1024*1024)} MB limit.",
                        )
                    buffer.write(chunk)

            # 2. Open the ZIP and validate every member path (Zip Slip prevention)
            resolved_session = session_path.resolve()
            _SKIP_PREFIXES = ("__MACOSX/", "__MACOSX\\")
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                members_to_extract = []
                for member in zip_ref.infolist():
                    # Drop macOS metadata entries before they touch the filesystem
                    if any(member.filename.startswith(p) for p in _SKIP_PREFIXES):
                        continue
                    member_path = (session_path / member.filename).resolve()
                    if not str(member_path).startswith(str(resolved_session)):
                        raise HTTPException(
                            status_code=400,
                            detail=f"Unsafe path in ZIP: {member.filename}",
                        )
                    members_to_extract.append(member)
                # Extract only validated, non-metadata members
                for member in members_to_extract:
                    zip_ref.extract(member, session_path)

            # 3. Clean up (remove the zip file to save space)
            os.remove(zip_path)

            return {
                "status": "success",
                "files": [
                    f.name for f in session_path.glob("**/*") if f.is_file()
                ],
            }

        except HTTPException:
            shutil.rmtree(session_path, ignore_errors=True)
            raise
        except Exception:
            shutil.rmtree(session_path, ignore_errors=True)
            raise HTTPException(
                status_code=500, detail="Failed to process upload."
            )

    def get_workspace_path(self, session_id: str) -> Path:
        """Returns the valid path for a given session ID."""
        _validate_session_id(session_id)
        path = WORKSPACE_DIR / session_id
        if not path.exists():
            raise HTTPException(status_code=404, detail="Session expired or not found.")
        return path

    def cleanup_workspace(self, session_id: str):
        """Deletes the session data."""
        _validate_session_id(session_id)
        path = WORKSPACE_DIR / session_id
        if path.exists():
            shutil.rmtree(path)