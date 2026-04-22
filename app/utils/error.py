import logging
from fastapi import HTTPException

logger = logging.getLogger(__name__)

def safe_http_error(status_code: int, public_msg: str, exc: Exception = None):
    """
    Raise an HTTPException with a safe, user-facing message.
    Logs the real exception server-side so details never leak to clients.
    """
    if exc is not None:
        logger.exception("Internal error: %s", exc)
    raise HTTPException(status_code=status_code, detail=public_msg)
