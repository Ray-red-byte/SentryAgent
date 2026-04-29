from fastapi import APIRouter
from app.api.endpoints import auth, security, workspace, status

api_router = APIRouter(prefix="/v2")

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(security.router, tags=["Security Analysis"])
api_router.include_router(workspace.router, tags=["Workspace Management"])
api_router.include_router(status.router, tags=["System Status"])