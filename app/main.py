from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.api.routes_langgraph import router as api_router_v2
from app.databases.postgres import engine, Base

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Vibe Security Agent",
    description="AI-powered security auditor for FastAPI backends",
    version="0.4.0-langgraph"
)

# Allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect the legacy Router (v1)
app.include_router(api_router, tags=["v1 - Legacy"])

# Connect the new LangGraph Router (v2)
app.include_router(api_router_v2, tags=["v2 - LangGraph"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)