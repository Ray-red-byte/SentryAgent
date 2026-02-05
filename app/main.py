from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Initialize the API
app = FastAPI(
    title="Vibe Security Agent",
    description="AI-powered security auditor for FastAPI backends",
    version="0.1.0"
)

# Enable CORS (Allows your future frontend to talk to this API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, change this to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """
    Simple endpoint to check if the server is running.
    """
    return {
        "status": "active", 
        "component": "Security Agent Backend",
        "version": "0.1.0",
        "environment": "conda: security_agent"
    }

if __name__ == "__main__":
    import uvicorn
    # 'reload=True' makes the server restart automatically when you save code
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)