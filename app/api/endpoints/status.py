import json
import asyncio
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from app.databases.redis import get_redis
from app.utils.auth import get_current_user

router = APIRouter()

@router.get("/status/{session_id}", dependencies=[Depends(get_current_user)])
async def stream_status(session_id: str, redis_client=Depends(get_redis)):
    """
    Server-Sent Events stream that broadcasts real-time scan/audit progress.
    The frontend connects here and receives JSON events as the LangGraph
    workflow progresses through its nodes.

    Emits events with shape: {"stage": "...", "message": "...", "progress": 0-100}
    Closes automatically when the 'complete' or 'error' stage is received.
    """
    async def event_generator():
        max_wait_seconds = 300  # 5 minute timeout
        poll_interval = 0.5
        elapsed = 0.0
        last_stage = None

        while elapsed < max_wait_seconds:
            stage_data = None

            if redis_client:
                raw = redis_client.get(f"status:{session_id}")
                if raw:
                    try:
                        stage_data = json.loads(raw)
                    except Exception:
                        pass

            if stage_data:
                stage = stage_data.get("stage", "unknown")

                # Only emit when stage changes
                if stage != last_stage:
                    last_stage = stage
                    yield f"data: {json.dumps(stage_data)}\n\n"

                    if stage in ("complete", "error"):
                        # Cleanup and close
                        if redis_client:
                            redis_client.delete(f"status:{session_id}")
                        return

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        yield f'data: {{"stage": "error", "message": "Status stream timed out", "progress": 0}}\n\n'

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )

@router.get("/health")
async def health_check():
    """Health check endpoint (unauthenticated, returns minimal info)."""
    return {
        "status": "active",
        "version": "0.4.0-langgraph",
        "workflow_engine": "LangGraph",
    }
