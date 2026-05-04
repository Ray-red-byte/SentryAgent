import json
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.databases.redis import get_redis
from app.databases.postgres import get_db
from app.utils.auth import get_current_user

router = APIRouter()

@router.get("/status/{session_id}", dependencies=[Depends(get_current_user)])
async def stream_status(session_id: str, redis_client=Depends(get_redis)):
    """
    SSE stream for real-time scan/audit progress + live LLM cost.

    Emits: {"stage": "...", "message": "...", "progress": 0-100, "cost_usd": 0.00000}
    Fires when stage changes OR cost_usd increases. Closes on 'complete'/'error'.
    """
    async def event_generator():
        max_wait_seconds = 300
        poll_interval    = 0.5
        elapsed          = 0.0
        last_stage       = None
        last_cost        = -1.0  # sentinel so first real cost (≥ 0) always emits

        while elapsed < max_wait_seconds:
            # ── Read Redis ──────────────────────────────────────────────────
            raw_status = raw_cost = None
            if redis_client:
                raw_status = redis_client.get(f"status:{session_id}")
                raw_cost   = redis_client.get(f"cost:{session_id}")

            stage_data: dict | None = None
            if raw_status:
                try:
                    stage_data = json.loads(raw_status)
                except Exception:
                    pass

            cost_usd = 0.0
            if raw_cost is not None:
                try:
                    cost_usd = float(raw_cost)
                except Exception:
                    pass

            # ── Decide whether to emit ──────────────────────────────────────
            if stage_data:
                stage          = stage_data.get("stage", "unknown")
                stage_changed  = stage != last_stage
                cost_increased = cost_usd > last_cost

                if stage_changed or cost_increased:
                    last_stage = stage

                    # Terminal event: re-read cost one final time before yielding.
                    # Gemini token counts arrive at the very end of the HTTP response,
                    # so incrbyfloat may have fired between this tick's initial Redis
                    # reads and right now. Capturing it here ensures the client gets
                    # the definitive bill before the pipe closes.
                    if stage in ("complete", "error") and redis_client:
                        try:
                            final_raw = redis_client.get(f"cost:{session_id}")
                            if final_raw is not None:
                                cost_usd = float(final_raw)
                        except Exception:
                            pass

                    last_cost = cost_usd
                    payload   = {**stage_data, "cost_usd": cost_usd}
                    yield f"data: {json.dumps(payload)}\n\n"

                    if stage in ("complete", "error"):
                        if redis_client:
                            redis_client.delete(f"status:{session_id}")
                        return

            elif cost_usd > last_cost:
                # Cost ticked up between stage transitions — emit a heartbeat
                # so the odometer stays responsive during long LLM calls.
                last_cost = cost_usd
                heartbeat = {
                    "stage":    last_stage or "processing",
                    "progress": 0,
                    "cost_usd": cost_usd,
                }
                yield f"data: {json.dumps(heartbeat)}\n\n"

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        final_cost = max(last_cost, 0.0)
        yield f'data: {{"stage":"error","message":"Status stream timed out","progress":0,"cost_usd":{final_cost}}}\n\n'

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

@router.get("/status/cost/{session_id}", dependencies=[Depends(get_current_user)])
async def get_session_cost(
    session_id: str,
    redis_client=Depends(get_redis),
    db: Session = Depends(get_db),
):
    """
    Return the accumulated LLM cost for a session.
    Checks Redis first (live counter), falls back to Postgres (persisted value).
    """
    live_cost = None
    if redis_client:
        raw = redis_client.get(f"cost:{session_id}")
        if raw is not None:
            live_cost = float(raw)

    db_cost = None
    try:
        from app.models.audit_log import AuditSession
        row = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if row:
            db_cost = row.total_cost
    except Exception:
        pass

    if live_cost is None and db_cost is None:
        raise HTTPException(status_code=404, detail="Session not found.")

    return {
        "session_id": session_id,
        "cost_usd": live_cost if live_cost is not None else db_cost,
        "source": "redis" if live_cost is not None else "postgres",
    }


@router.get("/health")
async def health_check():
    """Health check endpoint (unauthenticated, returns minimal info)."""
    return {
        "status": "active",
        "version": "0.4.0-langgraph",
        "workflow_engine": "LangGraph",
    }
