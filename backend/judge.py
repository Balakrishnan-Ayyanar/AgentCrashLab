"""Public read-only ASGI service. No inference, Docker, token, or evidence DB access."""
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from backend.judge_snapshot import Snapshot

MAX_SNAPSHOT_BYTES = 65536


def load(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SNAPSHOT_BYTES:
            raise ValueError("Invalid snapshot file")
        content = stream.read(MAX_SNAPSHOT_BYTES + 1)
        if len(content) > MAX_SNAPSHOT_BYTES:
            raise ValueError("Oversized snapshot")
        return Snapshot.model_validate_json(content)


def create_app(snapshot_path=None):
    path = Path(snapshot_path or os.getenv("AGENTCRASHLAB_JUDGE_SNAPSHOT", "deploy/judge/snapshot.json"))
    app = FastAPI(title="AgentCrashLab public evidence", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def response_policy(request, call_next):
        if request.method != "GET":
            return JSONResponse({"detail": "Read-only evidence service"}, status_code=405,
                                headers={"Allow": "GET", "Cache-Control": "no-store"})
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/api/judge/health")
    async def health():
        return {"service": "public_evidence", "execution_enabled": False}

    def document():
        try:
            snapshot = load(path)
        except (OSError, ValueError, ValidationError):
            raise HTTPException(503, "Reviewed evidence snapshot unavailable") from None
        age = (datetime.now(timezone.utc) - snapshot.generated_at).total_seconds()
        return {"snapshot_status": "stale" if age > 48 * 3600 else "current",
                "execution_enabled": False, "snapshot": snapshot.model_dump(mode="json")}

    @app.get("/api/judge")
    async def evidence():
        return document()

    @app.get("/api/judge/download")
    async def download():
        return JSONResponse(document(), headers={"Content-Disposition": 'attachment; filename="agentcrashlab-public-evidence.json"'})

    return app


app = create_app()
