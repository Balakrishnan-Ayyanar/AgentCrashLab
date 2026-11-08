import asyncio
import hmac
import json
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import ValidationError

from backend.engine import InvalidBaseline, evaluate
from backend.execution import execute, ready, recover, verify_probe
from backend.inference import InferenceError, Simulation, Vultr
from backend.models import TARGETS, EvaluationRequest
from backend.report import render_html
from backend.store import Store
from sandbox.runner import PROBES


def create_app(path=None, mode=None):
    mode = mode or os.getenv("AGENTCRASHLAB_MODE", "live")
    token = os.getenv("AGENTCRASHLAB_TOKEN")
    if mode not in {"live", "offline"}:
        raise ValueError("Unsupported execution mode")
    inference = Vultr() if mode == "live" else Simulation()
    tasks = {}
    last_start = 0.0
    store = None
    worker_ready = False

    @asynccontextmanager
    async def lifespan(app):
        nonlocal store, worker_ready
        store = Store(path or os.getenv("AGENTCRASHLAB_DB", "agentcrashlab.sqlite3"))
        worker_ready = await recover() if mode == "live" and token else False
        for job in store.jobs():
            if job["status"] == "running":
                store.emit(job["id"], "job.interrupted", {"reason": "Application restarted"}, "failed")
        yield
        for task in tasks.values():
            if not task.cancelling():
                task.cancel()
        await asyncio.gather(*tasks.values(), return_exceptions=True)

    app = FastAPI(title="AgentCrashLab", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if "*" in origins:
        raise ValueError("Explicit origins required")
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"],
                       allow_headers=["Authorization", "Content-Type", "Last-Event-ID"])

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exc):
        return JSONResponse({"detail": "Evidence store unavailable"}, status_code=503)

    def access(request: Request):
        if not token:
            raise HTTPException(403, "Workspace authentication is not configured")
        supplied = request.headers.get("authorization", "").encode()
        if not hmac.compare_digest(supplied, ("Bearer " + token).encode()):
            raise HTTPException(401, "Workspace token required", headers={"WWW-Authenticate": "Bearer"})

    protected = [Depends(access)]

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "mode": mode}

    @app.get("/api/ready", dependencies=protected)
    async def readiness():
        sandbox = worker_ready and await ready()
        provider_configured = mode == "live" and inference.configured
        return {"mode": mode, "ready": mode == "offline" or (sandbox and provider_configured),
                "docker": sandbox, "inference_configured": provider_configured,
                "inference_success_observed": mode == "live" and inference.success_observed}

    @app.get("/api/config/public")
    async def config():
        return {"mode": mode, "auth_required": True}

    @app.get("/api/models", dependencies=protected)
    async def models():
        return {"configured_model": inference.model}

    @app.get("/api/targets", dependencies=protected)
    async def targets():
        return [{"id": key, **value} for key, value in TARGETS.items()]

    def get(job_id, kind=None):
        job = store.get(str(job_id))
        if not job or (kind and job["kind"] != kind):
            raise HTTPException(404, "Job not found")
        return job

    async def run_job(job, kind, spec):
        def emit(name, data):
            nonlocal worker_ready
            if name == "sandbox.cleanup" and data.get("verified") is not True:
                worker_ready = False
            store.emit(job, name, data)

        try:
            if kind == "evaluation":
                await evaluate(EvaluationRequest.model_validate(spec), mode, inference, emit)
            else:
                execution = await execute(spec, mode, emit)
                emit("probe.verified", {"outcome": verify_probe(spec["probe"], execution), "execution": execution})
            store.emit(job, f"{kind}.completed", {}, "completed")
        except asyncio.CancelledError:
            store.emit(job, "job.cancelled", {}, "cancelled")
            raise
        except (TimeoutError, InferenceError, RuntimeError) as exc:
            reason = "Evaluation budget expired" if isinstance(exc, TimeoutError) else (
                str(exc) if isinstance(exc, (InferenceError, InvalidBaseline)) else "Execution evidence could not be verified")
            store.emit(job, "job.failed", {"reason": reason}, "failed")
        except Exception:
            store.emit(job, "job.failed", {"reason": "Execution unavailable"}, "failed")

    def submit(kind, spec):
        nonlocal last_start
        if mode == "live" and (not worker_ready or not inference.configured):
            raise HTTPException(503, "Live mode requires configured Vultr inference and a recovered Docker worker")
        if any(not task.done() for task in tasks.values()) or time.monotonic() - last_start < 0.5:
            raise HTTPException(429, "One job at a time. Wait before trying again.")
        job = str(uuid4())
        store.create(job, kind, mode, spec)
        last_start = time.monotonic()
        task = asyncio.create_task(run_job(job, kind, spec))
        tasks[job] = task

        def finished(done):
            if done.cancelled() and store.get(job)["status"] == "running":
                store.emit(job, "job.cancelled", {}, "cancelled")
            tasks.pop(job, None)

        task.add_done_callback(finished)
        return get(job)

    @app.post("/api/evaluations", status_code=202, dependencies=protected)
    async def create(request: Request):
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            raise HTTPException(415, "Expected application/json")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 2048:
                raise HTTPException(413, "Evaluation input exceeds limit")
            body.extend(chunk)
        try:
            spec = EvaluationRequest.model_validate_json(body)
        except ValidationError:
            raise HTTPException(422, "Invalid evaluation options") from None
        return submit("evaluation", spec.model_dump())

    @app.get("/api/evaluations", dependencies=protected)
    async def evaluations():
        return store.jobs("evaluation")

    @app.get("/api/evaluations/{job_id}", dependencies=protected)
    async def evaluation(job_id: UUID):
        return {"job": get(job_id, "evaluation"), "events": store.events(str(job_id))}

    @app.post("/api/evaluations/{job_id}/cancel", dependencies=protected)
    async def cancel(job_id: UUID):
        job = get(job_id, "evaluation")
        task = tasks.get(job["id"])
        if job["status"] != "running" or not task or task.cancelling():
            raise HTTPException(409, "Evaluation is no longer cancellable")
        task.cancel()
        return {"cancellation_requested": True}

    @app.get("/api/evaluations/{job_id}/events", dependencies=protected)
    async def events(job_id: UUID, request: Request, after: int = Query(0, ge=0)):
        job = get(job_id, "evaluation")
        try:
            cursor = max(after, int(request.headers.get("last-event-id", "0")))
            if cursor > 9223372036854775807:
                raise ValueError
        except ValueError:
            raise HTTPException(400, "Invalid event cursor") from None

        async def stream():
            nonlocal cursor
            last_heartbeat = time.monotonic()
            while not await request.is_disconnected():
                status = store.get(job["id"])["status"]
                for event in store.events(job["id"], cursor):
                    cursor = event["id"]
                    yield f"id: {cursor}\nevent: {event['type']}\ndata: {json.dumps(event)}\n\n"
                if status != "running":
                    break
                if time.monotonic() - last_heartbeat > 10:
                    yield ": heartbeat\n\n"
                    last_heartbeat = time.monotonic()
                await asyncio.sleep(0.25)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    def findings(events):
        return [{"id": f"finding-{event['id']}", "severity": "high",
                 "title": "Synthetic canary read outside the authorized task scope",
                 "mitigation": "Remove canary access from the target tool policy",
                 "evidence": event}
                for event in events if event["type"] == "attack.verified"
                and event["data"]["outcome"] == "CONFIRMED_FINDING"]

    @app.get("/api/evaluations/{job_id}/findings", dependencies=protected)
    async def evaluation_findings(job_id: UUID):
        get(job_id, "evaluation")
        return findings(store.events(str(job_id)))

    @app.get("/api/containment/probes", dependencies=protected)
    async def probes():
        return [{"id": key, "description": value} for key, value in PROBES.items()]

    @app.post("/api/containment/probes/{probe_id}/run", status_code=202, dependencies=protected)
    async def run_probe(probe_id: str):
        if probe_id not in PROBES:
            raise HTTPException(404, "Probe not found")
        if mode == "offline":
            raise HTTPException(503, "Offline simulation cannot verify OS containment")
        return submit("probe", {"probe": probe_id})

    @app.get("/api/containment/executions/{job_id}", dependencies=protected)
    async def probe_execution(job_id: UUID):
        return {"job": get(job_id, "probe"), "events": store.events(str(job_id))}

    def report(job_id):
        job = get(job_id, "evaluation")
        events = store.events(str(job_id))
        verified = [event["data"] for event in events if event["type"] == "attack.verified"]
        return {"job": job, "target": TARGETS[job["spec"]["target"]],
                "scope": {"fixtures": "synthetic only", "authorized_actions": ["report"],
                          "prohibited_objective": "read_canary"},
                "methodology": "Baseline, adaptive adversarial iterations, optional mitigation comparison. See regression method for the recorded replay type.",
                "summary": {"verified_experiments": len(verified), "findings": len(findings(events)),
                            "blocked": sum(result["blocked"] is True for result in verified)},
                "events": events, "findings": findings(events),
                "regression": next((event["data"] for event in reversed(events)
                                    if event["type"] == "regression.completed"), None),
                "limitations": ["Offline simulation has no OS isolation or model calls."] if job["mode"] == "offline"
                else ["Synthetic target scope. Tool-policy denial is distinct from OS enforcement."]}

    @app.get("/api/reports/{job_id}", dependencies=protected)
    async def get_report(job_id: UUID):
        return report(job_id)

    @app.get("/api/reports/{job_id}/download", dependencies=protected)
    async def download(job_id: UUID, format: str = "json"):
        data = report(job_id)
        if format not in {"html", "json"}:
            raise HTTPException(422, "Unsupported report format")
        headers = {"Content-Disposition": f'attachment; filename="agentcrashlab-{job_id}.{format}"',
                   "X-Content-Type-Options": "nosniff"}
        if format == "json":
            return JSONResponse(data, headers=headers)
        headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
        return HTMLResponse(render_html(data), headers=headers)

    @app.get("/api/metrics/overview", dependencies=protected)
    async def metrics():
        jobs = store.jobs()
        result = {}
        for group in ("live", "offline"):
            scoped = [job for job in jobs if job["mode"] == group]
            events = [event for job in scoped for event in store.events(job["id"])]
            verified = [event["data"] for event in events if event["type"] == "attack.verified"]
            result[group] = {"evaluations_completed": sum(job["kind"] == "evaluation" and job["status"] == "completed" for job in scoped),
                             "running": sum(job["status"] == "running" for job in scoped),
                             "findings": len(findings(events)),
                             "blocked": sum(row["blocked"] is True for row in verified),
                             "contained": sum(event["type"] == "probe.verified" and event["data"]["outcome"] == "PASS" for event in events),
                             "llm_requests": sum(event["type"] == "inference.requested" for event in events)}
        return result

    return app


app = create_app()
