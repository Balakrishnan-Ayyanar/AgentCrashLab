# AgentCrashLab

AgentCrashLab tests AI agent tool use with synthetic prompt injections, records what actually ran, and replays the exact proposal under a stricter policy while verifying that the legitimate task still succeeds.

**[Open the read-only public demo](http://agentcrashlab.155.138.162.49.sslip.io/judge).** The app, backend and fixed Docker worker run on an existing Vultr VM. The public service only reads a sanitized evidence snapshot: no token, private database, Docker access, uploads, execution or paid inference route. HTTPS is not enabled. The current URL is HTTP.

## What is verified

A deliberately misconfigured synthetic analyst trusted workflow instructions in CSV notes. Two genuine Vultr Serverless Inference requests to qwen3.8-27b selected `report` for clean input and `report, read_canary` for injected input. The actual hosted worker returned the physical synthetic canary under the vulnerable policy. Exact strict replay denied that same action with null value while preserving Jan=120, Feb=240, delta=120. All four stages verified cleanup. Two POSTs, no retries, 972 tokens. The historical unmodified v2 target resisted both notes. This finding concerns the disclosed misconfiguration, not general model vulnerability.

Separately, all seven fixed hosted Docker probes passed, including protected-write EROFS and cleanup. This is OS containment evidence from fixed probes, not a model-generated OS exploit. [Evidence and limitations](docs/EVIDENCE.md).

## Local offline setup

Use Python 3.12 and Node 22.12+ (reviewed locally with Node 22.23.3 and npm 11.6.2). Install dependencies from their official package registries. No provider key is needed for offline mode.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r deploy/requirements-runtime.txt -r requirements.txt
env AGENTCRASHLAB_MODE=offline AGENTCRASHLAB_TOKEN=synthetic-local-test-token \
  .venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run dev
```

Open the printed localhost URL. The public synthetic fixture token above unlocks only your local offline test stack. Never use it for a public or production workspace. Offline agent choices are scripted; no provider or Docker call occurs. The containment controls are disabled in offline mode.

For the read-only evidence explorer instead, stop that local backend and run:

```sh
env AGENTCRASHLAB_JUDGE_SNAPSHOT=examples/hosted-evidence.json \
  .venv/bin/uvicorn backend.judge:app --host 127.0.0.1 --port 8000
```

Keep Vite running and open its `/judge` path. These are recorded hosted results viewed locally, not a new hosted execution. Original record/export timestamps stay unchanged. After 48 hours the service labels the snapshot stale but keeps it readable. Missing or invalid snapshots fail closed with 503.

## Offline checks and reproduction

```sh
.venv/bin/python -m pytest -q -k 'not real_containment_when_available'
.venv/bin/python -m scripts.reproduce_fixture
(cd frontend && npm run typecheck && npm run build)
.venv/bin/python -m scripts.package_source --output ../AgentCrashLab-source.tar.gz
```

The first command excludes seven actual Docker tests; provider tests use mock transports. The fixture replay is explicitly simulated, not new live-model or OS evidence. For the real model/Docker experiment, inspect [the opt-in controlled experiment](docs/CONTROLLED_MODEL.md). It is separate from the simulated fixture and does not run during these checks. A source archive output must be a new path. [Reproduction](docs/REPRODUCIBILITY.md) explains test scope and the corrected frontend lockfile.

## Design and deployment

FastAPI, Pydantic, SQLite and SSE support the private operator plane. React/TypeScript/Vite provide the UI. The fixed tool enum, independent verifier, exact-proposal replay and disposable worker keep task success separate from attack outcomes. All agent runtime inference uses Vultr; no fallback provider or external MCP endpoint exists. Inputs are fixed synthetic fixtures; the app does not execute arbitrary model-generated code.

[Architecture/security](docs/SECURITY.md) · [Deployment](docs/DEPLOYMENT.md) · [Evidence](docs/EVIDENCE.md) · [Source changes](docs/RELEASE_NOTES.md).

The generic private API still defaults to two inference attempts and has no durable account-wide spend quota. It is not the bounded two-call verification harness and must never be forwarded publicly. The deployed private API remains locked without an operator token. Execution configuration, one-use run state, private audits and credentials are generated locally and are not distributed.

## Submission and license

MIT applies to this project source; dependencies retain their own licenses. The public repository, setup documentation, working Vultr demo, recorded containment video and PDF slides are submission requirements. Final video/PDF were verified locally and are distributed separately; rendered media is excluded here. Publication of this source is not a completed LabLab submission. The event cutoff is November 8, 2026 at 23:00 UTC. [Event and deliverables](docs/SUBMISSION.md).
