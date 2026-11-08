# Deployment and operations

## Current verified deployment

The existing Vultr host runs Ubuntu 26.10 / Linux amd64. The backend and fixed worker ran there; all agent inference used Vultr Serverless. The public HTTP judge URL is in the README. HTTPS is not enabled. Packaging and offline tests do not change a host.

Installed app runtime during the reviewed deployment: isolated Python 3.12.16, uv 0.13.7 and Caddy 2.11.9; pre-existing Node 24.19 / npm 11.16 and Docker 29.9.3. Host Python/Docker were not replaced or restarted. This candidate includes dependency, packaging, template and sanitized runner changes; it has not been installed on that host. Public snapshot hashes bind the historical executed release, not this later candidate.

## Layout and service identities

Use app paths `/opt/agentcrashlab`, `/etc/agentcrashlab` and `/var/lib/agentcrashlab`; do not overlay an unrelated project. Inspect destination files/listeners before installation. Preserve SSH settings and unrelated services. Use separate nologin identities `agentcrashlab`, `agentcrashlab-judge`, `agentcrashlab-web`. Only the private operator may have Docker access. Judge and web have no provider credential, operator token or private DB.

The templates are examples, not an automatic installer. Create the service identities and set file permissions before starting services. Install isolated Python 3.12 under app paths without replacing host Python. Use official sources and verify published archive checksums before running binaries: [uv](https://github.com/astral-sh/uv/releases), [Python builds](https://github.com/astral-sh/python-build-standalone/releases), [Caddy](https://github.com/caddyserver/caddy/releases), [Node](https://nodejs.org/en/download), [Docker](https://docs.docker.com/engine/install/). Pin the selected versions and verify their published checksums.

```sh
# After installing the isolated runtime and creating the app paths:
/opt/agentcrashlab/.venv/bin/python -m pip install -r /opt/agentcrashlab/deploy/requirements-runtime.txt
cd /opt/agentcrashlab/frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run build
```

Keep source/dist root-owned and readable by the judge/web services. Private environment directory: root:agentcrashlab 0750; environment file: root:agentcrashlab 0640. Never commit a populated copy. Operator state 0700, service UMask 0077 / StateDirectoryMode 0700. Public snapshot directory root:agentcrashlab-judge 0750; selected reviewed snapshot root:agentcrashlab-judge 0640. The judge has no runtime write/import route. Deployment file ownership must be checked against actual service identities.

The included judge unit uses loopback 18080. The operator unit uses loopback 18081 and no public execution. Leave its token unset for locked deployment; configure operator authentication separately when private execution is needed. A locked service denies API execution. Keep provider keys outside the worker, command arguments, browser, shell history and logs. Keep its secret file accessible only to the private operator service.

`deploy/Caddyfile` is explicitly HTTP-only with auto_https off/admin off. Supply the hostname via AGENTCRASHLAB_DOMAIN in an app-specific proxy service, running as the separate web identity with only bind-service capability. It allows only the exact judge GET routes and static UI, denies private API paths/mutations and never proxies 18081. The supplied web service template uses localhost as an example hostname. Configure routing, firewall and TLS separately for your environment. Verify HTTPS normally if enabled; never bypass certificate validation.

## Fixed worker build (not run by offline checks)

An operator can resolve an official Linux amd64 Python 3.12-slim digest, then use that immutable digest:

```sh
docker build --network=none --build-arg RUNNER_BASE=python@sha256:REVIEWED_DIGEST -t agentcrashlab-fixed:reviewed sandbox
# Inspect and pin the resulting immutable image ID before any execution.
```

The placeholder is intentionally non-executable until a real digest is reviewed. SANDBOX_IMAGE must use the actual resulting image ID for proof. Do not restart/upgrade the Docker daemon to install this app. `scripts.capture_evidence` runs fixed real Docker probes only when explicitly invoked by an operator; it is not an offline test. It must use a new evidence output and cannot establish a live-model finding.

## Acceptance and rollback

Verify source/dependency/image hashes, actual Linux architecture, loopback listeners, judge permissions and provider absence. Check public browsing/download; denied private/mutation/encoded variants; external 18080/18081 unreachable; missing/invalid 503; stale label without timestamp refresh. Run independent cleanup checks after actual probes. Never infer provider readiness from configured mode. Never turn an uncertain inference request into a retry.

For operator offline health/auth checks use `deploy/check_operator.py` against an intentionally offline loopback service; it does not submit evaluation. No automated host installer, firewall action or certificate enrollment is included. The paid model experiment is a separate explicit opt-in CLI. Roll back only AgentCrashLab units/paths; preserve evidence and unrelated workloads. Do not delete a VM or shared Docker data as cleanup.
