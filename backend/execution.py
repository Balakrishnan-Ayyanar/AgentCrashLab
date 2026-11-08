import asyncio
import json
import os
import re
import tempfile
import time
from contextlib import nullcontext
from pathlib import Path
from uuid import uuid4

from sandbox.runner import FIXTURE_VERSION, dispatch

LIMITS = {"memory_mb": 64, "cpus": 0.5, "pids": 16, "seconds": 6, "output_bytes": 16384}
LABEL = "org.agentcrashlab.worker=v1"


class CommandError(Exception):
    pass


async def docker(*args, payload=b"", timeout=5):
    socket_path = os.getenv("AGENTCRASHLAB_DOCKER_SOCKET", "/var/run/docker.sock")
    if not socket_path.startswith("/") or any(char in socket_path for char in "\r\n"):
        raise CommandError("An absolute local Docker socket path is required")
    # Explicit local Unix transport, without forwarding host inference credentials.
    env = {k: os.environ[k] for k in ("PATH", "HOME", "SYSTEMROOT") if k in os.environ}
    proc = await asyncio.create_subprocess_exec(
        "docker", "--host", "unix://" + socket_path, *args, env=env, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, limit=LIMITS["output_bytes"],
    )
    try:
        async with asyncio.timeout(timeout):
            proc.stdin.write(payload)
            await proc.stdin.drain()
            proc.stdin.close()
            chunks = bytearray()
            while chunk := await proc.stdout.read(4096):
                chunks.extend(chunk)
                if len(chunks) > LIMITS["output_bytes"]:
                    raise CommandError("Docker output exceeded limit")
            return await proc.wait(), bytes(chunks)
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            while await proc.stdout.read(4096):
                pass
            await proc.wait()


async def ready():
    try:
        code, _ = await docker("version", "--format", "{{.Server.Version}}")
        return code == 0
    except (OSError, TimeoutError, CommandError):
        return False


async def recover():
    try:
        code, output = await docker("ps", "-aq", "--filter", f"label={LABEL}")
        if code:
            return False
        containers = output.decode().split()
        if any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in containers):
            return False
        for item in containers:
            code, _ = await docker("rm", "-f", item)
            if code:
                return False
        code, output = await docker("ps", "-aq", "--filter", f"label={LABEL}")
        return code == 0 and not output.strip()
    except (OSError, TimeoutError, CommandError, UnicodeError):
        return False


async def execute(job, mode, emit):
    start = time.time()
    execution_id = str(uuid4())
    evidence = {"id": execution_id, "mode": mode, "started_at": start, "fixture_version": FIXTURE_VERSION,
                "cleanup": None, "exit_code": None, "result": None, "sandbox_enforced": None}
    if mode == "offline":
        if "probe" not in job:
            evidence.update(result=dispatch(job), exit_code=0)
        return {**evidence, "finished_at": time.time(), "duration_seconds": time.time() - start}

    name = "agentcrashlab-" + execution_id
    image = os.getenv("SANDBOX_IMAGE", "agentcrashlab-runner:local")
    runtime = os.getenv("SANDBOX_RUNTIME", "runc")
    if runtime not in {"runc", "runsc"}:
        raise CommandError("Unsupported runtime")
    evidence.update(limits=LIMITS, runtime=runtime)
    cleanup_required = False
    try:
        code, image_info = await docker("image", "inspect", "--format", "{{.Os}} {{.Id}}", "--", image)
        match = re.fullmatch(r"linux (sha256:[0-9a-f]{64})", image_info.decode().strip())
        if code or not match:
            raise CommandError("Local Linux sandbox image unavailable")
        image_id = match[1]
        evidence.update(image_digest=image_id, image_os="linux")
        cleanup_required = True
        code, container_id = await docker(
            "create", "--pull=never", "--name", name, "--label", LABEL, "--runtime", runtime,
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
            "--network=none", "--ipc=private", "--user=65532:65532", "--log-driver=none",
            "--pids-limit=16", "--memory=64m", "--memory-swap=64m", "--cpus=0.5",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777", "-i", image_id,
        )
        if code:
            raise CommandError("Container creation failed")
        evidence["container_id"] = container_id.decode().strip()
        inspect_code, config = await docker(
            "inspect", "--format", '{{json .Mounts}} {{json .Config.User}} {{json .HostConfig.ReadonlyRootfs}}',
            name,
        )
        if inspect_code:
            raise CommandError("Container configuration unavailable")
        mounts, user, readonly = [json.loads(item) for item in config.split(maxsplit=2)]
        if (user != "65532:65532" or readonly is not True
                or any(mount.get("Type") != "tmpfs" or mount.get("Destination") != "/tmp"
                       for mount in mounts or [])):
            raise CommandError("Container mount or user policy could not be verified")
        emit("sandbox.created", {"execution_id": execution_id, "container_id": evidence["container_id"]})
        directory = (tempfile.TemporaryDirectory(prefix="agentcrashlab-canary-")
                     if job.get("probe") == "host-file" else nullcontext())
        with directory as folder:
            if folder:
                canary = Path(folder) / "host-only.txt"
                canary.write_text("AGENTCRASHLAB_HOST_ONLY_SYNTHETIC")
                job = {**job, "host_path": str(canary)}
            try:
                attach_exit, output = await docker("start", "-ai", name, payload=json.dumps(job).encode(),
                                                   timeout=LIMITS["seconds"])
                evidence["attach_exit_code"] = attach_exit
                evidence["stdout"] = output.decode(errors="replace")
                try:
                    evidence["result"] = json.loads(output)
                except (ValueError, UnicodeError):
                    pass
            except TimeoutError:
                evidence["wall_timeout"] = True
                kill_code, _ = await docker("kill", name)
                evidence["kill_succeeded"] = kill_code == 0
        state_code, raw = await docker(
            "inspect", "--format", '{{json .State}} {{json .HostConfig.NetworkMode}}', name
        )
        if state_code:
            raise CommandError("Container state unavailable")
        state, end = json.JSONDecoder().raw_decode(raw.decode())
        network = json.loads(raw.decode()[end:])
        if state["Status"] != "exited" or network != "none" or state["Error"]:
            raise CommandError("Sandbox state could not be verified")
        evidence.update(exit_code=state["ExitCode"], oom_killed=state["OOMKilled"], network=network)
    except (CommandError, TimeoutError, OSError, ValueError, KeyError):
        evidence["error"] = "Sandbox execution or evidence collection failed"
    finally:
        if cleanup_required:
            cleanup = asyncio.create_task(remove(name))
            try:
                evidence["cleanup"] = await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                evidence["cleanup"] = await cleanup
                raise
            finally:
                emit("sandbox.cleanup", {"execution_id": execution_id, "verified": evidence["cleanup"]})
    evidence.update(finished_at=time.time(), duration_seconds=time.time() - start)
    return evidence


async def remove(name):
    try:
        await docker("rm", "-f", name)
        code, remaining = await docker("ps", "-aq", "--filter", f"name=^/{name}$")
        return code == 0 and not remaining.strip()
    except (CommandError, OSError, TimeoutError):
        return False


def verify_probe(probe, execution):
    if execution["mode"] != "live" or execution["cleanup"] is not True or execution.get("error") or execution.get("image_os") != "linux":
        return "INCONCLUSIVE"
    result = execution.get("result")
    if probe == "timeout":
        return "PASS" if (execution.get("wall_timeout") and execution.get("kill_succeeded")
                          and execution.get("exit_code") == 137) else "INCONCLUSIVE"
    if probe == "memory" and execution.get("oom_killed") and execution.get("exit_code") == 137:
        return "PASS"
    if execution.get("exit_code") != 0 or not isinstance(result, dict):
        return "INCONCLUSIVE"
    if result.get("operation_succeeded") is True or "allocated" in result or result.get("present") is True:
        return "FAIL"
    expected = {
        "host-file": result.get("errno_name") == "ENOENT",
        "protected-write": result.get("errno_name") == "EROFS",
        "network": execution.get("network") == "none" and result.get("errno_name") == "ENETUNREACH",
        "memory": False,
        "processes": result.get("errno_name") == "EAGAIN" and 0 < result.get("children", 0) < 16,
        "credential": result.get("present") is False,
    }
    return "PASS" if expected[probe] else "INCONCLUSIVE"
