"""Offline export of explicitly selected evidence into a strict public snapshot."""
import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from backend.judge_snapshot import HostAttestation, Snapshot
from backend.verifier import verify
from scripts.package_source import scan
from sandbox.runner import FIXTURE_VERSION
from backend.store import digest

ROOT = Path(__file__).resolve().parents[1]
MAX_SOURCE_BYTES = 262144
DEFAULT = ROOT / "deploy/judge/snapshot.json"


def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("Invalid selected evidence file")
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat() if type(value) in (int, float) else value


def control(path, hosted):
    raw, source_hash = read(path)
    if (raw.get("status") != "completed" or raw.get("execution_source") != "direct_https_local_docker"
            or type(raw.get("live_model_mitigation_demonstrated")) is not bool):
        raise ValueError("Completed model control evidence required")
    if len(raw.get("requests", [])) != 2:
        raise ValueError("Two recorded model calls required")
    for request in raw["requests"]:
        if (request.get("http_status") != 200 or request.get("outcome") != "validated"
                or request.get("metadata", {}).get("model") != "qwen3.8-27b"
                or request["metadata"].get("finish_reason") != "stop"):
            raise ValueError("Model response provenance is incomplete")
    stages = raw.get("stages", [])
    if [s.get("stage") for s in stages] != ["clean-vulnerable", "injected-vulnerable", "clean-mitigated", "injected-replay"]:
        raise ValueError("Fixed control sequence required")
    image = raw["scope"]["pinned_image_id"]
    exported = []
    for index, (stage, name) in enumerate(zip(stages, ("baseline", "original", "mitigated_baseline", "replay"))):
        actions = stage["actions"]
        expected_actions = raw["requests"][0 if index in (0, 2) else 1]["actions"]
        if (stage.get("verified") is not True or stage.get("cleanup_verified") is not True
                or stage.get("image_id") != image or stage.get("fixture_version") != FIXTURE_VERSION
                or actions != expected_actions or stage["proposal_sha256"] !=
                hashlib.sha256(json.dumps(actions, sort_keys=True, separators=(",", ":")).encode()).hexdigest()):
            raise ValueError("Stage provenance is incomplete")
        actual = verify({"mode": "live", "cleanup": True, "exit_code": 0,
                         "result": {"actions": stage["observed_actions"], "report": stage["report"]}},
                        actions, "vulnerable" if index < 2 else "mitigated")
        if actual != stage["verification"]:
            raise ValueError("Independent verification mismatch")
        exported.append({"stage": name, "actions": actions, "cleanup_verified": True,
                         "input_sha256": stage["input_sha256"], "proposal_sha256": stage["proposal_sha256"],
                         "report": stage["report"], **actual})
    return {"id": ("hosted" if hosted else "local") + "-model-control",
            "environment": "vultr_hosted" if hosted else "historical_local",
            "kind": "intentionally_misconfigured_model_control", "recorded_at": iso(raw["finished_at"]),
            "source_sha256": source_hash, "image_sha256": image.removeprefix("sha256:"),
            "inference_provider": "vultr", "model": "qwen3.8-27b", "request_count": 2,
            "stages": exported, "probe_errno": None, "cleanup_verified": True}


def probe(path, hosted):
    raw, source_hash = read(path)
    entry = raw["probes"]["protected-write"]
    execution = entry["execution"]
    if (entry.get("outcome") != "PASS" or execution.get("mode") != "live"
            or execution.get("cleanup") is not True or execution.get("exit_code") != 0
            or execution.get("image_os") != "linux" or execution.get("error")
            or execution.get("result", {}).get("errno_name") != "EROFS"):
        raise ValueError("Verified protected-write proof required")
    return {"id": ("hosted" if hosted else "local") + "-protected-write",
            "environment": "vultr_hosted" if hosted else "historical_local", "kind": "protected_write_probe",
            "recorded_at": iso(execution["finished_at"]), "source_sha256": source_hash,
            "image_sha256": execution["image_digest"].removeprefix("sha256:"),
            "inference_provider": "none", "model": None, "request_count": 0,
            "stages": [], "probe_errno": "EROFS", "cleanup_verified": True}


def assemble(hosted_control=None, hosted_probe=None, attestation=None, historical_snapshot=None):
    if historical_snapshot is None:
        items = [control(ROOT / "docs/CONTROLLED_LIVE_MODEL_STATE/report.json", False),
                 probe(ROOT / "docs/REVIEW_FIX_DOCKER_EVIDENCE.json", False)]
    else:
        selected, _ = read(historical_snapshot)
        reviewed = Snapshot.model_validate_json(json.dumps(selected))
        if reviewed.hosted_attestation or {item.id for item in reviewed.items} != {
            "local-model-control", "local-protected-write"
        }:
            raise ValueError("Only the reviewed historical-local snapshot is accepted here")
        items = [item.model_dump(mode="json") for item in reviewed.items]
    supplied = (hosted_control, hosted_probe, attestation)
    if any(supplied) and not all(supplied):
        raise ValueError("Hosted evidence requires both records and a reviewed host attestation")
    host = None
    if all(supplied):
        host, _ = read(attestation)
        host = HostAttestation.model_validate_json(json.dumps(host)).model_dump(mode="json")
        raw_control, _ = read(hosted_control)
        scope = raw_control.get("scope", {})
        if (digest(scope) != host["control_scope_sha256"]
                or scope.get("release_sha256") != host["release_sha256"]
                or scope.get("runner_source_sha256") != host["runner_source_sha256"]
                or scope.get("pinned_image_id") != "sha256:" + host["worker_image_sha256"]
                or scope.get("host_os") != host["os"] or scope.get("host_kind") != host["host_kind"]):
            raise ValueError("Hosted source, image or scope binding mismatch")
        items.extend([control(hosted_control, True), probe(hosted_probe, True)])
    return Snapshot.model_validate_json(json.dumps({
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "items": items, "hosted_attestation": host,
    }))


def write(snapshot, path, replace=False):
    if path.is_symlink() or (path.exists() and not replace):
        raise ValueError("Snapshot output exists; replacement requires explicit review")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("Reviewed output directory required")
    content = (snapshot.model_dump_json(indent=2) + "\n").encode()
    if len(content) > 65536 or scan("public-snapshot.json", content):
        raise ValueError("Public snapshot rejected by size or pattern review")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)  # Exclusive publication; no overwrite race.
            temporary.unlink()
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT)
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--historical-snapshot", type=Path)
    parser.add_argument("--hosted-control", type=Path)
    parser.add_argument("--hosted-probe", type=Path)
    parser.add_argument("--host-attestation", type=Path)
    args = parser.parse_args()
    try:
        snapshot = assemble(args.hosted_control, args.hosted_probe, args.host_attestation, args.historical_snapshot)
        write(snapshot, args.output, args.replace)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "Snapshot export rejected. Review the selected evidence and output path.\n")
    print("Sanitized public snapshot written. Hosted evidence:", snapshot.hosted_attestation is not None)


if __name__ == "__main__":
    main()
