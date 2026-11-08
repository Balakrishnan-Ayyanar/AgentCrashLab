import hashlib
import importlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.judge import create_app, load
from backend.judge_snapshot import Snapshot
from scripts import export_judge_snapshot as exporter


def serialize(snapshot):
    return snapshot.model_dump(mode="json")


@pytest.fixture
def selected_evidence(tmp_path, monkeypatch):
    # Reconstruct synthetic exporter inputs from the bounded public fixture, never private logs.
    from pathlib import Path
    from sandbox.runner import CANARY

    snapshot = json.loads(Path("deploy/judge/snapshot.json").read_text())
    model, probe_item = snapshot["items"]
    stages = []
    names = ["clean-vulnerable", "injected-vulnerable", "clean-mitigated", "injected-replay"]
    for index, (public, name) in enumerate(zip(model["stages"], names)):
        observed = [{"action": action, "decision": "allowed"} if action == "report" else {
            "action": action, "decision": "allowed" if index < 2 else "denied",
            "value": CANARY if index < 2 else None,
        } for action in public["actions"]]
        stages.append({"stage": name, "actions": public["actions"], "verified": True,
                       "cleanup_verified": True, "image_id": "sha256:" + model["image_sha256"],
                       "fixture_version": "2", "proposal_sha256": public["proposal_sha256"],
                       "input_sha256": public["input_sha256"], "observed_actions": observed,
                       "report": public["report"], "verification": {key: public[key] for key in (
                           "outcome", "task_completed", "attempted", "achieved", "blocked")}})
    raw_model = {"status": "completed", "execution_source": "direct_https_local_docker",
                 "live_model_mitigation_demonstrated": True, "finished_at": model["recorded_at"],
                 "scope": {"pinned_image_id": "sha256:" + model["image_sha256"]}, "stages": stages,
                 "requests": [{"http_status": 200, "outcome": "validated", "actions": model["stages"][i]["actions"],
                               "metadata": {"model": "qwen3.8-27b", "finish_reason": "stop"}} for i in (0, 1)]}
    raw_probe = {"probes": {"protected-write": {"outcome": "PASS", "execution": {
        "mode": "live", "cleanup": True, "exit_code": 0, "image_os": "linux",
        "result": {"errno_name": "EROFS"}, "finished_at": probe_item["recorded_at"],
        "image_digest": "sha256:" + probe_item["image_sha256"],
    }}}}
    docs = tmp_path / "docs"
    (docs / "CONTROLLED_LIVE_MODEL_STATE").mkdir(parents=True)
    (docs / "CONTROLLED_LIVE_MODEL_STATE/report.json").write_text(json.dumps(raw_model))
    (docs / "REVIEW_FIX_DOCKER_EVIDENCE.json").write_text(json.dumps(raw_probe))
    monkeypatch.setattr(exporter, "ROOT", tmp_path)
    return tmp_path


@pytest.fixture
def snapshot_file(tmp_path, selected_evidence):
    path = tmp_path / "snapshot.json"
    exporter.write(exporter.assemble(), path)
    return path


def test_public_service_is_read_only_even_with_operator_token(snapshot_file):
    with TestClient(create_app(snapshot_file), headers={"Authorization": "Bearer synthetic-operator"}) as client:
        response = client.get("/api/judge")
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        document = response.json()
        assert document["execution_enabled"] is False and document["snapshot"]["hosted_attestation"] is None
        assert {item["environment"] for item in document["snapshot"]["items"]} == {"historical_local"}
        assert "authorization" not in response.text.lower() and "AGENTCRASHLAB_TOKEN" not in response.text
        for endpoint in ("/api/evaluations", "/api/ready", "/api/models", "/api/reports/x", "/api/evaluations/x/events",
                         "/api/containment/probes/protected-write/run", "/api/judge/import"):
            assert client.get(endpoint).status_code == 404
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                assert client.request(method, endpoint, json={"actions": ["read_canary"]}).status_code == 405
        assert client.post("/api/judge").status_code == 405
        assert client.get("/api/judge/download").json() == document
        assert "attachment" in client.get("/api/judge/download").headers["content-disposition"]


def test_import_never_constructs_inference_docker_or_db():
    script = """
import os,sys
class Block:
    def find_spec(self,name,*args):
        if name in {"backend.main","backend.inference","backend.execution","backend.store","sqlite3","httpx"}:
            raise AssertionError("Unexpected private dependency")
sys.meta_path.insert(0,Block())
original=os.environ.__class__.__getitem__
def guarded(self,key):
    if "KEY" in key or "TOKEN" in key:
        raise AssertionError("Unexpected credential read")
    return original(self,key)
os.environ.__class__.__getitem__=guarded
from backend.judge import app
print("pure read-only judge import")
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("kind", ["absent", "corrupt", "extra", "symlink", "oversized"])
def test_unavailable_snapshot_fails_closed(tmp_path, kind, selected_evidence):
    path = tmp_path / "snapshot.json"
    if kind == "corrupt":
        path.write_text("invalid")
    elif kind == "extra":
        document = serialize(exporter.assemble())
        document["secret"] = "synthetic-secret"
        path.write_text(json.dumps(document))
    elif kind == "symlink":
        original = tmp_path / "original.json"
        exporter.write(exporter.assemble(), original)
        path.symlink_to(original)
    elif kind == "oversized":
        path.write_text(" " * 65537)
    with TestClient(create_app(path)) as client:
        response = client.get("/api/judge")
        assert response.status_code == 503
        assert response.json() == {"detail": "Reviewed evidence snapshot unavailable"}
        assert str(tmp_path) not in response.text


def test_stale_snapshot_is_explicit_and_keeps_original_evidence_dates(snapshot_file):
    data = json.loads(snapshot_file.read_text())
    data["generated_at"] = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    snapshot_file.write_text(json.dumps(data))
    with TestClient(create_app(snapshot_file)) as client:
        document = client.get("/api/judge").json()
        assert document["snapshot_status"] == "stale"
        assert document["snapshot"]["items"][0]["recorded_at"] == data["items"][0]["recorded_at"]


def test_export_is_a_strict_allowlist(snapshot_file):
    data = json.loads(snapshot_file.read_text())
    assert {item["id"] for item in data["items"]} == {"local-model-control", "local-protected-write"}
    forbidden = ("AGENTCRASHLAB_TOKEN", "read_canary tool", "container_id", "execution_id", "stdout",
                 "/Users/", "private gateway", "authorization", "api_key")
    assert not any(term in snapshot_file.read_text() for term in forbidden)
    for item in data["items"]:
        assert len(item["source_sha256"]) == len(item["image_sha256"]) == 64
    assert load(snapshot_file).model_dump(mode="json") == data
    with pytest.raises(ValueError):
        exporter.write(exporter.assemble(), snapshot_file)


def test_hosted_import_rejects_local_relabel_and_incomplete_inputs(tmp_path, selected_evidence):
    root = exporter.ROOT
    with pytest.raises(ValueError):
        exporter.assemble(root / "docs/CONTROLLED_LIVE_MODEL_STATE/report.json")
    host = tmp_path / "host.json"
    host.write_text(json.dumps({
        "platform": "vultr", "os": "ubuntu-24.04", "architecture": "amd64",
        "host_kind": "dedicated", "runner_source_sha256": "b" * 64,
        "worker_image_sha256": "c" * 64, "control_scope_sha256": "d" * 64,
        "backend_on_vultr": True, "worker_on_vultr": True,
        "release_sha256": "a" * 64, "observed_at": "2026-11-01T00:00:00Z",
    }))
    with pytest.raises(ValueError, match="binding mismatch"):
        exporter.assemble(root / "docs/CONTROLLED_LIVE_MODEL_STATE/report.json",
                          root / "docs/REVIEW_FIX_DOCKER_EVIDENCE.json", host)


@pytest.mark.parametrize("change", ["extra", "future", "changed_input", "false_finding"])
def test_snapshot_validation_rejects_unreviewed_shape(snapshot_file, change):
    data = json.loads(snapshot_file.read_text())
    if change == "extra":
        data["items"][0]["prompt"] = "do something"
    elif change == "future":
        data["items"][0]["recorded_at"] = "2999-01-01T00:00:00Z"
    elif change == "changed_input":
        data["items"][0]["stages"][3]["input_sha256"] = "0" * 64
    else:
        data["items"][0]["stages"][1]["achieved"] = False
    with pytest.raises(ValidationError):
        Snapshot.model_validate_json(json.dumps(data))


def test_proxy_has_exact_read_allowlist_and_no_private_forward():
    from pathlib import Path

    config = Path("deploy/Caddyfile").read_text()
    assert "path /api/judge /api/judge/download /api/judge/health" in config
    assert "method GET" in config and "respond 404" in config
    assert "127.0.0.1:18080" in config and "18081" not in config


def test_released_historical_snapshot_import_needs_no_private_sources(snapshot_file, monkeypatch, tmp_path):
    monkeypatch.setattr(exporter, "ROOT", tmp_path / "no-private-evidence")
    exported = exporter.assemble(historical_snapshot=snapshot_file)
    original = json.loads(snapshot_file.read_text())
    assert exported.hosted_attestation is None
    assert [item.model_dump(mode="json") for item in exported.items] == original["items"]


def test_query_parameters_cannot_select_private_files(snapshot_file):
    with TestClient(create_app(snapshot_file)) as client:
        response = client.get("/api/judge?file=../../.env&database=private.sqlite3")
        assert response.status_code == 200
        assert response.json() == client.get("/api/judge").json()


def test_negative_model_result_can_be_reviewed_without_mitigation_credit(selected_evidence, tmp_path):
    path = selected_evidence / "docs/CONTROLLED_LIVE_MODEL_STATE/report.json"
    raw = json.loads(path.read_text())
    raw["live_model_mitigation_demonstrated"] = False
    raw["requests"][1]["actions"] = ["report"]
    for index in (1, 3):
        stage = raw["stages"][index]
        stage["actions"] = ["report"]
        stage["proposal_sha256"] = raw["stages"][0]["proposal_sha256"]
        stage["observed_actions"] = [{"action": "report", "decision": "allowed"}]
        stage["verification"] = {"outcome": "PASS", "task_completed": True, "attempted": False,
                                 "achieved": False, "blocked": False}
    path.write_text(json.dumps(raw))
    snapshot = exporter.assemble()
    control = snapshot.items[0]
    assert not control.stages[1].achieved and not control.stages[3].blocked
