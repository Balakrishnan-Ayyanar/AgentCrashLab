import asyncio
import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from uuid import UUID

import httpx
import pytest

from sandbox.runner import dispatch
from scripts import controlled_model as control

KEY = "synthetic-control-mock-key"


def response(actions, finish="stop"):
    return httpx.Response(200, json={
        "model": control.MODEL, "usage": {"prompt_tokens": 100, "completion_tokens": 20, "secret": KEY},
        "choices": [{"finish_reason": finish, "message": {"content": json.dumps({"actions": actions})}}],
    })


@pytest.fixture
def scope(tmp_path, monkeypatch):
    monkeypatch.setenv("VULTR_INFERENCE_API_KEY", KEY)
    monkeypatch.delenv("VULTR_INFERENCE_BASE_URL", raising=False)
    config, state = tmp_path / "config.json", tmp_path / "state"
    config.write_text(json.dumps(control.OPT_IN))
    return config, state


def executor(jobs, *, bad_cleanup=False):
    async def run(job, mode, emit):
        jobs.append(deepcopy(job))
        index = len(jobs)
        execution_id, container_id = str(UUID(int=index)), f"{index:064x}"
        emit("sandbox.created", {"execution_id": execution_id, "container_id": container_id})
        emit("sandbox.cleanup", {"execution_id": execution_id, "verified": not bad_cleanup})
        return {"id": execution_id, "container_id": container_id, "mode": mode, "exit_code": 0,
                "image_digest": control.IMAGE, "fixture_version": control.FIXTURE_VERSION,
                "cleanup": not bad_cleanup, "result": dispatch(job), "stdout": KEY}
    return run


def run(scope, handle, execute=None):
    return asyncio.run(control.run_once(*scope, transport=httpx.MockTransport(handle),
                                        executor=execute or executor([])))


@pytest.mark.parametrize("attacked,passes", [
    (["report", "read_canary"], True), (["report"], False), (["read_canary"], False), ([], False),
])
def test_exact_model_proposals_and_mock_claim_boundary(scope, attacked, passes):
    calls, jobs = [], []

    def handle(request):
        calls.append(json.loads(request.content))
        index = len(calls)
        assert calls[-1] == control.body(index)
        assert request.headers["Authorization"] == "Bearer " + KEY
        reservation = json.loads((scope[1] / f"post-{index}-reserved.json").read_text())
        assert reservation["canonical_body_sha256"] == control.SCOPE["request_body_sha256"][index - 1]
        assert reservation["wire_body_sha256"] == hashlib.sha256(request.content).hexdigest()
        return response(["report"] if index == 1 else attacked)

    report = run(scope, handle, executor(jobs))
    assert report["status"] == "completed" and report["execution_source"] == "mock"
    assert report["comparison_checks_passed"] is passes and report["live_model_mitigation_demonstrated"] is False
    assert report["OS_containment_demonstrated"] is False
    assert len(calls) == 2 and len(jobs) == 4
    assert [job["actions"] for job in jobs] == [["report"], attacked] * 2
    assert calls[0]["messages"][0] == calls[1]["messages"][0]
    assert control.NOTE not in calls[0]["messages"][1]["content"]
    assert control.NOTE in calls[1]["messages"][1]["content"]
    assert all(KEY.encode() not in path.read_bytes() for path in scope[1].iterdir())
    with pytest.raises(control.Stopped, match="state_already_consumed"):
        run(scope, handle)
    assert len(calls) == 2


@pytest.mark.parametrize("outcome", ["invalid_baseline_proposal", "sandbox_verification_failed"])
def test_bad_baseline_stops_before_second_post(scope, outcome):
    calls, jobs = [], []

    def handle(request):
        calls.append(request)
        return response(["read_canary"] if outcome == "invalid_baseline_proposal" else ["report"])

    report = run(scope, handle, executor(jobs, bad_cleanup=True))
    assert report["status"] == outcome and len(calls) == 1
    assert not report["live_model_mitigation_demonstrated"]


@pytest.mark.parametrize("field", ["input_sha256", "proposal_sha256", "policy_sha256"])
def test_provenance_mismatch_loses_credit(scope, field):
    replies = iter([["report"], ["report", "read_canary"]])
    report = run(scope, lambda request: response(next(replies)))
    report["stages"][3][field] = report["stages"][1][field] if field == "policy_sha256" else "bad"
    assert not control.mitigation_demonstrated(report["stages"])


@pytest.mark.parametrize("failure,expected", [
    ("timeout", "inference_unknown"), (503, "inference_unknown"), (307, "inference_http_error"),
    ("schema", "inference_response_invalid"), ("length", "inference_response_invalid"),
])
def test_provider_failures_are_terminal_and_sanitized(scope, failure, expected):
    calls = []

    def handle(request):
        calls.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout(KEY, request=request)
        if failure == "schema":
            return response([KEY])
        if failure == "length":
            return response(["report"], finish="length")
        return httpx.Response(failure, text=KEY, headers={"Location": "https://example.invalid/" + KEY})

    report = run(scope, handle)
    assert report["status"] == expected
    assert len(calls) == len(report["requests"]) == 1 and report["stages"] == []
    assert all(KEY.encode() not in path.read_bytes() for path in scope[1].iterdir())
    with pytest.raises(control.Stopped, match="consumed"):
        run(scope, handle)


@pytest.mark.parametrize("change", ["third", "unverified_baseline", "method", "origin", "host", "auth", "body"])
def test_gate_rejects_out_of_scope_request(scope, change):
    _, state = scope
    state.mkdir()
    gate = control.Gate(httpx.MockTransport(lambda request: pytest.fail("Unexpected POST")), state, control.time.monotonic() + 10)
    gate.key = KEY
    gate.index = 3 if change == "third" else 2 if change == "unverified_baseline" else 1
    if change == "unverified_baseline":
        gate.requests.append({})
    content = control.body(2 if change == "unverified_baseline" else 1)
    if change == "body":
        content["max_tokens"] = 601
    request = httpx.Request("GET" if change == "method" else "POST",
                            "https://example.invalid" if change == "origin" else control.ENDPOINT,
                            headers={"Authorization": "Bearer " + ("wrong" if change == "auth" else KEY)},
                            json=content)
    if change == "host":
        request.headers["Host"] = "example.invalid"
    with pytest.raises(control.Stopped):
        asyncio.run(gate.handle_async_request(request))
    assert not list(state.iterdir())


def test_accidental_adapter_retry_cannot_send_again(scope, monkeypatch):
    factory = control.Vultr
    calls = []

    def accidentally_retry(*args, **kwargs):
        assert kwargs["max_attempts"] == 1
        return factory(*args, **{**kwargs, "max_attempts": 2})

    def handle(request):
        calls.append(request)
        return httpx.Response(503)

    monkeypatch.setattr(control, "Vultr", accidentally_retry)
    report = run(scope, handle)
    assert len(calls) == 1 and report["status"] == "request_budget_or_order_violation"


@pytest.mark.parametrize("phase", ["claim", "post"])
def test_failed_persistence_prevents_network(scope, monkeypatch, phase):
    if phase == "claim":
        def sync(path):
            raise OSError("simulated sync failure")
        monkeypatch.setattr(control, "sync_directory", sync)
        with pytest.raises(OSError):
            run(scope, lambda request: pytest.fail("Unexpected POST"))
    else:
        write = control.write_record

        def fail(path, data):
            if path.name == "post-1-reserved.json":
                raise OSError("simulated sync failure")
            write(path, data)

        monkeypatch.setattr(control, "write_record", fail)
        assert run(scope, lambda request: pytest.fail("Unexpected POST"))["status"] == "execution_or_audit_failed"
    assert scope[1].exists()
    with pytest.raises(control.Stopped, match="consumed"):
        run(scope, lambda request: pytest.fail("Unexpected POST"))


def test_missing_or_changed_config_refuses_before_client_or_claim(scope, monkeypatch):
    monkeypatch.setattr(control, "Vultr", lambda *args, **kwargs: pytest.fail("Unexpected client"))
    scope[0].unlink()
    with pytest.raises(FileNotFoundError):
        run(scope, lambda request: pytest.fail("Unexpected POST"))
    scope[0].write_text(json.dumps({**control.OPT_IN, "max_posts": 3}))
    with pytest.raises(control.Stopped, match="configuration_scope_mismatch"):
        run(scope, lambda request: pytest.fail("Unexpected POST"))
    assert not scope[1].exists()


def test_two_processes_cannot_claim_same_intent_and_crash_is_terminal(scope):
    code = """
import asyncio, os, sys, httpx
from pathlib import Path
from scripts.controlled_model import run_once
def mock(request):
    print("reserved", flush=True)
    sys.stdin.readline()
    os._exit(41)
asyncio.run(run_once(Path(sys.argv[1]), Path(sys.argv[2]), transport=httpx.MockTransport(mock), executor=lambda *args: None))
"""
    args = [sys.executable, "-c", code, *map(str, scope)]
    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as owner:
        try:
            assert owner.stdout.readline().strip() == "reserved"
            second = subprocess.run(args, input="", capture_output=True, text=True, timeout=10)
            assert second.returncode != 0 and "state_already_consumed" in second.stderr
        finally:
            owner.communicate("\n", timeout=10)
        assert owner.returncode == 41
    assert json.loads((scope[1] / "post-1-reserved.json").read_text())["outcome"] == "reserved_unknown"
    with pytest.raises(control.Stopped, match="consumed"):
        run(scope, lambda request: pytest.fail("Unexpected POST"))


def test_import_and_cli_without_flag_do_not_access_credentials():
    code = """
import os, sys
original = os.environ.__class__.__getitem__
def no_keys(self, key):
    if "KEY" in key or "TOKEN" in key:
        raise AssertionError("Unexpected credential access")
    return original(self, key)
os.environ.__class__.__getitem__ = no_keys
from scripts import controlled_model as control
sys.argv = ["controlled_model"]
control.main()
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=10)
    assert result.returncode == 2 and "--print-config" in result.stderr
    assert "Unexpected" not in result.stderr


def test_deadline_after_reservation_prevents_send(scope, monkeypatch):
    write = control.write_record
    now = control.time.monotonic
    expired = False

    def clock():
        return now() + (181 if expired else 0)

    def reserve(path, data):
        nonlocal expired
        write(path, data)
        if path.name == "post-1-reserved.json":
            expired = True

    # Replace the module clock only, leaving the asyncio event-loop clock unchanged.
    from types import SimpleNamespace

    monkeypatch.setattr(control, "time", SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(control, "write_record", reserve)
    result = run(scope, lambda request: pytest.fail("POST after deadline"))
    assert result["status"] == "deadline_or_cancellation"
    assert result["requests"][0]["outcome"] == "reserved_unknown"


def test_cancellation_during_first_docker_stage_preserves_cleanup_and_intent(scope):
    calls, cleaned = [], []

    def handle(request):
        calls.append(request)
        return response(["report"])

    async def docker(job, mode, emit):
        try:
            asyncio.current_task().cancel()
            await asyncio.sleep(0)
        finally:
            cleaned.append(True)
            emit("sandbox.cleanup", {"execution_id": str(UUID(int=1)), "verified": True})

    with pytest.raises(asyncio.CancelledError):
        run(scope, handle, docker)
    result = json.loads((scope[1] / "report.json").read_text())
    assert result["status"] == "cancelled" and cleaned == [True] and len(calls) == 1
    assert json.loads((scope[1] / "stage-1-sandbox.cleanup.json").read_text())["cleanup_verified"]
    with pytest.raises(control.Stopped, match="consumed"):
        run(scope, handle)



@pytest.mark.parametrize("model", [None, "unexpected-private-model-name"])
def test_missing_or_wrong_response_model_stops_before_docker(scope, model):
    calls = []

    def handle(request):
        calls.append(request)
        data = response(["report"]).json()
        if model is None:
            del data["model"]
        else:
            data["model"] = model
        return httpx.Response(200, json=data)

    async def forbidden(*args):
        pytest.fail("Unexpected Docker execution")

    report = run(scope, handle, forbidden)
    assert report["status"] == "unverified_model_response"
    assert len(calls) == 1 and report["stages"] == []
    assert report["requests"][0]["outcome"] == "response_invalid"
    assert "model" not in report["requests"][0]["metadata"]
    if model:
        assert all(model not in path.read_text() for path in scope[1].iterdir())


def test_stage_retains_observed_report(scope):
    base = executor([])

    async def reordered_report(job, mode, emit):
        evidence = await base(job, mode, emit)
        evidence["result"]["report"] = dict(reversed(list(evidence["result"]["report"].items())))
        return evidence

    report = run(scope, lambda request: response(["report"]), reordered_report)
    assert report["status"] == "completed"
    assert list(report["stages"][0]["report"]) == ["delta", "Feb", "Jan"]


def test_public_image_configuration_is_immutable_and_scope_bound(monkeypatch):
    monkeypatch.setattr(control, 'IMAGE', control.IMAGE)
    monkeypatch.setattr(control, 'SCOPE', dict(control.SCOPE))
    monkeypatch.setattr(control, 'OPT_IN', dict(control.OPT_IN))
    for bad in ('latest', 'sha256:short', 'sha256:' + '0' * 64):
        with pytest.raises(ValueError, match='immutable_image_required'):
            control.configure_image(bad)
    image = 'sha256:' + 'a' * 64
    control.configure_image(image)
    assert control.SCOPE['pinned_image_id'] == image
    assert control.OPT_IN == {'scope_sha256': control.digest(control.SCOPE), 'execute_two_requests': True}
    assert control.SCOPE['max_posts'] == 2 and control.SCOPE['max_output_tokens'] == 600


def test_public_configuration_rejects_duplicates_and_symlinks(tmp_path):
    p = tmp_path / 'config.json'
    p.write_text('{"execute_two_requests":true,"execute_two_requests":false}')
    with pytest.raises(ValueError, match='duplicate_json_keys'):
        control.read_configuration(p)
    link = tmp_path / 'link.json'
    link.symlink_to(p)
    with pytest.raises(OSError):
        control.read_configuration(link)


def test_print_config_is_offline_and_does_not_read_keys():
    code = '''
import os,sys
from scripts import controlled_model as c
original=os.environ.__class__.__getitem__
def check(self,key):
    if "KEY" in key or "TOKEN" in key:raise AssertionError("credential read")
    return original(self,key)
os.environ.__class__.__getitem__=check
c.image_preflight=lambda: (_ for _ in ()).throw(AssertionError("Docker accessed"))
c.Vultr=lambda *a,**k: (_ for _ in ()).throw(AssertionError("client constructed"))
sys.argv=["controlled_model","--print-config","--image-id","sha256:"+"a"*64]
c.main()
'''
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert json.loads(result.stdout)['execute_two_requests'] is True
