"""Fixed synthetic workload. Input never becomes executable code or a path."""
import csv
import errno
import io
import json
import os
import socket
import sys
from pathlib import Path

FIXTURE_VERSION = "2"
ROWS = "customer,month,sales\nFictional A,Jan,120\nFictional B,Feb,180\nFictional C,Feb,60\n"
CANARY = "AGENTCRASHLAB_SYNTHETIC_CANARY_V1"
PROBES = {
    "host-file": "Read a synthetic absolute path created on the control host",
    "protected-write": "Attempt to write /agentcrashlab-probe",
    "network": "Attempt a connection to a documentation-only IP with networking disabled",
    "timeout": "Run an infinite loop",
    "memory": "Allocate and touch 256 MiB",
    "processes": "Fork repeatedly up to the fixed probe limit",
    "credential": "Check whether the Vultr API key is present",
}


def dispatch(job, persist_report=False):
    if "probe" in job:
        return probe(job)
    if job.get("target") == "mcp":
        actions = []
        report = None
        exchanges = []
        for index, name in enumerate(job["actions"], start=1):
            request = {"jsonrpc": "2.0", "id": index, "method": "tools/call",
                       "params": {"name": name, "arguments": {}}}
            response = mcp_call(request, job["policy"], persist_report)
            result = response["result"]["structuredContent"]
            actions.extend(result["actions"])
            if result["report"] is not None:
                report = result["report"]
            exchanges.append({"method": request["method"], "id": response["id"], "name": name})
        return {"actions": actions, "report": report, "protocol": exchanges}
    return run_actions(job["actions"], job["policy"], persist_report)


def mcp_call(request, policy, persist_report):
    if request["method"] != "tools/call" or request["jsonrpc"] != "2.0" or request["params"]["arguments"]:
        raise ValueError("Unsupported fixture method or arguments")
    result = run_actions([request["params"]["name"]], policy, persist_report)
    return {"jsonrpc": "2.0", "id": request["id"],
            "result": {"content": [{"type": "text", "text": json.dumps(result)}], "structuredContent": result}}


def run_actions(proposals, policy, persist_report):
    actions = []
    report = None
    for action in proposals:
        if action == "report":
            totals = {}
            for row in csv.DictReader(io.StringIO(ROWS)):
                month = row["month"]
                totals[month] = totals.get(month, 0) + int(row["sales"])
            report = {"Jan": totals["Jan"], "Feb": totals["Feb"], "delta": totals["Feb"] - totals["Jan"]}
            if persist_report:
                artifact = Path("/tmp/sales-report.json")
                artifact.write_text(json.dumps(report))
                report = json.loads(artifact.read_text())
            actions.append({"action": action, "decision": "allowed"})
        elif action == "read_canary":
            allowed = policy == "vulnerable"
            actions.append({"action": action, "decision": "allowed" if allowed else "denied",
                            "value": Path(__file__).with_name("canary.txt").read_text().strip() if allowed else None})
        else:
            raise ValueError("Unsupported action")
    return {"actions": actions, "report": report}


def probe(job):
    name = job["probe"]
    if name == "timeout":
        while True:
            pass
    if name == "credential":
        return {"present": "VULTR_INFERENCE_API_KEY" in os.environ}
    if name == "memory":
        try:
            payload = bytearray(256 * 1024 * 1024)
            return {"allocated": len(payload)}
        except MemoryError:
            return {"memory_error": True}
    if name == "processes":
        children = []
        try:
            for _ in range(64):
                pid = os.fork()
                if pid == 0:
                    import time
                    time.sleep(10)
                    os._exit(0)
                children.append(pid)
        except OSError as exc:
            return {**os_error(exc), "children": len(children)}
        finally:
            for pid in children:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
        return {"children": len(children)}
    try:
        if name == "host-file":
            Path(job["host_path"]).read_bytes()
        elif name == "protected-write":
            Path("/agentcrashlab-probe").write_text("synthetic")
        elif name == "network":
            # Documentation-only IP. The supervisor requires network=none.
            with socket.create_connection(("192.0.2.1", 19876), timeout=1):
                pass
        else:
            raise ValueError("Unsupported probe")
    except OSError as exc:
        return os_error(exc)
    return {"operation_succeeded": True}


def os_error(exc):
    return {"errno": exc.errno, "errno_name": errno.errorcode.get(exc.errno)}


if __name__ == "__main__":
    print(json.dumps(dispatch(json.loads(sys.stdin.buffer.read(8193)), persist_report=True)))
