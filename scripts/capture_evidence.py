"""Capture reviewed local Docker evidence without starting the API or calling inference."""
import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.execution import execute, ready, verify_probe
from backend.store import digest
from backend.verifier import Outcome, verify
from sandbox.runner import FIXTURE_VERSION, PROBES


async def capture():
    if not await ready():
        raise RuntimeError("Explicit local Docker socket is unavailable")

    async def run(job):
        events = []
        execution = await execute(job, "live", lambda name, data: events.append({"type": name, "data": data}))
        return {"execution": execution, "events": events, "execution_sha256": digest(execution)}

    probes = {}
    for name in PROBES:
        row = await run({"probe": name})
        row["outcome"] = verify_probe(name, row["execution"])
        probes[name] = row
        if row["execution"]["cleanup"] is not True:
            break
    policies = {}
    actions = ["report", "read_canary"]
    if len(probes) == len(PROBES) and all(row["execution"]["cleanup"] is True for row in probes.values()):
        for policy in ("vulnerable", "mitigated"):
            row = await run({"target": "analyst", "policy": policy, "actions": actions})
            row["verification"] = verify(row["execution"], actions, policy)
            policies[policy] = row
            if row["execution"]["cleanup"] is not True:
                break

    rows = [*probes.values(), *policies.values()]
    images = {row["execution"].get("image_digest") for row in rows}
    passed = (
        len(probes) == len(PROBES) and len(policies) == 2
        and all(row["outcome"] == "PASS" for row in probes.values())
        and policies["vulnerable"]["verification"]["outcome"] == Outcome.CONFIRMED_FINDING
        and policies["mitigated"]["verification"]["outcome"] == Outcome.ATTEMPT_BLOCKED
        and all(row["verification"]["task_completed"] is True for row in policies.values())
        and len(images) == 1 and None not in images
    )
    return {
        "kind": "local_docker_fixed_fixture",
        "inference_used": False,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "fixture_version": FIXTURE_VERSION,
        "image_digests": sorted(item for item in images if item is not None),
        "passed": passed,
        "probes": probes,
        "fixed_policy_checks": policies,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New JSON file (existing files are preserved)")
    args = parser.parse_args()
    if args.output.exists() or not args.output.parent.is_dir():
        parser.error("Choose a new output file in an existing directory")
    try:
        evidence = asyncio.run(capture())
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(evidence, output, indent=2, allow_nan=False)
            output.write("\n")
    except (OSError, RuntimeError) as exc:
        parser.exit(1, f"Evidence capture failed: {exc}\n")
    print(f"Evidence saved to {args.output}. All checks passed: {evidence['passed']}")
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
