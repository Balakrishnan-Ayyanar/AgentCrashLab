"""Render the existing report payload as a standalone, escaped HTML document."""
import json
from html import escape


def text(value):
    return escape(str(value))


def outcome(value):
    return text(str(value or "unavailable").replace("_", " ").title())


def status(value):
    return "Yes" if value is True else "No" if value is False else "Unavailable"


def render_html(report):
    job = report["job"]
    target = report["target"]
    summary = report["summary"]
    regression = report["regression"]
    findings = "".join(
        f'<li><strong>{text(item["title"])}</strong> ({text(item["severity"])}) '
        f'<a href="#event-{text(item["evidence"]["id"])}">Evidence</a>'
        f'<p>{text(item["mitigation"])}</p></li>'
        for item in report["findings"]
    )
    rows = "".join(
        f'<tr><th scope="row"><a href="#event-{text(event["id"])}">{text(data["stage"])}</a></th>'
        f'<td>{outcome(data["outcome"])}</td><td>{status(data["task_completed"])}</td>'
        f'<td>{status(data["attempted"])}</td><td>{status(data["achieved"])}</td>'
        f'<td>{status(data["blocked"])}</td></tr>'
        for event in report["events"] if event["type"] == "attack.verified" for data in [event["data"]]
    )
    comparison = ""
    if regression:
        comparisons = "".join(
            f'<li>Attack {index}: {outcome(pair["before"]["outcome"])} → '
            f'{outcome(pair["after"]["outcome"])}. Report completed after replay: '
            f'{status(pair["after"]["task_completed"])}. Policy block demonstrated: '
            f'{status(pair.get("policy_block_demonstrated"))}.</li>'
            for index, pair in enumerate(regression["comparisons"], start=1)
        )
        method = ("Exact original tool proposals replayed under both policies."
                  if regression.get("method") == "exact_proposal_replay"
                  else "Historical comparison without verified proposal replay.")
        comparison = (f'<p>{method}</p><p>Baseline report preserved: {status(regression["baseline_preserved"])}.</p>'
                      f'<ul>{comparisons}</ul>')
    evidence = "".join(
        f'<details id="event-{text(event["id"])}"><summary>#{text(event["id"])} '
        f'{text(event["type"])}</summary><pre>{text(json.dumps(event, indent=2))}</pre></details>'
        for event in report["events"]
    )
    limitations = "".join(f"<li>{text(item)}</li>" for item in report["limitations"])
    mode = "Offline simulation" if job["mode"] == "offline" else "Configured live mode"
    authorized = ", ".join(report["scope"]["authorized_actions"])
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentCrashLab security report</title>
<style>
body {{ font: 1rem/1.55 system-ui,sans-serif; max-width: 68rem; margin: 2rem auto; padding: 0 1rem; color: #172530; }}
header, section {{ border-bottom: 1px solid #cbd5df; padding: .5rem 0 1rem; }}
small {{ color: #395369; }} table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: .55rem; text-align: left; border-bottom: 1px solid #cbd5df; }}
.table {{ overflow-x: auto; }} details {{ padding: .35rem 0; }} summary {{ cursor: pointer; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #eff4f8; padding: 1rem; }}
</style>
<main>
<header><small>{mode}</small><h1>AgentCrashLab security report</h1>
<p>{text(target["name"])} · {text(job["status"])}<br>Evaluation {text(job["id"])}</p></header>
<section><h2>Executive summary</h2>
<p>{text(summary["verified_experiments"])} verified experiments · {text(summary["findings"])} findings ·
{text(summary["blocked"])} blocked tool actions</p><p>{text(report["methodology"])}</p></section>
<section><h2>Target and scope</h2><p>{text(target["task"])}</p>
<p>Attack surface: {text(target["surface"])}. Authorized actions: {text(authorized)}.
Prohibited objective: {text(report["scope"]["prohibited_objective"])}.</p></section>
<section><h2>Experiment outcomes</h2>{f'''<div class="table"><table><thead><tr>
<th scope="col">Stage</th><th scope="col">Outcome</th><th scope="col">Task completed</th>
<th scope="col">Attempted</th><th scope="col">Achieved</th><th scope="col">Blocked</th>
</tr></thead><tbody>{rows}</tbody></table></div>''' if rows else '<p>No verified experiments recorded.</p>'}</section>
<section><h2>Findings and mitigations</h2>{f'<ul>{findings}</ul>' if findings else '<p>No findings recorded.</p>'}</section>
<section><h2>Mitigation regression</h2>{comparison or '<p>No comparison recorded.</p>'}</section>
<section><h2>Limitations</h2><ul>{limitations}</ul>
<p>OS containment is assessed separately in the Containment Lab.</p></section>
<section><h2>Evidence timeline</h2>{evidence or '<p>No events recorded.</p>'}</section>
</main></html>"""
