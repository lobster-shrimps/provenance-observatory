"""Continuous agent monitoring (E2) + agent-level advisories (E3).

Runs an authorized agent through the engine on a schedule, computes a stable
AGENT FINGERPRINT (the model composition of the run), and feeds the SAME
disclosure pipeline the endpoint targets use — `advisory.on_drift` opens a draft
when tonight's agent looks different from the pinned baseline, and the intra-run
model switches travel as evidence. No new crypto, no new advisory machinery: an
agent advisory is a numbered MPA just like an endpoint one.

    engine `agent-trace <trace> --export rec.json`  ->  rec (verdict + steps)
        agent_fingerprint(rec)  ->  advisory.on_drift(name, fp, evidence)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))   # runner/ on path (repo convention)
import advisory  # noqa: E402
import agent_behaviors  # noqa: E402

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
AGENT_TRACE_TIMEOUT = 300     # seconds — a hung engine call can't stall the nightly run


def safe_name(name: str) -> str:
    """Reject target names that could escape the data/staging tree (`/`, `..`) or
    break the manifest glob. Path-injection guard."""
    if not isinstance(name, str) or not _SAFE_NAME.match(name):
        raise ValueError(f"unsafe target name {name!r}: use [A-Za-z0-9._-] only")
    return name


def behavior_findings(record: dict) -> list[dict]:
    """Concerning-behavior rows already attached to an agent record, deduped by id."""
    items, seen = [], set()
    sources = (
        record.get("concerning_behaviors"),
        (record.get("verdict") or {}).get("concerning_behaviors") if isinstance(record.get("verdict"), dict) else None,
    )
    for src in sources:
        if not isinstance(src, list):
            continue
        for item in src:
            if isinstance(item, str):
                item = {"id": item, "summary": item}
            if not isinstance(item, dict) or not item.get("id") or item["id"] in seen:
                continue
            seen.add(item["id"])
            items.append(item)
    items.sort(key=lambda row: row["id"])
    return items


def annotate_trace(record: dict, trace_path: str | None) -> dict:
    """Merge a local scan of ``trace_path`` into the engine record.

    The observatory does not import the probe package (T7). The checker is the
    vendored copy of ``agent_behaviors``. An unreadable trace leaves the engine
    record unchanged. Empty scans do not add a key, so a clean record's
    fingerprint stays what it was before this check existed.
    """
    if not trace_path:
        return record
    try:
        findings = agent_behaviors.scan_path(trace_path)
    except (OSError, ValueError):
        return record
    return merge_findings(record, findings)


def merge_findings(record: dict, findings: list[dict]) -> dict:
    """Return a copy of ``record`` with ``concerning_behaviors`` unioned in."""
    incoming = []
    for item in findings or []:
        if isinstance(item, dict) and item.get("id"):
            incoming.append(item)
    existing = behavior_findings(record)
    if not existing and not incoming:
        return record
    seen = set()
    merged = []
    for item in existing + incoming:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        merged.append({
            "id": item["id"],
            "summary": item.get("summary") or item["id"],
            "source": item.get("source") or agent_behaviors.SOURCE_ID,
            **({"indicator": item["indicator"]} if item.get("indicator") else {}),
        })
    merged.sort(key=lambda row: row["id"])
    out = dict(record)
    verdict = dict(out.get("verdict") or {})
    verdict["concerning_behaviors"] = merged
    verdict["alert"] = True
    out["verdict"] = verdict
    out["concerning_behaviors"] = merged
    return out


def agent_fingerprint(record: dict) -> str:
    """Stable hash of the run's MODEL COMPOSITION — the per-step (kind, echoed
    model, jurisdiction basis) sequence plus the overall verdict label. Changes
    when the agent starts running a different model, routing differently, or
    egressing to a different jurisdiction; ignores volatile per-run text.

    A non-empty concerning-behavior id list is part of the hash. An absent or
    empty list is omitted so records from before this check keep their fingerprint.
    """
    steps = record.get("steps") or []
    sig = [[s.get("kind"), s.get("echoed_model"), s.get("jurisdiction_basis")] for s in steps]
    label = (record.get("verdict") or {}).get("label") if isinstance(record.get("verdict"), dict) else None
    payload = {"steps": sig, "verdict": label}
    ids = [row["id"] for row in behavior_findings(record)]
    if ids:
        payload["concerning_behaviors"] = ids
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def run_agent_target(trace_path: str, export_path: str) -> dict:
    """Invoke the engine as a black-box CLI to assess a captured agent run and
    return the exported evidence record. Raises on a hard engine failure."""
    r = subprocess.run(
        ["provenance-probe", "agent-trace", trace_path, "--export", export_path],
        capture_output=True, text=True, timeout=AGENT_TRACE_TIMEOUT)
    if r.returncode not in (0, 2):      # 2 = a switch was detected (alert, not error)
        raise RuntimeError(f"agent-trace failed ({r.returncode}): {r.stderr[:200]}")
    with open(export_path) as f:
        return json.load(f)


def monitor_agent(target_name: str, record: dict, *, target_public: bool) -> dict:
    """Fingerprint the agent run and drive the advisory pipeline. First run seeds
    the baseline (no drift); a later run with a different composition opens a
    draft. Intra-run model switches ride along as evidence."""
    fp = agent_fingerprint(record)
    verdict = record.get("verdict") or {}
    findings = behavior_findings(record)
    evidence = {
        "kind": "agent",
        "verdict_label": verdict.get("label"),
        "provenance_verdict": verdict.get("provenance_verdict"),
        "jurisdiction_verdict": verdict.get("jurisdiction_verdict"),
        "steps": len(record.get("steps") or []),
        "model_switches": verdict.get("model_switches") or [],
        "concerning_behaviors": [row["id"] for row in findings],
    }
    state = advisory.load_state(target_name)
    if not state.pinned_baseline:               # first sight -> seed, no advisory
        advisory.ensure_baseline(target_name, fp)
        summary = {"action": "seeded", "target": target_name}
    elif fp != state.pinned_baseline:           # composition changed -> drift advisory
        summary = advisory.on_drift(target_name, fp, evidence, target_public=target_public)
    else:
        summary = {"action": "no-change", "target": target_name}
    behavior_advisory = None
    if findings:
        behavior_advisory = advisory.on_agent_behavior(
            target_name, findings, target_public=target_public)
    return {"fingerprint": fp, "advisory": summary,
            "switch_in_run": bool(evidence["model_switches"]),
            "behavior_alert": bool(findings),
            "behavior_advisory": behavior_advisory}


def write_agent_record(data_dir: str, target_name: str, date_str: str, record: dict,
                       filename: str = "verdict.json") -> str:
    """Drop the evidence record where the daily cosign+Rekor manifest signs it."""
    d = os.path.join(data_dir, "agents", safe_name(target_name), date_str)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "verdict.json")
    with open(path, "w") as f:
        json.dump(record, f, indent=2, sort_keys=True)
    return path
