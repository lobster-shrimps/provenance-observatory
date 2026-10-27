"""Pinned Qwen trace grade. Hermetic: no model call and no network."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "runner"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "site"))
import build  # noqa: E402
import trace_grade  # noqa: E402
from lib import publish_policy, signing  # noqa: E402


def test_pinned_trace_ids_and_quiet_prefill():
    rec = trace_grade.grade()
    assert rec["behavior_ids"] == trace_grade.EXPECTED_IDS
    assert "beijing_oss_put" in rec["behavior_ids"]
    assert rec["prefill_behavior_ids"] == []
    assert rec["trace_sha256"]
    assert rec["measurement_path"] == "direct"


def test_grade_is_signable_and_on_the_manifest(tmp_path):
    path = trace_grade.write_grade(str(tmp_path), "2026-10-27")
    with open(path, encoding="utf-8") as fh:
        rec = json.load(fh)
    ok, reason = publish_policy.is_publishable(rec)
    assert ok, reason
    manifest = signing.build_manifest(str(tmp_path), "2026-10-27")
    rel = "agent-controls/cohere-qwen/2026-10-27/grade.json"
    assert rel in manifest["entries"]
    assert len(manifest["entries"][rel]) == 64


def test_site_shows_the_pinned_grade(tmp_path):
    data = tmp_path / "data"
    trace_grade.write_grade(str(data), "2026-10-27")
    out = build.build(str(data), str(tmp_path / "out"), now_iso="2026-10-27T12:00:00")
    page = open(out, encoding="utf-8").read()
    assert "Pinned trace grade" in page
    assert "beijing_oss_put" in page
    assert "prefill completion stayed quiet" in page
