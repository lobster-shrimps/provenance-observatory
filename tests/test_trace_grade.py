"""Pinned Qwen trace grade. Hermetic: no model call and no network."""
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "runner"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "site"))
import build  # noqa: E402
import trace_grade  # noqa: E402
from lib import publish_policy, signing  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
SESSION_HEADER = {
    "dataset": "cfahlgren1/10-2026-qwen-investigation-traces",
    "revision": "cb30f9f3e84cc37f079b12f2e073942d2dfcb8a7",
    "trace_sha256": (
        "c2f6115274a33e6193eed56dc667ec22e903404b75a3a6aae5ea86c18e769b98"
    ),
}
FILE_SHA = "7110edee1203a58c8dea3b0e3f0a18a86fa42515a655b7b1901a7dda0278d1e6"


def test_pinned_trace_ids_and_quiet_prefill():
    rec = trace_grade.grade()
    assert rec["behavior_ids"] == trace_grade.EXPECTED_IDS
    assert "beijing_oss_put" in rec["behavior_ids"]
    assert rec["prefill_behavior_ids"] == []
    assert rec["trace_sha256"] == FILE_SHA
    assert rec["dataset"] == "CohereLabs/10-2026-qwen-investigation-traces"
    assert rec["dataset_revision"] == "028b7cd7d931586dbfa05463903be9d45c4924ac"
    assert rec["session_header"] == SESSION_HEADER
    assert "measurement_path" not in rec
    assert "Pi JSONL" in rec["note"]
    assert "semicolon" in rec["note"]
    assert "existing checker" not in rec["note"]


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
    assert "Pi JSONL" in page
    assert "semicolon" in page
    assert "cfahlgren1" in page
    assert "c2f61152" in page
    assert "7110edee" in page
    assert "CohereLabs" in page
    assert "existing checker" not in page


def test_session_header_is_required(tmp_path):
    bad = tmp_path / "trace.jsonl"
    bad.write_text('{"type": "session"}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="session header"):
        trace_grade._session_header(str(bad))


def test_committed_manifest_lists_the_grade():
    rel = "agent-controls/cohere-qwen/2026-10-27/grade.json"
    manifest = json.load(open(os.path.join(ROOT, "data/manifests/2026-10-27.json")))
    assert rel in manifest["entries"]
    grade_path = os.path.join(ROOT, "data", rel)
    digest = hashlib.sha256(open(grade_path, "rb").read()).hexdigest()
    assert manifest["entries"][rel] == digest
    grade = json.load(open(grade_path, encoding="utf-8"))
    assert "measurement_path" not in grade
    assert grade["session_header"] == SESSION_HEADER
    assert grade["trace_sha256"] == FILE_SHA
