import json
from pathlib import Path

import pytest

from agelayer.intent import IntentScope, evaluate

ROOT = Path(__file__).resolve().parents[1]


def test_scope_from_request():
    s = IntentScope.from_request("Summarise ticket TCK-101 for me")
    assert s.tools == {"read_tickets"} and s.max_category == "read" and s.resources == {"TCK-101"}


def test_empty_scope_fails_closed():
    d = IntentScope.from_request("hello there").check("read_logs")
    assert not d.in_scope and d.rule_id == "INTENT-04"


def test_tool_not_implied():
    d = IntentScope.from_request("Show me the open orders").check("read_logs")
    assert d.rule_id == "INTENT-01"


def test_resource_not_named():
    d = IntentScope.from_request("Fix invoice INV-31").check("write_invoice", {"invoice_id": "INV-32"})
    assert d.rule_id == "INTENT-02"


def test_resource_named_ok():
    d = IntentScope.from_request("Fix invoice INV-31").check("write_invoice", {"invoice_id": "INV-31"})
    assert d.in_scope


@pytest.mark.parametrize("tool", ["write_invoice", "deploy_service", "purge_cache", "drop_database"])
def test_write_during_read_request(tool):
    d = IntentScope.from_request("Show me the open orders").check(tool)
    assert d.rule_id == "INTENT-03"


def test_unknown_tool_treated_as_destructive():
    d = IntentScope.from_request("Clear the cache").check("format_disk")
    assert d.rule_id == "INTENT-01"
    d = IntentScope.from_request("Show the logs").check("format_disk")
    assert d.rule_id == "INTENT-03"


def test_widen_needs_human():
    s = IntentScope.from_request("Show the logs")
    for bad in ("", "agt-router"):
        with pytest.raises(PermissionError):
            s.widen("purge_cache", bad, "x")
    s.widen("purge_cache", "r.osei (security on-call)", "incident 42")
    assert s.check("purge_cache").in_scope and s.max_category == "destructive"
    assert s.widened[0]["approver"] == "r.osei (security on-call)"


def test_eval_set_measured():
    cases = json.loads((ROOT / "data/intent_eval.json").read_text())["cases"]
    r = evaluate(cases)
    assert (r["cases"], r["tp"], r["fp"], r["fn"], r["tn"]) == (30, 16, 1, 1, 12)


def test_known_misses_still_missed():
    """Kept on purpose: if one starts passing, update the docs' limitations list."""
    cases = json.loads((ROOT / "data/intent_eval.json").read_text())["cases"]
    known = [c for c in cases if c.get("known_miss")]
    r = evaluate(known)
    assert r["fp"] + r["fn"] == len(known) == 2


def test_evaluate_empty():
    assert evaluate([])["precision"] == 1.0
