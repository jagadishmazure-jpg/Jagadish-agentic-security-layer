import pytest

from agelayer import browser_policy as b
from agelayer.shadow_ai import CATALOG


def host(state):
    return next(a.host for a in CATALOG if a.sanction == state and a.is_ai)


@pytest.fixture
def eng():
    return b.BrowserPolicyEngine(agent_ids={"agt-router"})


@pytest.mark.parametrize("state,action", [("approved", "allow"), ("monitored", "warn"), ("unsanctioned", "warn")])
def test_state_defaults(eng, state, action):
    d = eng.evaluate({"host": host(state), "group": "sales"})
    assert (d.state, d.action) == (state, action)


def test_unclassified_is_warned_and_named(eng):
    d = eng.evaluate({"host": "brand-new-ai.example", "group": "sales"})
    assert d.state == "unclassified" and d.action == "warn"
    assert d.app_key == "unclassified:brand-new-ai.example"


def test_personal_login_on_approved_app(eng):
    d = eng.evaluate({"host": host("approved"), "group": "sales", "login_domain": "mail.example"})
    assert d.state == "personal" and "BPOL-04" in d.rules


def test_personal_on_unsanctioned_stays_unsanctioned(eng):
    d = eng.evaluate({"host": host("unsanctioned"), "group": "sales", "login_domain": "mail.example"})
    assert d.state == "unsanctioned"


@pytest.mark.parametrize("group", ["finance", "hr"])
@pytest.mark.parametrize("state", ["unsanctioned", "unclassified"])
def test_sensitive_groups_block(eng, group, state):
    h = host(state) if state != "unclassified" else "new-ai.example"
    d = eng.evaluate({"host": h, "group": group})
    assert d.action == "block" and "BPOL-02" in d.rules


def test_finance_approved_still_allowed(eng):
    assert eng.evaluate({"host": host("approved"), "group": "finance"}).action == "allow"


@pytest.mark.parametrize("state,action", [("approved", "redact"), ("monitored", "redact"), ("unsanctioned", "block")])
def test_sensitive_content(eng, state, action):
    d = eng.evaluate({"host": host(state), "group": "sales", "sensitive": True})
    assert d.action == action and "BPOL-03" in d.rules


def test_stricter_never_loosens():
    for a in b.ACTIONS:
        for c in b.ACTIONS:
            assert b._RANK[b.stricter(a, c)] == max(b._RANK[a], b._RANK[c])


def test_unknown_state_default_fails_closed():
    pol = {"state_defaults": {}, "group_overrides": {}, "sensitive": {}}
    e = b.BrowserPolicyEngine(policy=pol)
    assert e.evaluate({"host": host("approved")}).action == "block"


def test_policy_change_needs_other_human(eng):
    app = next(a.app_id for a in CATALOG if a.sanction == "unsanctioned")
    cid = eng.propose(app, "approved", "j.okafor", "contract signed")
    for bad in ("", "j.okafor", "agt-router", "agt-anything"):
        with pytest.raises(PermissionError):
            eng.approve(cid, bad)
    ch = eng.approve(cid, "l.nakamura (CISO)")
    assert ch.status == "approved"
    assert eng.evaluate({"host": next(a.host for a in CATALOG if a.app_id == app)}).state == "approved"


def test_policy_change_cannot_be_approved_twice(eng):
    app = CATALOG[0].app_id
    cid = eng.propose(app, "monitored", "j.okafor", "x")
    eng.approve(cid, "l.nakamura (CISO)")
    with pytest.raises(PermissionError):
        eng.approve(cid, "someone else")


def test_proposal_does_not_apply_before_approval(eng):
    app = next(a for a in CATALOG if a.sanction == "unsanctioned")
    eng.propose(app.app_id, "approved", "j.okafor", "x")
    assert eng.evaluate({"host": app.host}).state == "unsanctioned"


@pytest.mark.parametrize("bad", ["personal", "unclassified", "yolo"])
def test_propose_rejects_bad_state(eng, bad):
    with pytest.raises(ValueError):
        eng.propose(CATALOG[0].app_id, bad, "x", "y")


def test_propose_unknown_app(eng):
    with pytest.raises(KeyError):
        eng.propose("app-nope", "approved", "x", "y")


def test_synthetic_summary_counts():
    e = b.BrowserPolicyEngine()
    for ev in b.synthetic_browser_events():
        e.evaluate(ev)
    sm = e.summary()
    assert sm["total"] == 400 == sum(sm["actions"].values()) == sum(sm["by_state"].values())
    assert sm["actions"] == {"allow": 133, "warn": 149, "redact": 17, "block": 101}
