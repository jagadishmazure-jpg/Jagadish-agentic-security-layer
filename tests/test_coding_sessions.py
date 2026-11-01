import pytest

from agelayer import coding_sessions as c
from agelayer import secrets_scan as ss
from agelayer.scenarios import coding_scenario

KINDS = ["cloud_access_key", "git_token", "chat_bot_token", "private_key", "generic_secret"]


@pytest.mark.parametrize("kind", KINDS[:4])
def test_fake_secrets_detected(kind):
    assert [h[0] for h in ss.find_secrets("x " + ss.fake_secret(kind) + " y")] == [kind]


def test_generic_secret_needs_assignment_and_entropy():
    v = ss.fake_secret("generic_secret")
    assert ss.find_secrets(f'api_key = "{v}"')[0][0] == "generic_secret"
    assert ss.find_secrets(v) == []
    assert ss.find_secrets('password = "aaaaaaaaaaaaaaaaaaaa"') == []
    assert ss.find_secrets('token = "changeme-changeme-123"') == []


def test_fake_secret_deterministic_and_unknown():
    assert ss.fake_secret("git_token", 3) == ss.fake_secret("git_token", 3)
    with pytest.raises(ValueError):
        ss.fake_secret("nope")


def test_entropy_edges():
    assert ss.entropy("") == 0.0 and ss.entropy("aaaa") == 0.0
    assert ss.entropy("abcd") == 2.0


def _session(turns, app="app-stackwise"):
    return {"session_id": "t", "agent_id": "agt-x", "app_id": app, "turns": turns}


def test_clean_session():
    r = c.guard_session(_session([{"role": "user", "content": "rename a variable"}]))
    assert r["findings"] == [] and r["turns_sent"] == 1


@pytest.mark.parametrize("path", ["app/.env", "deploy/prod.env", "keys/server.pem", "home/id_rsa",
                                  "cfg/credentials", "x/secrets.json"])
def test_secret_files_blocked(path):
    r = c.guard_session(_session([{"role": "context", "file": path, "content": "x"}]))
    assert r["findings"][0]["rule_id"] == "CSG-02" and r["blocked_turns"] == [0]


def test_normal_file_not_blocked():
    r = c.guard_session(_session([{"role": "context", "file": "src/envelope.py", "content": "x"}]))
    assert r["findings"] == []


def test_restricted_code_needs_approved_assistant():
    turn = [{"role": "context", "file": "payments/ledger.py", "content": "x"}]
    assert c.guard_session(_session(turn))["findings"] == []
    r = c.guard_session(_session(turn, app="app-gitmuse"))
    assert {f["rule_id"] for f in r["findings"]} == {"CSG-03", "CSG-05"}


def test_model_reply_not_scanned():
    r = c.guard_session(_session([{"role": "assistant", "content": ss.fake_secret("git_token")}]))
    assert r["findings"] == []


def test_findings_never_contain_secret_values():
    secret = ss.fake_secret("cloud_access_key", 9)
    r = c.guard_session(_session([{"role": "user", "content": "use " + secret}]))
    assert secret not in repr(r)


def test_unregistered_agent_flagged_with_registry():
    from agelayer.demo_helpers import build_demo_db
    r = c.guard_session(_session([]), conn=build_demo_db())
    assert r["findings"][0]["rule_id"] == "CSG-04"


def test_demo_scenario_measured():
    out = coding_scenario()
    assert [s["blocked_turns"] for s in out] == [[], [0, 1], [0, 1]]
    assert {f["rule_id"] for f in out[2]["findings"]} == {"CSG-01", "CSG-03", "CSG-04", "CSG-05"}
