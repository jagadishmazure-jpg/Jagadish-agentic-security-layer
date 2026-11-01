import pytest

from agelayer import effective, registry, risk_card
from agelayer.demo_helpers import TOOL_CATALOG, build_demo_db


@pytest.fixture
def conn():
    c = build_demo_db()
    effective.init_db(c)
    effective.seed_effective(c)
    return c


def test_demo_cards(conn):
    cards = {c["agent_id"]: c for c in risk_card.demo_cards(conn, TOOL_CATALOG)}
    assert cards["agt-deployer"]["tier"] == "critical"
    assert cards["agt-deployer"]["flags"] == ["RISK-02", "RISK-03", "RISK-04", "RISK-05", "RISK-06"]
    assert cards["agt-biller"]["flags"] == ["RISK-04"]


def test_missing_owner_flag():
    c = build_demo_db()
    registry.register_agent(c, "agt-orphan", "Orphan", "fm-small-1", ["read_logs"], ["logs"], 2, "")
    card = risk_card.build_card(c, "agt-orphan", TOOL_CATALOG)
    assert {"RISK-01", "RISK-02"} <= set(card["flags"]) and card["owner"] is None


def test_l1_needs_no_approval_path():
    c = build_demo_db()
    card = risk_card.build_card(c, "agt-router", TOOL_CATALOG)
    assert "RISK-02" not in card["flags"]


def test_fallback_without_groups_table():
    card = risk_card.build_card(build_demo_db(), "agt-router", TOOL_CATALOG)
    assert card["indirect_tools"] == []


def test_unknown_agent():
    with pytest.raises(KeyError):
        risk_card.build_card(build_demo_db(), "agt-nope", TOOL_CATALOG)


def test_asr_threshold(conn):
    lo = risk_card.build_card(conn, "agt-biller", TOOL_CATALOG, redteam_asr={"agt-biller": 0.10})
    hi = risk_card.build_card(conn, "agt-biller", TOOL_CATALOG, redteam_asr={"agt-biller": 0.11})
    assert "RISK-05" not in lo["flags"] and "RISK-05" in hi["flags"]


def test_governed_share(conn):
    g = risk_card.governed_share(risk_card.demo_cards(conn, TOOL_CATALOG))
    assert g == {"l2_plus": 3, "with_owner_and_path": 2, "share": 0.667, "gaps": ["agt-deployer"]}


def test_governed_share_empty():
    assert risk_card.governed_share([])["share"] == 1.0


def test_markdown_marks_missing(conn):
    card = risk_card.build_card(conn, "agt-deployer", TOOL_CATALOG)
    md = risk_card.render_markdown(card)
    assert "**missing**" in md and "agt-deployer" in md


def test_score_capped(conn):
    card = risk_card.build_card(conn, "agt-deployer", TOOL_CATALOG, mcp_grants={"agt-deployer": ["evil"]},
                                redteam_asr={"agt-deployer": 1.0})
    assert card["score"] <= 100
