import pytest

from agelayer import extensions as e


def ext(**kw):
    base = dict(ext_id="x", name="X", permissions=["storage"], users=1)
    base.update(kw)
    return e.Extension(**base)


def test_low_risk_allowed():
    s, rules = e.score(ext())
    assert rules == [] and e.recommend(ext(), s) == "allow"


@pytest.mark.parametrize("perm", sorted(e.HIGH_RISK))
def test_high_risk_permission_flagged_and_reviewed(perm):
    x = ext(permissions=[perm])
    s, rules = e.score(x)
    assert "EXT-01" in rules
    assert e.recommend(x, s) in ("allow-with-review", "block")


def test_sideloaded_flagged():
    assert "EXT-02" in e.score(ext(from_store=False))[1]


def test_stale_flagged():
    assert "EXT-02" in e.score(ext(last_update="2024-01-01"))[1]


def test_ai_remote_flagged():
    assert "EXT-03" in e.score(ext(ai_remote=True))[1]


def test_unknown_permission_weighted():
    assert e.score(ext(permissions=["mysteryPerm"]))[0] == 10


def test_score_capped():
    x = ext(permissions=list(e.PERMISSION_WEIGHTS) + ["a", "b"], from_store=False, ai_remote=True)
    assert e.score(x)[0] == 100


def test_duplicate_permissions_counted_once():
    assert e.score(ext(permissions=["cookies", "cookies"]))[0] == 20


def test_corporate_force_installed():
    x = ext(corporate=True, permissions=["<all_urls>", "cookies", "webRequest"])
    assert e.recommend(x, e.score(x)[0]) == "force-install"


def test_demo_assessment_sorted_and_blocks():
    rows = e.assess(e.demo_inventory())
    assert [r["score"] for r in rows] == sorted((r["score"] for r in rows), reverse=True)
    assert {r["ext_id"] for r in rows if r["recommendation"] == "block"} == {"ext-coupon", "ext-draftbird", "ext-devtool"}


def test_sign_off_needs_human():
    row = next(r for r in e.assess(e.demo_inventory()) if r["recommendation"] == "block")
    for bad in ("", "  ", "agt-cleaner"):
        with pytest.raises(PermissionError):
            e.sign_off_block(row, bad, "2026-10-31")
    assert e.sign_off_block(row, "t.mensah (IT)", "2026-10-31").owner == "t.mensah (IT)"


def test_sign_off_only_for_blocks():
    row = next(r for r in e.assess(e.demo_inventory()) if r["recommendation"] == "allow")
    with pytest.raises(ValueError):
        e.sign_off_block(row, "t.mensah (IT)", "2026-10-31")


def test_kpis_measured():
    k = e.kpis(e.demo_inventory())
    assert k == {"extensions": 9, "high_risk_share": 0.444, "blocked_share": 0.222,
                 "block_recommended": 3, "mean_days_to_remove": 2.0}


def test_kpis_empty():
    assert e.kpis([])["mean_days_to_remove"] is None
