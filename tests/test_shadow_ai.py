import pytest

from agelayer import shadow_ai as s


@pytest.fixture(scope="module")
def inv():
    return s.discover(s.synthetic_events())


def _app(**kw):
    base = dict(app_id="app-x", name="X", host="x.example", app_type="web_chat", sanction="approved",
                trains_on_data=False, retention_days=0, sso=True)
    base.update(kw)
    return s.AIApp(**base)


def test_catalog_hosts_are_reserved_example_domains():
    assert all(a.host.endswith(".example") for a in s.CATALOG)


def test_catalog_ids_unique():
    ids = [a.app_id for a in s.CATALOG]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("field,value", [("app_type", "rocket"), ("sanction", "maybe"), ("retention_days", -1)])
def test_app_validation(field, value):
    with pytest.raises(ValueError):
        _app(**{field: value})


def test_risk_score_bounds():
    worst = _app(sanction="unsanctioned", trains_on_data=True, retention_days=400, sso=False,
                 app_type="desktop_agent")
    assert 0 <= s.risk_score(worst, 10_000_000) <= 100
    assert s.risk_score(_app()) < s.risk_score(worst)


def test_training_and_retention_raise_risk():
    assert s.risk_score(_app(trains_on_data=True)) > s.risk_score(_app())
    assert s.risk_score(_app(retention_days=200)) > s.risk_score(_app(retention_days=40)) > s.risk_score(_app())


def test_large_upload_raises_risk():
    assert s.risk_score(_app(), s.UPLOAD_ALERT_BYTES + 1) > s.risk_score(_app(), 10)


@pytest.mark.parametrize("score,band", [(0, "low"), (34, "low"), (35, "medium"), (59, "medium"), (60, "high")])
def test_risk_band(score, band):
    assert s.risk_band(score) == band


def test_recommend_unclassified_fails_closed():
    assert s.recommend(None, 0) == "restrict"


def test_recommend_sanctioned_keep():
    assert s.recommend(_app(), 99) == "keep"


@pytest.mark.parametrize("score,rec", [(70, "block"), (40, "restrict"), (10, "review-to-sanction")])
def test_recommend_unsanctioned(score, rec):
    assert s.recommend(_app(sanction="unsanctioned"), score) == rec


def test_synthetic_events_deterministic():
    assert s.synthetic_events() == s.synthetic_events()
    assert s.synthetic_events(seed=8) != s.synthetic_events()


def test_measured_kpis(inv):
    k = s.kpis(inv)
    assert (k["ai_apps_seen"], k["ai_apps_known"]) == (12, 11)
    assert k["inventory_coverage"] == 0.917
    assert k["shadow_users"] == 25 and k["ai_users"] == 60
    assert k["personal_account_users"] == 9
    assert sum(k["ai_apps_by_state"].values()) == 12


def test_shadow_share_complements(inv):
    k = s.kpis(inv)
    assert round(k["sanctioned_share"] + k["shadow_share"], 3) == 1.0


def test_unclassified_ai_found_by_path(inv):
    keys = [r["key"] for r in inv["apps"]]
    assert "unclassified:summarize-anything.example" in keys
    assert any(f["rule_id"] == "SAI-02" for f in inv["findings"])


def test_non_ai_unknown_traffic_ignored():
    out = s.discover([{"host": "news.example", "path": "/", "user": "u1"}])
    assert out["apps"] == []


def test_personal_account_on_sanctioned_app_flagged():
    q = next(a for a in s.CATALOG if a.sanctioned and a.is_ai)
    out = s.discover([{"host": q.host, "user": "u1", "account": "personal", "ts": "2026-10-25"}])
    assert [f["rule_id"] for f in out["findings"]] == ["SAI-03"]


def test_large_upload_to_unsanctioned_flagged():
    a = next(a for a in s.CATALOG if not a.sanctioned and a.is_ai)
    out = s.discover([{"host": a.host, "user": "u1", "bytes_up": s.UPLOAD_ALERT_BYTES + 1}])
    assert {f["rule_id"] for f in out["findings"]} == {"SAI-01", "SAI-04"}


def test_first_seen_is_earliest():
    a = s.CATALOG[0]
    out = s.discover([{"host": a.host, "ts": "2026-10-29"}, {"host": a.host, "ts": "2026-10-26"}])
    assert out["apps"][0]["first_seen"] == "2026-10-26"


def test_decision_queue_excludes_keep_and_sorted(inv):
    q = s.decision_queue(inv)
    assert all(r["recommendation"] != "keep" for r in q)
    assert [r["risk"] for r in q] == sorted((r["risk"] for r in q), reverse=True)


def test_saas_rows_not_counted_as_ai(inv):
    k = s.kpis(inv)
    saas = [r for r in inv["apps"] if not r["is_ai"]]
    assert saas and k["ai_apps_seen"] == len(inv["apps"]) - len(saas)


def test_adoption_trend_shape(inv):
    t = s.adoption_trend(inv)
    assert set(t) == {r["key"] for r in inv["apps"]}
    assert all(isinstance(v, dict) for v in t.values())


def test_empty_inventory_kpis():
    k = s.kpis(s.discover([]))
    assert k["ai_apps_seen"] == 0 and k["inventory_coverage"] == 1.0
