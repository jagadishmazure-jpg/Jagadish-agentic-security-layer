import pytest

from agelayer.budget import Budget, BudgetStop, KillSwitch, Meter, cost_usd


def test_budget_validation():
    for kw in ({"max_steps": 0}, {"max_tokens": -1}, {"max_cost_usd": 0}):
        with pytest.raises(ValueError):
            Budget(**kw)


def test_cost_unknown_model_uses_priciest():
    assert cost_usd("mystery", 1000, 1000) == cost_usd("fm-large-1", 1000, 1000)
    assert cost_usd("fm-small-1", 1000, 0) < cost_usd("fm-large-1", 1000, 0)


def test_step_cap():
    m = Meter(Budget(max_steps=2))
    for i in range(2):
        m.pre_check("t", {"i": i})
        m.account("fm-small-1", 1, 1)
    with pytest.raises(BudgetStop) as e:
        m.pre_check("t", {"i": 9})
    assert e.value.rule_id == "BUDGET-01"


def test_token_cap():
    m = Meter(Budget(max_tokens=100))
    m.pre_check("t", {})
    m.account("fm-small-1", 150, 0)
    with pytest.raises(BudgetStop) as e:
        m.post_check()
    assert e.value.rule_id == "BUDGET-02"


def test_cost_cap():
    m = Meter(Budget(max_cost_usd=0.01, max_tokens=10**9))
    m.pre_check("t", {})
    m.account("fm-large-1", 10_000, 0)
    with pytest.raises(BudgetStop) as e:
        m.post_check()
    assert e.value.rule_id == "BUDGET-03"


def test_loop_same_call():
    m = Meter(Budget())
    m.pre_check("t", {"a": 1})
    m.pre_check("t", {"a": 1})
    with pytest.raises(BudgetStop) as e:
        m.pre_check("t", {"a": 1})
    assert e.value.rule_id == "LOOP-01"


def test_loop_oscillation():
    m = Meter(Budget())
    m.pre_check("a", {})
    m.pre_check("b", {})
    m.pre_check("a", {})
    with pytest.raises(BudgetStop) as e:
        m.pre_check("b", {})
    assert e.value.rule_id == "LOOP-02"


def test_varied_args_not_a_loop():
    m = Meter(Budget())
    for i in range(10):
        m.pre_check("t", {"page": i})


def test_stopped_stays_stopped_until_human_reset():
    m = Meter(Budget(max_steps=1))
    m.pre_check("t", {})
    m.account("fm-small-1", 1, 1)
    with pytest.raises(BudgetStop):
        m.pre_check("t", {"x": 1})
    with pytest.raises(BudgetStop):
        m.pre_check("other", {})
    for bad in ("", "agt-x"):
        with pytest.raises(PermissionError):
            m.reset(bad)
    m.reset("r.osei (security on-call)")
    assert m.stopped is None


def test_negative_tokens_rejected():
    with pytest.raises(ValueError):
        Meter(Budget()).account("fm-small-1", -1, 0)


def test_kill_switch_global_and_agent():
    k = KillSwitch()
    k.check("a")
    k.trip("r.osei", agent_id="a")
    with pytest.raises(BudgetStop):
        k.check("a")
    k.check("b")
    k.trip("r.osei")
    with pytest.raises(BudgetStop) as e:
        k.check("b")
    assert e.value.rule_id == "KILL-01"


def test_kill_switch_unreadable_fails_closed():
    k = KillSwitch()

    def boom():
        raise RuntimeError("down")
    k.reader = boom
    with pytest.raises(BudgetStop) as e:
        k.check("a")
    assert e.value.rule_id == "KILL-02"


def test_kill_reset_needs_human():
    k = KillSwitch()
    k.trip("x")
    with pytest.raises(PermissionError):
        k.reset("agt-auto")
    k.reset("r.osei")
    k.check("a")
    k.trip("x", agent_id="a")
    k.reset("r.osei", agent_id="a")
    k.check("a")
    assert len(k.events) == 2
