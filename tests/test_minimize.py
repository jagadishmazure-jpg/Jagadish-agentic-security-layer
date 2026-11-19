"""Context-minimization checks (MIN-01/02): deny-by-default field
profiles, nested dot paths, and a report that names dropped fields
without ever carrying their values.
"""

import json

import pytest

from agelayer import minimize as min_mod

CRM_RECORD = {
    "customer_name": "Acme Corp",
    "contract_end": "2027-03-31",
    "renewal_date": "2027-03-01",
    "billing": {"card_last4": "4242", "iban": "DE00-SECRET-IBAN"},
    "internal_notes": "SECRET-NOTE: churn risk, do not share",
    "contacts": ["ops@acme.example"],
}

PROFILES = {
    "renewal_lookup": {"customer_name", "contract_end", "renewal_date"},
}


def test_minimize_only_allowed_fields_pass():
    mz = min_mod.ContextMinimizer(PROFILES)
    out, report = mz.minimize("renewal_lookup", CRM_RECORD)
    assert out == {"customer_name": "Acme Corp",
                   "contract_end": "2027-03-31",
                   "renewal_date": "2027-03-01"}
    assert report.kept == ["contract_end", "customer_name", "renewal_date"]


def test_minimize_drops_sensitive_extras():
    mz = min_mod.ContextMinimizer(PROFILES)
    out, report = mz.minimize("renewal_lookup", CRM_RECORD)
    assert "billing" not in out
    assert "internal_notes" not in out
    assert "contacts" not in out
    assert "billing.card_last4" in report.dropped
    assert "billing.iban" in report.dropped
    assert "internal_notes" in report.dropped
    assert "contacts" in report.dropped


def test_minimize_nested_dot_path_allow_and_drop():
    mz = min_mod.ContextMinimizer(
        {"deal_lookup": {"customer_name", "contract.end_date"}})
    record = {"customer_name": "Acme Corp",
              "contract": {"start_date": "2026-04-01",
                           "end_date": "2027-03-31",
                           "value": 50000}}
    out, report = mz.minimize("deal_lookup", record)
    assert out == {"customer_name": "Acme Corp",
                   "contract": {"end_date": "2027-03-31"}}
    assert "contract.end_date" in report.kept
    assert "contract.start_date" in report.dropped
    assert "contract.value" in report.dropped


def test_minimize_parent_path_keeps_whole_subtree():
    mz = min_mod.ContextMinimizer({"full_contract": {"contract"}})
    record = {"contract": {"start_date": "2026-04-01",
                           "end_date": "2027-03-31"},
              "internal_notes": "hidden"}
    out, report = mz.minimize("full_contract", record)
    assert out == {"contract": {"start_date": "2026-04-01",
                                "end_date": "2027-03-31"}}
    assert report.dropped == ["internal_notes"]


def test_minimize_unknown_profile_strict_denied():
    mz = min_mod.ContextMinimizer(PROFILES, strict=True)
    with pytest.raises(min_mod.MinimizeDenied) as e:
        mz.minimize("salary_lookup", CRM_RECORD)
    assert e.value.policy_id == "MIN-01"


def test_minimize_unknown_profile_non_strict_empty():
    mz = min_mod.ContextMinimizer(PROFILES, strict=False)
    out, report = mz.minimize("salary_lookup", CRM_RECORD)
    assert out == {}
    assert report.kept == []
    assert set(report.dropped) == {
        "customer_name", "contract_end", "renewal_date",
        "billing.card_last4", "billing.iban", "internal_notes",
        "contacts"}


def test_minimize_report_names_fields_never_values():
    mz = min_mod.ContextMinimizer(PROFILES)
    _out, report = mz.minimize("renewal_lookup", CRM_RECORD)
    blob = json.dumps(report.as_dict()) + repr(report)
    assert "internal_notes" in blob          # the NAME is reported
    assert "SECRET-NOTE" not in blob         # the VALUE never is
    assert "DE00-SECRET-IBAN" not in blob
    assert "4242" not in blob


def test_minimize_non_dict_record_rejected():
    mz = min_mod.ContextMinimizer(PROFILES)
    for bad in (["customer_name"], "a string", None, 42):
        with pytest.raises(min_mod.MinimizeDenied) as e:
            mz.minimize("renewal_lookup", bad)
        assert e.value.policy_id == "MIN-02"


def test_minimize_missing_allowed_field_is_skipped():
    mz = min_mod.ContextMinimizer(PROFILES)
    out, report = mz.minimize("renewal_lookup",
                              {"customer_name": "Acme Corp"})
    assert out == {"customer_name": "Acme Corp"}
    assert report.kept == ["customer_name"]
    assert report.dropped == []


def test_minimize_empty_record():
    mz = min_mod.ContextMinimizer(PROFILES)
    out, report = mz.minimize("renewal_lookup", {})
    assert out == {}
    assert report.kept == [] and report.dropped == []


def test_minimize_does_not_mutate_source_record():
    mz = min_mod.ContextMinimizer(PROFILES)
    record = dict(CRM_RECORD)
    mz.minimize("renewal_lookup", record)
    assert record == CRM_RECORD
