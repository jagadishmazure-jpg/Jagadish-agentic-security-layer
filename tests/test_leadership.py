import csv
import io
import subprocess
import sys
from pathlib import Path

import pytest

from agelayer import leadership as L
from agelayer.scenarios import kpi_measurements

ROOT = Path(__file__).resolve().parents[1]
FEED = L.load_feed(ROOT / "data/leadership_feed_synthetic.json")


@pytest.fixture(scope="module")
def measured():
    return kpi_measurements()


def test_catalog_has_24_unique_kpis():
    assert len(L.KPI_IDS) == 24 == len(set(L.KPI_IDS))
    assert L.KPI_IDS[:14] == [f"K{i:02d}" for i in range(1, 15)]


def test_this_repo_measures_what_it_owns(measured):
    owned = {k for k, *_rest in L.KPI_CATALOG if _rest[2] == L.ASL}
    assert owned == set(measured)


def test_feed_covers_everything_and_is_labelled():
    not_ours = {k for k, *rest in L.KPI_CATALOG if rest[2] != L.ASL}
    assert not_ours <= set(FEED["kpis"])
    assert "synthetic" in FEED["label"]


def test_feed_must_be_labelled(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('{"label": "real numbers", "kpis": {}}')
    with pytest.raises(ValueError):
        L.load_feed(p)


def test_build_labels_sources(measured):
    rows = L.build(measured, FEED, L.ASL)
    src = {r.kpi_id: r.source for r in rows}
    assert src["K01"].startswith("measured") and src["K03"].startswith("synthetic sample (owned by pii-guard)")
    assert src["K12"].startswith("synthetic sample (owned by continuous-security-program")


def test_measured_values(measured):
    v = {r.kpi_id: r.value for r in L.build(measured, FEED, L.ASL)}
    assert v["K01"] == "91.7%" and v["K02"] == "25" and v["K06"] == "66.7%" and v["K07"] == "6"
    assert v["K23"] == "75.9%" and v["K24"] == "93.8%"


def test_daily_subset(measured):
    d = L.build(measured, FEED, L.ASL, "daily")
    w = L.build(measured, FEED, L.ASL, "weekly")
    assert len(w) == 24 and 0 < len(d) < 24
    assert {r.kpi_id for r in d} <= {r.kpi_id for r in w}


def test_missing_source():
    rows = L.build({}, {"kpis": {}}, L.ASL)
    assert all(r.source == "missing" for r in rows)


def test_bad_cadence_and_unknown_kpi():
    with pytest.raises(ValueError):
        L.build({}, FEED, L.ASL, "monthly")
    with pytest.raises(KeyError):
        L.build({"K99": (1, "")}, FEED, L.ASL)


@pytest.mark.parametrize("v,s", [(0.5, "50.0%"), (12, "12"), (1234, "1,234"), (2.5, "2.50"), ("x", "x")])
def test_fmt(v, s):
    assert L.fmt(v) == s


def test_csv_and_html(measured):
    rows = L.build(measured, FEED, L.ASL)
    parsed = list(csv.DictReader(io.StringIO(L.to_csv(rows))))
    assert len(parsed) == 24 and parsed[0]["kpi_id"] == "K01"
    h = L.to_html([L.KPIRow("K01", "<b>", "1", "&", "s", "o")], "T", "2026-10-31")
    assert "&lt;b&gt;" in h and "not sent" in h


def test_committed_reports_match_fresh_run(tmp_path):
    """reports/ is deterministic: regenerate and compare with the committed copy."""
    import shutil
    work = tmp_path / "repo"
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "reports"))
    subprocess.run([sys.executable, "scripts/leadership_report.py"], cwd=work, check=True,
                   capture_output=True, env={"PYTHONHASHSEED": "0", "PATH": ""})
    for f in sorted((ROOT / "reports").glob("leadership_*")):
        assert (work / "reports" / f.name).read_text() == f.read_text(), f.name
