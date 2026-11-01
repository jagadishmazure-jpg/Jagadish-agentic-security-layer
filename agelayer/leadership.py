"""Leadership KPI report (daily and weekly), shared shape across the AI security repos.

The same 24-KPI catalog is used in Jagadish-agentic-security-layer,
Jagadish-pii-guard and Jagadish-agent-security-redteam. Each repo *measures*
the KPIs it owns by running its own code on synthetic data. KPIs owned by
another repo are filled from ``data/leadership_feed_synthetic.json`` and are
labelled "synthetic sample (owned by <repo>)" so nobody mistakes them for a
measurement.

Outputs are Markdown, CSV and an HTML email preview written to ``reports/``.
Nothing is sent anywhere.
"""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass
from pathlib import Path

ASL = "agentic-security-layer"
PII = "pii-guard"
RT = "agent-security-redteam"
CSP = "continuous-security-program (planned)"

# id, name, definition, owner, cadence
KPI_CATALOG: list[tuple[str, str, str, str, str]] = [
    ("K01", "AI app inventory coverage", "known AI apps / AI apps seen in traffic; sanctioned vs shadow share of events", ASL, "daily"),
    ("K02", "Shadow AI users", "distinct users of unsanctioned or unclassified AI apps, by business unit", ASL, "daily"),
    ("K03", "High-risk prompt rate", "prompts with a block-level finding / all prompts", PII, "daily"),
    ("K04", "DLP actions by entity type", "warned, redacted and blocked counts by PII / secret / source code", PII, "daily"),
    ("K05", "Registered agent coverage", "registered active agents / distinct agents seen acting; open shadow-agent findings", ASL, "daily"),
    ("K06", "L2+ agents with owner and approval path", "agents at autonomy L2 or higher with a named owner and an approval path", ASL, "weekly"),
    ("K07", "Out-of-intent action attempts", "tool calls outside the user's request, and the share blocked", ASL, "daily"),
    ("K08", "Budget breaches", "sessions stopped by step, token, cost or loop limits; tokens and cost avoided", ASL, "daily"),
    ("K09", "MCP posture", "unapproved MCP servers seen, description drift events, poisoned descriptions", ASL, "daily"),
    ("K10", "Red-team attack success rate", "attack success rate by OWASP category and change since the last release", RT, "weekly"),
    ("K11", "Mean time to fix an AI finding", "red-team finding opened -> fix verified by replay", RT, "weekly"),
    ("K12", "Proven exposures vs raw findings", "share of findings proven exploitable; the rest are noise", CSP, "weekly"),
    ("K13", "MTTSR and zero-disruption rate", "mean time to safe remediation; share of fixes with no service impact", CSP, "weekly"),
    ("K14", "Human approval latency and override rate", "median minutes from AI-proposed action to human decision; share rejected or changed", ASL, "weekly"),
    ("K15", "AI tools by sanction state", "AI tools seen, split approved / monitored / unsanctioned / unclassified", ASL, "weekly"),
    ("K16", "Personal-account AI use", "share of sanctioned-app AI events made from personal (non-corporate) logins", ASL, "daily"),
    ("K17", "New unsanctioned tools this week", "unsanctioned or unclassified AI tools first seen in the last 7 days", ASL, "weekly"),
    ("K18", "First-seen to decision time", "median days from an AI tool first being seen to an approve / restrict / block decision", ASL, "weekly"),
    ("K19", "DLP findings per 1,000 prompts", "sensitive-data findings per 1,000 prompts, by type and by destination app", PII, "daily"),
    ("K20", "DLP outcome mix and false blocks", "% warned / redacted / blocked; false-block rate (overrides upheld on review)", PII, "weekly"),
    ("K21", "Blocked paste and upload events", "blocked paste / upload events to unapproved destinations; top destinations", PII, "daily"),
    ("K22", "Browser extension risk", "extensions in use, % with high-risk permissions, % blocked, mean days to remove", ASL, "weekly"),
    ("K23", "AI seat utilisation", "active users per sanctioned AI tool / paid seats", ASL, "weekly"),
    ("K24", "Telemetry coverage", "share of the workforce seen by at least one AI-usage telemetry source", ASL, "weekly"),
]
KPI_IDS = [k[0] for k in KPI_CATALOG]


@dataclass
class KPIRow:
    kpi_id: str
    name: str
    value: str
    detail: str
    source: str
    owner: str


def fmt(v) -> str:
    if isinstance(v, float):
        return f"{v:.1%}" if 0 <= v <= 1 else f"{v:,.2f}"
    if isinstance(v, int):
        return f"{v:,}"
    return str(v)


def load_feed(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text())
    if "synthetic" not in data.get("label", "").lower():
        raise ValueError("feed must be labelled synthetic")
    return data


def build(measured: dict[str, tuple], feed: dict, this_repo: str,
          cadence: str = "weekly") -> list[KPIRow]:
    """measured: {kpi_id: (value, detail)} from this repo's own run."""
    if cadence not in ("daily", "weekly"):
        raise ValueError("cadence must be daily or weekly")
    unknown = set(measured) - set(KPI_IDS)
    if unknown:
        raise KeyError(f"unknown KPI ids {sorted(unknown)}")
    rows = []
    for kid, name, _definition, owner, kcad in KPI_CATALOG:
        if cadence == "daily" and kcad != "daily":
            continue
        if kid in measured:
            v, d = measured[kid]
            rows.append(KPIRow(kid, name, fmt(v), d, "measured: this repo, synthetic data", owner))
        elif kid in feed.get("kpis", {}):
            f = feed["kpis"][kid]
            rows.append(KPIRow(kid, name, fmt(f["value"]), f.get("detail", ""),
                               f"synthetic sample (owned by {owner})", owner))
        else:
            rows.append(KPIRow(kid, name, "n/a", "no source yet", "missing", owner))
    return rows


def to_markdown(rows: list[KPIRow], title: str, as_of: str) -> str:
    out = [f"# {title}", "", f"As of {as_of}. All data is synthetic. "
           "\"measured\" rows come from running this repo's code; \"synthetic sample\" rows are "
           "placeholders for KPIs another repo owns.", "",
           "| KPI | Name | Value | Detail | Source |", "| --- | --- | --- | --- | --- |"]
    for r in rows:
        out.append(f"| {r.kpi_id} | {r.name} | {r.value} | {r.detail} | {r.source} |")
    return "\n".join(out) + "\n"


def to_csv(rows: list[KPIRow]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["kpi_id", "name", "value", "detail", "source", "owner"])
    for r in rows:
        w.writerow([r.kpi_id, r.name, r.value, r.detail, r.source, r.owner])
    return buf.getvalue()


def to_html(rows: list[KPIRow], title: str, as_of: str) -> str:
    """Email-style HTML preview. Saved to disk only; this module never sends mail."""
    e = html.escape
    trs = "".join(
        f"<tr><td>{e(r.kpi_id)}</td><td>{e(r.name)}</td><td><b>{e(r.value)}</b></td>"
        f"<td>{e(r.detail)}</td><td><i>{e(r.source)}</i></td></tr>" for r in rows)
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{e(title)}</title></head>"
            f"<body style='font-family:sans-serif'><h2>{e(title)}</h2>"
            f"<p>As of {e(as_of)}. Synthetic data. Preview only; not sent.</p>"
            f"<table border='1' cellpadding='4' cellspacing='0'><tr><th>KPI</th><th>Name</th>"
            f"<th>Value</th><th>Detail</th><th>Source</th></tr>{trs}</table></body></html>\n")


def write_reports(rows_daily, rows_weekly, out_dir: str | Path, repo: str, as_of: str) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for cad, rows in (("daily", rows_daily), ("weekly", rows_weekly)):
        title = f"{repo}: {cad} AI security leadership report"
        for ext, body in (("md", to_markdown(rows, title, as_of)), ("csv", to_csv(rows)),
                          ("html", to_html(rows, title, as_of))):
            p = out / f"leadership_{cad}.{ext}"
            p.write_text(body)
            paths.append(p)
    return paths
