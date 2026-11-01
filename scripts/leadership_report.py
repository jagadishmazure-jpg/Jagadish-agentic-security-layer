"""Write daily and weekly leadership KPI reports (Markdown, CSV, HTML preview) to reports/.

Measured KPIs come from this repo's code on synthetic data; KPIs owned by
other repos come from data/leadership_feed_synthetic.json and are labelled.
Prints the weekly Markdown table. Nothing is emailed.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agelayer import leadership  # noqa: E402
from agelayer.scenarios import AS_OF, kpi_measurements  # noqa: E402

measured = kpi_measurements()
feed = leadership.load_feed(ROOT / "data/leadership_feed_synthetic.json")
daily = leadership.build(measured, feed, leadership.ASL, "daily")
weekly = leadership.build(measured, feed, leadership.ASL, "weekly")
leadership.write_reports(daily, weekly, ROOT / "reports", "Jagadish-agentic-security-layer", AS_OF)
print(leadership.to_markdown(weekly, "Weekly AI security leadership report", AS_OF).rstrip())
