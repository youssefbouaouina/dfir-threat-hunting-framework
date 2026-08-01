"""
Flask dashboard: reads findings from dfir.db and shows them as an HTML
page with severity color-coding and a top summary section.

Setup:
    pip install flask --break-system-packages
    python load_findings.py          # populates dfir.db
    python attack_mapping.py         # fills in ATT&CK mapping
    python dashboard.py              # starts the server

Then open http://127.0.0.1:5000 in a browser.
"""

import json
import sqlite3
from datetime import datetime, timezone

from flask import Flask, Response, request

app = Flask(__name__)

DB_PATH = "dfir.db"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

SEVERITY_COLORS = {
    "critical": "#8b0000",  # dark red
    "high": "#d9534f",      # red
    "medium": "#f0ad4e",    # orange
    "low": "#5bc0de",       # blue
}

# Simple recommended-action lookup by source type. This is deliberately
# generic for now -- as real Sigma/YARA rules get added, this can grow
# into a per-rule_id lookup similar to ATTACK_MAP in attack_mapping.py.
RECOMMENDATIONS = {
    "yara": "Isolate the host and collect the flagged file/process for deeper malware analysis.",
    "sigma": "Review the surrounding log timeline for this host to confirm intent before escalating.",
    "ioc_match": "Block the matched indicator at the network/EDR level and check for lateral spread.",
}


def get_findings(artifact_type=None, source=None):
    """Fetch findings, optionally filtered by artifact_type and/or source.
    Filtering happens in SQL rather than in Python so this stays cheap
    even if the findings table grows large."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if artifact_type:
        query += " AND artifact_type = ?"
        params.append(artifact_type)
    if source:
        query += " AND source = ?"
        params.append(source)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_filter_options():
    """Distinct artifact_type and source values currently in the DB, used
    to populate the filter dropdowns without hardcoding a list that could
    drift out of sync with real data."""
    conn = sqlite3.connect(DB_PATH)
    artifact_types = [r[0] for r in conn.execute(
        "SELECT DISTINCT artifact_type FROM findings ORDER BY artifact_type"
    ).fetchall()]
    sources = [r[0] for r in conn.execute(
        "SELECT DISTINCT source FROM findings ORDER BY source"
    ).fetchall()]
    conn.close()
    return artifact_types, sources


def render_summary(grouped):
    """Top-of-page summary: counts per severity, color-coded."""
    parts = ['<div class="summary">']
    for severity in SEVERITY_ORDER:
        count = len(grouped.get(severity, []))
        color = SEVERITY_COLORS[severity]
        parts.append(
            f'<div class="summary-box" style="background:{color}">'
            f'<div class="summary-count">{count}</div>'
            f'<div class="summary-label">{severity.upper()}</div>'
            f'</div>'
        )
    parts.append("</div>")
    return "".join(parts)


def render_finding(f):
    mapping = json.loads(f["attack_mapping_json"]) if f["attack_mapping_json"] else None
    technique = (
        f"{mapping['technique_id']} &mdash; {mapping['technique_name']} "
        f'<span class="tactic">({mapping["tactic"]})</span>'
        if mapping
        else "not mapped yet"
    )
    recommendation = RECOMMENDATIONS.get(
        f["source"], "Review manually and triage based on context."
    )
    color = SEVERITY_COLORS.get(f["severity"], "#999")

    confidence = f.get("confidence")
    confidence_html = (
        f'<span class="confidence">Confidence: {round(confidence * 100)}%</span>'
        if confidence is not None
        else ""
    )

    return (
        f'<div class="finding" style="border-left: 5px solid {color}">'
        f'<div class="finding-header"><b>{f["rule_id"]}</b> '
        f'<span class="artifact-type">({f["artifact_type"]})</span> '
        f'{confidence_html}</div>'
        f'<div class="finding-desc">{f["rule_description"]}</div>'
        f'<div class="finding-attack">ATT&amp;CK: {technique}</div>'
        f'<div class="finding-rec">Recommended action: {recommendation}</div>'
        f'</div>'
    )


PAGE_STYLE = """
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #f4f5f7; margin: 0; padding: 24px; color: #222; }
  h1 { margin-bottom: 4px; }
  .summary { display: flex; gap: 12px; margin: 16px 0 28px 0; }
  .summary-box { flex: 1; padding: 14px; border-radius: 8px; color: white; text-align: center; }
  .summary-count { font-size: 28px; font-weight: bold; }
  .summary-label { font-size: 12px; letter-spacing: 1px; opacity: 0.9; }
  h2 { margin-top: 32px; border-bottom: 2px solid #ddd; padding-bottom: 4px; }
  .finding { background: white; border-radius: 6px; padding: 12px 16px; margin: 10px 0; box-shadow: 0 1px 2px rgba(0,0,0,0.08); }
  .finding-header { font-size: 15px; margin-bottom: 4px; }
  .artifact-type { color: #777; font-weight: normal; font-size: 13px; }
  .finding-desc { margin-bottom: 6px; }
  .finding-attack { font-style: italic; color: #444; margin-bottom: 4px; }
  .finding-rec { font-size: 13px; color: #555; }
  .tactic { color: #888; }
  .confidence { float: right; font-size: 12px; color: #777; font-weight: normal; }
  .filter-bar { background: white; border-radius: 8px; padding: 12px 16px; margin: 16px 0 24px 0; display: flex; gap: 16px; align-items: center; box-shadow: 0 1px 2px rgba(0,0,0,0.08); }
  .filter-bar label { font-size: 13px; color: #555; margin-right: 6px; }
  .filter-bar select, .filter-bar button { font-size: 13px; padding: 4px 8px; border-radius: 4px; border: 1px solid #ccc; }
  .filter-bar button { background: #2a6fdb; color: white; border: none; cursor: pointer; }
  .filter-clear { color: #999; font-size: 13px; }
</style>
"""


def render_filter_bar(artifact_types, sources, selected_type, selected_source):
    type_options = ['<option value="">All</option>']
    for t in artifact_types:
        sel = ' selected' if t == selected_type else ''
        type_options.append(f'<option value="{t}"{sel}>{t}</option>')

    source_options = ['<option value="">All</option>']
    for s in sources:
        sel = ' selected' if s == selected_source else ''
        source_options.append(f'<option value="{s}"{sel}>{s}</option>')

    clear_link = ""
    if selected_type or selected_source:
        clear_link = '<a class="filter-clear" href="/">Clear filters</a>'

    return (
        '<form class="filter-bar" method="get" action="/">'
        f'<label>Artifact type</label><select name="artifact_type">{"".join(type_options)}</select>'
        f'<label>Source</label><select name="source">{"".join(source_options)}</select>'
        '<button type="submit">Apply</button>'
        f'{clear_link}'
        '</form>'
    )


@app.route("/")
def index():
    selected_type = request.args.get("artifact_type") or None
    selected_source = request.args.get("source") or None

    findings = get_findings(artifact_type=selected_type, source=selected_source)
    artifact_types, sources = get_filter_options()

    grouped = {sev: [] for sev in SEVERITY_ORDER}
    for f in findings:
        grouped.setdefault(f["severity"], []).append(f)

    html_parts = [
        "<html><head><title>DFIR Dashboard</title>",
        PAGE_STYLE,
        "</head><body>",
        "<h1>DFIR Dashboard</h1>",
        f"<p>{len(findings)} finding(s) shown. "
        '<a href="/timeline">View attack chain timeline &rarr;</a> &nbsp;|&nbsp; '
        '<a href="/report">Download investigation report &rarr;</a></p>',
        render_filter_bar(artifact_types, sources, selected_type, selected_source),
        render_summary(grouped),
    ]

    for severity in SEVERITY_ORDER:
        items = grouped.get(severity, [])
        if not items:
            continue
        html_parts.append(f"<h2>{severity.upper()} ({len(items)})</h2>")
        for f in items:
            html_parts.append(render_finding(f))

    if not findings:
        html_parts.append("<p>No findings match the selected filters.</p>")

    html_parts.append("</body></html>")
    return "".join(html_parts)


def render_timeline_entry(f, index, total):
    mapping = json.loads(f["attack_mapping_json"]) if f["attack_mapping_json"] else None
    tactic = mapping["tactic"] if mapping else "Unmapped"
    technique = f"{mapping['technique_id']} {mapping['technique_name']}" if mapping else "not mapped yet"
    color = SEVERITY_COLORS.get(f["severity"], "#999")
    is_last = index == total - 1

    connector = "" if is_last else '<div class="timeline-connector"></div>'

    return (
        '<div class="timeline-entry">'
        f'<div class="timeline-dot" style="background:{color}"></div>'
        f'{connector}'
        '<div class="timeline-content">'
        f'<div class="timeline-time">{f["timestamp"]}</div>'
        f'<div class="timeline-tactic">{tactic}</div>'
        f'<div class="timeline-rule"><b>{f["rule_id"]}</b> ({f["artifact_type"]})</div>'
        f'<div class="timeline-technique">{technique}</div>'
        f'<div class="timeline-desc">{f["rule_description"]}</div>'
        '</div>'
        '</div>'
    )


TIMELINE_STYLE = """
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #f4f5f7; margin: 0; padding: 24px; color: #222; }
  h1 { margin-bottom: 4px; }
  a { color: #2a6fdb; text-decoration: none; }
  .timeline { margin-top: 32px; padding-left: 8px; }
  .timeline-entry { display: flex; position: relative; padding-bottom: 4px; }
  .timeline-dot { width: 16px; height: 16px; border-radius: 50%; margin-top: 4px; flex-shrink: 0; z-index: 1; }
  .timeline-connector { position: absolute; left: 7px; top: 20px; bottom: -4px; width: 2px; background: #ccc; }
  .timeline-content { background: white; border-radius: 6px; padding: 10px 14px; margin: 0 0 20px 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.08); flex: 1; }
  .timeline-time { font-size: 12px; color: #888; }
  .timeline-tactic { display: inline-block; font-size: 11px; font-weight: bold; letter-spacing: 0.5px; color: #555; text-transform: uppercase; background: #eee; border-radius: 4px; padding: 2px 6px; margin: 4px 0; }
  .timeline-rule { margin-top: 4px; }
  .timeline-technique { font-style: italic; font-size: 13px; color: #444; margin-top: 2px; }
  .timeline-desc { font-size: 13px; color: #555; margin-top: 4px; }
</style>
"""


@app.route("/timeline")
def timeline():
    """Attack chain view: findings sorted chronologically so the
    investigator can see the story of the incident unfold, tactic by
    tactic, rather than just a severity-sorted list."""
    findings = get_findings()
    findings.sort(key=lambda f: f["timestamp"] or "")

    html_parts = [
        "<html><head><title>Attack Chain Timeline</title>",
        TIMELINE_STYLE,
        "</head><body>",
        "<h1>Attack Chain Timeline</h1>",
        '<p><a href="/">&larr; Back to dashboard</a></p>',
        '<div class="timeline">',
    ]

    total = len(findings)
    for i, f in enumerate(findings):
        html_parts.append(render_timeline_entry(f, i, total))

    html_parts.append("</div></body></html>")
    return "".join(html_parts)


def generate_report_text():
    """Builds a structured plain-text investigation report: summary,
    severity breakdown, then a chronological finding-by-finding writeup
    with ATT&CK mapping and recommended actions. Designed to be readable
    on its own -- e.g. pasted into an email or attached to a ticket."""
    findings = get_findings()
    findings.sort(key=lambda f: f["timestamp"] or "")

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    hostnames = sorted({f["host_hostname"] for f in findings if f["host_hostname"]})
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("=" * 70)
    lines.append("DFIR INVESTIGATION REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {generated_at}")
    lines.append(f"Host(s):   {', '.join(hostnames) if hostnames else 'unknown'}")
    lines.append(f"Total findings: {len(findings)}")
    lines.append("")
    lines.append("SEVERITY BREAKDOWN")
    lines.append("-" * 70)
    for sev in SEVERITY_ORDER:
        lines.append(f"  {sev.upper():<10} {counts[sev]}")
    lines.append("")
    lines.append("ATTACK CHAIN (chronological)")
    lines.append("-" * 70)

    for i, f in enumerate(findings, start=1):
        mapping = json.loads(f["attack_mapping_json"]) if f["attack_mapping_json"] else None
        technique = (
            f"{mapping['technique_id']} - {mapping['technique_name']} (Tactic: {mapping['tactic']})"
            if mapping
            else "Not yet mapped to ATT&CK"
        )
        recommendation = RECOMMENDATIONS.get(
            f["source"], "Review manually and triage based on context."
        )

        lines.append(f"[{i}] {f['timestamp']}  -  {f['severity'].upper()}")
        lines.append(f"    Rule:        {f['rule_id']} ({f['artifact_type']})")
        lines.append(f"    Description: {f['rule_description']}")
        lines.append(f"    ATT&CK:      {technique}")
        lines.append(f"    Action:      {recommendation}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    return "\n".join(lines)


@app.route("/report")
def report():
    """Serves the investigation report as a downloadable .txt file."""
    report_text = generate_report_text()
    filename = f"dfir_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt"

    return Response(
        report_text,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


if __name__ == "__main__":
    app.run(debug=True)
