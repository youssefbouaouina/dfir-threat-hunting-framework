"""
Loads findings from sample_findings.json (or any file matching the shared
schema) into a SQLite database — one row per finding.

Usage:
    python load_findings.py
    python load_findings.py --input sample_findings.json --db dfir.db
"""

import argparse
import json
import sqlite3


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT,
    host_hostname TEXT,
    source TEXT,
    severity TEXT,
    artifact_type TEXT,
    artifact_json TEXT,      -- the "artifact" object, stored as JSON text
    rule_id TEXT,
    rule_description TEXT,
    matched_pattern TEXT,
    raw_log_ref TEXT,
    timestamp TEXT,
    confidence REAL,
    attack_mapping_json TEXT, -- the "attack_mapping" object, stored as JSON text (NULL until mapped)
    tags_json TEXT            -- the "tags" array, stored as JSON text
)
"""

INSERT_SQL = """
INSERT OR REPLACE INTO findings (
    finding_id, scan_id, host_hostname, source, severity, artifact_type,
    artifact_json, rule_id, rule_description, matched_pattern, raw_log_ref,
    timestamp, confidence, attack_mapping_json, tags_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def load_findings(input_path, db_path):
    with open(input_path) as f:
        scan_result = json.load(f)

    scan_id = scan_result.get("scan_id")
    hostname = scan_result.get("host", {}).get("hostname")
    findings = scan_result.get("findings", [])

    conn = sqlite3.connect(db_path)
    conn.execute(CREATE_TABLE_SQL)

    for finding in findings:
        conn.execute(
            INSERT_SQL,
            (
                finding["finding_id"],
                scan_id,
                hostname,
                finding.get("source"),
                finding.get("severity"),
                finding.get("artifact_type"),
                json.dumps(finding.get("artifact")),
                finding.get("rule_id"),
                finding.get("rule_description"),
                finding.get("matched_pattern"),
                finding.get("raw_log_ref"),
                finding.get("timestamp"),
                finding.get("confidence"),
                json.dumps(finding.get("attack_mapping")),
                json.dumps(finding.get("tags")),
            ),
        )

    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    conn.close()

    print(f"Loaded {len(findings)} findings from {input_path} into {db_path}")
    print(f"Table now has {count} total rows")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="sample_findings.json")
    parser.add_argument("--db", default="dfir.db")
    args = parser.parse_args()

    load_findings(args.input, args.db)


if __name__ == "__main__":
    main()
