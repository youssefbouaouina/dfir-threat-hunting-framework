"""
Lightweight, Sigma-inspired behavioral detection matcher.

Rather than depending on a specific pySigma backend (that ecosystem's
backend support varies and changes fast), this implements a simple,
fully transparent matcher: each rule declares which artifact_type it
applies to, and what field/value conditions must hold in that
artifact's `data`. This is easy to read, easy to test, and easy to
explain/justify in your technical report — you can always swap in a
real pySigma backend later once the core detection logic is proven.

Rule file format (YAML), e.g. sigma_rules/suspicious_powershell.yml:

    title: Suspicious PowerShell EncodedCommand
    id: rule-001
    artifact_type: process
    technique_id: T1059.001
    condition:
      cmdline_contains: ["-enc", "-EncodedCommand"]

Supported condition operators:
    field: value              -> exact match
    field: [v1, v2]           -> value must be one of the list
    field_contains: [s1, s2]  -> field (as string, case-insensitive)
                                  must contain at least one of the substrings
"""
import os

import yaml


def load_rules(rules_dir: str) -> list:
    rules = []
    for fname in os.listdir(rules_dir):
        if fname.endswith((".yml", ".yaml")):
            with open(os.path.join(rules_dir, fname), "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
                if rule:
                    rules.append(rule)
    return rules


def _matches_condition(data: dict, condition: dict) -> bool:
    for field, expected in condition.items():
        if field.endswith("_contains"):
            real_field = field[: -len("_contains")]
            value = str(data.get(real_field, "")).lower()
            terms = expected if isinstance(expected, list) else [expected]
            if not any(str(term).lower() in value for term in terms):
                return False
        else:
            value = data.get(field)
            if isinstance(expected, list):
                if value not in expected:
                    return False
            elif value != expected:
                return False
    return True


def evaluate(rules: list, artifacts: list) -> list:
    """
    artifacts: list of wrapped artifact dicts, i.e. the exact shape the
    collector produces / the ingest API stores: {host, os, artifact_type,
    collected_at, data}.

    Returns a list of detection dicts describing which rule fired on
    which artifact.
    """
    detections = []
    for rule in rules:
        target_type = rule.get("artifact_type")
        condition = rule.get("condition", {})
        for artifact in artifacts:
            if artifact.get("artifact_type") != target_type:
                continue
            if _matches_condition(artifact.get("data", {}), condition):
                detections.append(
                    {
                        "rule_id": rule.get("id"),
                        "rule_title": rule.get("title"),
                        "technique_id": rule.get("technique_id"),
                        "severity": rule.get("severity", "unknown"),
                        "host": artifact.get("host"),
                        "artifact_type": artifact.get("artifact_type"),
                        "matched_data": artifact.get("data"),
                    }
                )
    return detections


if __name__ == "__main__":
    # Quick manual test using inline sample data — no files needed.
    sample_artifacts = [
        {
            "host": "test-host",
            "os": "windows",
            "artifact_type": "process",
            "collected_at": "2026-07-29T00:00:00Z",
            "data": {
                "pid": 4321,
                "name": "powershell.exe",
                "cmdline": "powershell.exe -EncodedCommand SQBFAFgA...",
            },
        },
        {
            "host": "test-host",
            "os": "windows",
            "artifact_type": "process",
            "collected_at": "2026-07-29T00:00:00Z",
            "data": {"pid": 111, "name": "explorer.exe", "cmdline": "explorer.exe"},
        },
    ]

    os.makedirs("sigma_rules", exist_ok=True)
    test_rule_path = os.path.join("sigma_rules", "test_encoded_ps.yml")
    with open(test_rule_path, "w") as f:
        f.write(
            "title: Suspicious PowerShell EncodedCommand\n"
            "id: rule-001\n"
            "artifact_type: process\n"
            "technique_id: T1059.001\n"
            "condition:\n"
            '  cmdline_contains: ["-enc", "-EncodedCommand"]\n'
        )

    rules = load_rules("sigma_rules")
    results = evaluate(rules, sample_artifacts)
    print(results)
