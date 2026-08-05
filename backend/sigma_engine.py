"""
pySigma-powered detection engine (Phase 5 / F6).

Uses the real pySigma library to parse and validate native Sigma rules
(rule loading, logsource handling, detection/condition parsing, Sigma type
system) and evaluates them against artifact events by walking pySigma's
typed condition tree. This is the "real Sigma backend" upgrade over the
in-house `sigma_matcher` — that module stays for the legacy in-house rule
format, this one handles native Sigma YAML (our own rules plus rules pulled
from SigmaHQ by the update pipeline).

How it works:
  * load_rules()        — parse every .yml/.yaml under a directory with
                          SigmaRule.from_yaml_file, dropping invalid or
                          duplicate rules (deterministic filename order).
  * evaluate()          — for each rule, build one predicate from its parsed
                          condition tree (a real pySigma ConditionAND/OR/NOT
                          tree with SigmaType values) and apply it to the
                          artifacts whose artifact_type matches the rule's
                          logsource category. Returns detection dicts in the
                          same shape the legacy matcher produces, so the
                          detection pipeline is unaffected.
  * field semantics follow the Sigma spec: string equality is
    case-insensitive unless the |cased modifier is used; contains/startswith/
    endswith and wildcards come straight from the SigmaString value; the |re
    modifier and CIDR values are compiled/checked natively.

Only native Sigma rule files belong in the directory passed to load_rules
(e.g. sigma_rules/native/). The legacy ruleNNN_*.yml files at the top level
of sigma_rules/ are handled by sigma_matcher.py as before.
"""
import ipaddress
import logging
import os
import re
from typing import Any, Callable, Optional, cast

from sigma import conditions as cond
from sigma import types as st
from sigma.rule import SigmaRule

logger = logging.getLogger(__name__)

# Sigma logsource category -> our artifact_type. Rules whose logsource
# category isn't listed here are parseable but never match anything (their
# events are outside our current collector's schema), so they are skipped
# during evaluation rather than producing false negatives everywhere.
LOGSRC_TO_ARTIFACT = {
    "process_creation": "process",
    "network_connection": "network",
    "dns_query": "network",
    "proxy": "network",
    "firewall": "network",
    "registry_add": "persistence",
    "registry_set": "persistence",
    "registry_delete": "persistence",
    "registry_event": "persistence",
    "file_event": "file_scan",
    "scheduled_task": "scheduled_task",
}

# Sigma rule `level` values are already the same strings Detection.severity uses.
DEFAULT_SEVERITY = "unknown"

_WILDCARD_FLAGS = re.IGNORECASE | re.DOTALL

# Maps Sigma-standard field names to the field names our collector actually
# stores per artifact_type (see collector/modules/*.py). SigmaHQ rules and
# our own native rules use Sigma field names (CommandLine, Image, ...); this
# layer translates them at predicate-build time. Fields not present here are
# passed through unchanged — if they don't exist in the artifact data the
# condition simply won't match (safe: no false positives, only coverage gaps).
FIELD_MAP = {
    "process": {
        "Image": "exe",
        "CommandLine": "cmdline",
        "ProcessId": "pid",
        "ParentProcessId": "ppid",
        "ProcessName": "name",
        "User": "username",
    },
    "network": {
        "DestinationIp": "remote_address",
        "SourceIp": "local_address",
        "DestinationPort": "remote_address",
        "SourcePort": "local_address",
        "Protocol": "type",
    },
    "persistence": {
        "TargetObject": "key_path",
        "Details": "value_data",
        "EventType": "type",
        "Image": "name",
        "ServiceName": "name",
        "ServiceFileName": "name",
        "CommandLine": "entry",
    },
    "scheduled_task": {
        "TaskName": "task_name",
        "TaskContent": "task_to_run",
        "Command": "task_to_run",
    },
    "file_scan": {
        "TargetFilename": "path",
        "FileSize": "size_bytes",
    },
    "log_event": {
        "EventID": "event_id",
        "Channel": "source_name",
        "Provider_Name": "source_name",
    },
}


def _artifact_type_for_rule(rule: SigmaRule) -> Optional[str]:
    """Resolves a rule's logsource category to our artifact_type (None = unsupported)."""
    if rule.logsource is None or rule.logsource.category is None:
        return None
    return LOGSRC_TO_ARTIFACT.get(rule.logsource.category)


def load_rules(rules_dir: str) -> list:
    """Loads every native Sigma rule file under rules_dir (recursive).

    Invalid files (unparseable YAML / rule validation errors) are skipped with
    a warning instead of crashing a detection run. Duplicate rule ids keep the
    first occurrence (sorted filename order). Rules with status 'deprecated'
    are dropped. Returns a list of pySigma SigmaRule objects.
    """
    rules = []
    seen_ids = set()
    for dirpath, _, filenames in os.walk(rules_dir):
        for fname in sorted(filenames):
            if not fname.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(dirpath, fname)
            try:
                with open(path, encoding="utf-8") as f:
                    rule = SigmaRule.from_yaml(f.read())
            except Exception as exc:  # noqa: BLE001 — pySigma raises many types
                logger.warning("Skipping invalid Sigma rule %s: %s", path, exc)
                continue
            if rule.status == "deprecated":
                logger.debug("Skipping deprecated rule %s", path)
                continue
            if rule.id in seen_ids:
                logger.warning("Skipping duplicate Sigma rule id %s in %s", rule.id, path)
                continue
            seen_ids.add(rule.id)
            rules.append(rule)
    return rules


def summarize(rules: list) -> dict:
    """Counts rules by supportability — used by /sigma/status and the pipeline."""
    mapped = sum(1 for r in rules if _artifact_type_for_rule(r) is not None)
    return {"total": len(rules), "mapped": mapped, "unmapped": len(rules) - mapped}


def _string_matcher(value: st.SigmaString) -> Callable[[object], bool]:
    """Builds a matcher for a Sigma string value (wildcards + case-insensitivity)."""
    regex = value.to_regex()
    pattern = "^" + regex.to_plain() + "$"
    flags = _WILDCARD_FLAGS if not isinstance(value, st.SigmaCasedString) else re.RegexFlag(0)
    compiled = re.compile(pattern, flags)

    def match(actual: object) -> bool:
        if actual is None:
            return False
        return compiled.match(str(actual)) is not None

    return match


def _regex_matcher(value: st.SigmaRegularExpression) -> Callable[[object], bool]:
    flags = 0
    for flag in value.flags:
        flags |= st.SigmaRegularExpression.sigma_to_python_flags[flag]
    compiled = re.compile(value.to_plain(), flags)

    def match(actual: object) -> bool:
        if actual is None:
            return False
        return compiled.search(str(actual)) is not None

    return match


def _numeric(actual: object) -> Optional[float]:
    if isinstance(actual, bool) or actual is None:
        return None
    try:
        return float(cast(Any, actual))
    except (TypeError, ValueError):
        return None


def _field_match(data: dict, field: str, value: st.SigmaType, field_map: dict) -> bool:
    """Evaluates one field=value condition against an artifact's data dict."""
    actual = data.get(field_map.get(field, field))

    if isinstance(value, st.SigmaNull):
        return actual is None or actual == "" or actual == []
    if isinstance(value, st.SigmaExists):
        present = actual is not None and actual != ""
        return present == value.exists

    if actual is None:
        return False

    if isinstance(value, st.SigmaString):
        return _string_matcher(value)(actual)
    if isinstance(value, st.SigmaRegularExpression):
        return _regex_matcher(value)(actual)
    if isinstance(value, st.SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in value.network
        except ValueError:
            return False
    if isinstance(value, st.SigmaNumber):
        num = _numeric(actual)
        return num is not None and num == float(value.number)
    if isinstance(value, st.SigmaBool):
        return bool(actual) == bool(value.boolean)
    if isinstance(value, st.SigmaCompareExpression):
        num = _numeric(actual)
        if num is None:
            return False
        other = float(value.number.number)
        op = value.op
        if op == st.CompareOperators.LT:
            return num < other
        if op == st.CompareOperators.LTE:
            return num <= other
        if op == st.CompareOperators.GT:
            return num > other
        if op == st.CompareOperators.GTE:
            return num >= other
        if op == st.CompareOperators.NEQ:
            return num != other
        return num == other
    if isinstance(value, st.SigmaFieldReference):
        return str(actual).lower() == str(
            data.get(field_map.get(value.field, value.field), "")
        ).lower()
    if isinstance(value, st.SigmaExpansion):
        return any(_field_match(data, field, v, field_map) for v in value.values)

    logger.warning("Unsupported Sigma value type %s for field %s", type(value).__name__, field)
    return False


def _value_only_match(data: dict, value: st.SigmaType) -> bool:
    """Matches a value-only condition: the value must appear in any string field."""
    if isinstance(value, st.SigmaString):
        matcher = _string_matcher(value)
        return any(
            matcher(v) for v in data.values() if isinstance(v, (str, int, float)) and v is not None
        )
    if isinstance(value, st.SigmaExpansion):
        return any(_value_only_match(data, v) for v in value.values)
    return False


def _build_predicate(tree, field_map: Optional[dict] = None) -> Callable[[dict], bool]:
    """Compiles a pySigma condition tree into a callable(data) -> bool predicate."""
    if field_map is None:
        field_map = {}
    if isinstance(tree, cond.ConditionAND):
        sub = [_build_predicate(a, field_map) for a in tree.args]
        return lambda data: all(p(data) for p in sub)
    if isinstance(tree, cond.ConditionOR):
        sub = [_build_predicate(a, field_map) for a in tree.args]
        return lambda data: any(p(data) for p in sub)
    if isinstance(tree, cond.ConditionNOT):
        inner = _build_predicate(tree.args[0], field_map)
        return lambda data: not inner(data)
    if isinstance(tree, cond.ConditionFieldEqualsValueExpression):
        return lambda data: _field_match(data, tree.field, tree.value, field_map)
    if isinstance(tree, cond.ConditionValueExpression):
        return lambda data: _value_only_match(data, tree.value)
    raise TypeError(f"Unsupported Sigma condition node: {type(tree).__name__}")


def _rule_technique_id(rule: SigmaRule) -> Optional[str]:
    for tag in rule.tags:
        if tag.namespace == "attack":
            name = str(tag.name)
            if name.startswith("t"):
                return "T" + name[1:]
            if name.startswith("T"):
                return name
    return None


def _rule_detection(rule: SigmaRule) -> dict:
    """Returns the detection metadata in the same shape as sigma_matcher.evaluate()."""
    level = str(rule.level) if rule.level else DEFAULT_SEVERITY
    return {
        "rule_id": str(rule.id),
        "rule_title": rule.title or str(rule.id),
        "technique_id": _rule_technique_id(rule),
        "severity": level,
    }


def evaluate(rules: list, artifacts: list) -> list:
    """
    Evaluates native Sigma rules against wrapped artifact dicts.

    artifacts: list of {host, os, artifact_type, collected_at, data} — the
    exact shape the collector produces / the ingest API stores.

    Returns a list of detection dicts ({rule_id, rule_title, technique_id,
    severity, host, artifact_type, matched_data}) for every rule that fired.
    """
    detections = []

    compiled = []  # (predicate, meta, target_type)
    for rule in rules:
        target_type = _artifact_type_for_rule(rule)
        if target_type is None:
            continue  # logsource outside our collector's schema
        field_map = FIELD_MAP.get(target_type, {})
        try:
            parsed_list = rule.detection.parsed_condition
            predicates = []
            for sigma_cond in parsed_list:
                tree = sigma_cond.parse(True)
                if tree is None:
                    continue
                predicates.append(_build_predicate(tree, field_map))
            if not predicates:
                logger.warning("Skipping rule %s: no usable condition", rule.id)
                continue
        except Exception as exc:  # noqa: BLE001 — one bad rule must not kill a run
            logger.warning("Skipping rule %s: condition parse failed: %s", rule.id, exc)
            continue

        def combined(data: dict, preds=predicates) -> bool:
            return all(p(data) for p in preds)

        compiled.append((combined, _rule_detection(rule), target_type))

    for predicate, meta, target_type in compiled:
        for artifact in artifacts:
            if artifact.get("artifact_type") != target_type:
                continue
            if predicate(artifact.get("data", {})):
                detections.append(
                    {
                        **meta,
                        "host": artifact.get("host"),
                        "artifact_type": artifact.get("artifact_type"),
                        "matched_data": artifact.get("data"),
                    }
                )
    return detections
