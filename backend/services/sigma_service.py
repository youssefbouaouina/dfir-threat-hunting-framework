"""
SigmaHQ rule update pipeline (Phase 5 / F6).

Imports compatible native Sigma rules into sigma_rules/native/sigmahq/ where
the pySigma engine (sigma_engine) picks them up on the next detection run.

Pipeline steps for each candidate rule:
  1. Parse with the real pySigma parser (SigmaRule.from_yaml) — invalid rules
     are rejected, not silently ignored.
  2. Skip deprecated rules.
  3. Require a logsource category we support (mapped in sigma_engine).
  4. Require every detection field to be mappable to our collector schema
     (FIELD_MAP) — otherwise the rule could never match our artifacts and
     would only burn CPU on every detection run.
  5. Deduplicate by rule id and write the original YAML into the target dir.

The source can be a local directory (tests, air-gapped deployments) or the
SigmaHQ GitHub repo (shallow git clone, fail-soft on network errors).
"""
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Optional

from sigma.rule import SigmaRule

from sigma_engine import FIELD_MAP, LOGSRC_TO_ARTIFACT

logger = logging.getLogger(__name__)

DEFAULT_TARGET_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigma_rules", "native", "sigmahq"
)
SIGMAHQ_REPO_URL = os.getenv("SIGMAHQ_REPO_URL", "https://github.com/SigmaHQ/sigma.git")
LOCAL_SOURCE_DIR = os.getenv("SIGMA_LOCAL_SOURCE_DIR", "")
REFRESH_MARKER = "refresh.json"


def _rule_fields(rule: SigmaRule) -> set:
    """Collects every field referenced by a rule's detection items (recursive)."""
    fields = set()

    def walk(items):
        for item in items:
            field = getattr(item, "field", None)
            if field:
                fields.add(field)
            # Nested SigmaDetection groups (e.g. `all` / negated lists)
            if hasattr(item, "detection_items"):
                walk(item.detection_items)

    detections = getattr(rule.detection, "detections", {}) or {}
    for det in detections.values():
        walk(getattr(det, "detection_items", []))
    return fields


def _importable(rule: SigmaRule) -> Optional[str]:
    """Returns the artifact_type this rule would map to, or None if not importable."""
    if str(rule.status) == "deprecated":
        return None
    if rule.logsource is None or rule.logsource.category is None:
        return None
    target_type = LOGSRC_TO_ARTIFACT.get(rule.logsource.category)
    if target_type is None:
        return None
    fields = _rule_fields(rule)
    allowed = set(FIELD_MAP.get(target_type, {}))
    # Rules with value-only (field-less) conditions can't be mapped safely.
    unmapped = {f for f in fields if f not in allowed}
    if unmapped:
        return None
    # Sanity: the condition must actually parse into a usable predicate.
    try:
        for sigma_cond in rule.detection.parsed_condition:
            if sigma_cond.parse(True) is None:
                return None
    except Exception:  # noqa: BLE001 — unparseable condition means skip the rule
        return None
    return target_type


def _local_source_candidates() -> list:
    """Returns (filepath, rule) pairs from LOCAL_SOURCE_DIR, or [] if unset."""
    if not LOCAL_SOURCE_DIR or not os.path.isdir(LOCAL_SOURCE_DIR):
        return []
    candidates = []
    for dirpath, _, filenames in os.walk(LOCAL_SOURCE_DIR):
        for fname in sorted(filenames):
            if fname.endswith((".yml", ".yaml")):
                candidates.append(os.path.join(dirpath, fname))
    return candidates


def _clone_sigmahq() -> str:
    """Shallow-clones the SigmaHQ repo into a temp dir; returns the rules dir.

    Raises RuntimeError on any failure so callers can fail soft.
    """
    tmp = tempfile.mkdtemp(prefix="sigmahq_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", SIGMAHQ_REPO_URL, os.path.join(tmp, "sigma")],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        raise RuntimeError(f"SigmaHQ clone failed: {exc}") from exc
    rules_dir = os.path.join(tmp, "sigma", "rules")
    if not os.path.isdir(rules_dir):
        raise RuntimeError("SigmaHQ clone did not contain a rules/ directory")
    return rules_dir


def _walk_rule_files(rules_dir: str) -> list:
    """Returns every .yml/.yaml file under rules_dir (recursive, sorted)."""
    paths = []
    for dirpath, _, filenames in os.walk(rules_dir):
        for fname in sorted(filenames):
            if fname.endswith((".yml", ".yaml")):
                paths.append(os.path.join(dirpath, fname))
    return paths


def _find_source_rules(source: str) -> list:
    """Resolves the requested source into a list of candidate rule file paths."""
    if source == "local":
        return _local_source_candidates()
    if source == "github":
        return _walk_rule_files(_clone_sigmahq())
    raise ValueError(f"Unknown Sigma source '{source}' — use 'local' or 'github'")


def refresh_sigma_rules(source: str = "local", target_dir: str = DEFAULT_TARGET_DIR) -> dict:
    """Imports compatible rules from `source` into `target_dir`.

    Returns a summary dict {scanned, imported, skipped_deprecated,
    skipped_unmapped, skipped_invalid, skipped_duplicate, target_dir}.
    """
    source_rules = _find_source_rules(source)

    summary: dict[str, Any] = {
        "source": source,
        "scanned": len(source_rules),
        "imported": 0,
        "skipped_deprecated": 0,
        "skipped_unmapped": 0,
        "skipped_invalid": 0,
        "skipped_duplicate": 0,
        "target_dir": target_dir,
    }

    os.makedirs(target_dir, exist_ok=True)
    seen_ids = set()

    for path in source_rules:
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read()
            rule = SigmaRule.from_yaml(raw)
        except Exception as exc:  # noqa: BLE001 — invalid YAML/rule is a skip, not a failure
            logger.debug("Invalid Sigma rule %s: %s", path, exc)
            summary["skipped_invalid"] += 1
            continue

        if str(rule.status) == "deprecated":
            summary["skipped_deprecated"] += 1
            continue
        if _importable(rule) is None:
            summary["skipped_unmapped"] += 1
            continue
        if rule.id in seen_ids:
            summary["skipped_duplicate"] += 1
            continue
        seen_ids.add(rule.id)

        out_path = os.path.join(target_dir, f"sigmahq_{rule.id}.yml")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(raw)
        summary["imported"] += 1

    _write_refresh_marker(target_dir, summary)
    logger.info(
        "Sigma refresh: scanned=%d imported=%d (invalid=%d deprecated=%d unmapped=%d dup=%d)",
        summary["scanned"],
        summary["imported"],
        summary["skipped_invalid"],
        summary["skipped_deprecated"],
        summary["skipped_unmapped"],
        summary["skipped_duplicate"],
    )
    return summary


def _write_refresh_marker(target_dir: str, summary: dict) -> None:
    payload = {
        "last_refresh": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
    }
    with open(os.path.join(target_dir, REFRESH_MARKER), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def get_refresh_status(target_dir: str = DEFAULT_TARGET_DIR) -> dict:
    """Returns the last refresh record + current imported rule count."""
    status = {"last_refresh": None, "summary": None, "current_rule_count": 0}
    marker = os.path.join(target_dir, REFRESH_MARKER)
    if os.path.isfile(marker):
        try:
            with open(marker, encoding="utf-8") as f:
                payload = json.load(f)
            status["last_refresh"] = payload.get("last_refresh")
            status["summary"] = payload.get("summary")
        except (OSError, json.JSONDecodeError):
            pass
    if os.path.isdir(target_dir):
        status["current_rule_count"] = sum(
            1
            for name in os.listdir(target_dir)
            if name.startswith("sigmahq_") and name.endswith(".yml")
        )
    return status
