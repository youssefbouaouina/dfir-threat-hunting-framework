"""Tests for attack-chain reconstruction (attack_chain.py)."""

from datetime import UTC, datetime

from attack_chain import (
    build_attack_chain,
    recommended_actions,
    summary_recommendations,
)


def _detection(technique_id, tactic=None, severity="high", host="h1", detected_at=None):
    return {
        "technique_id": technique_id,
        "technique_name": f"{technique_id} name",
        "tactic": tactic,
        "severity": severity,
        "host": host,
        "detected_at": detected_at or datetime(2026, 8, 8, 12, 0, tzinfo=UTC).isoformat(),
    }


def test_chain_orders_by_tactic():
    dets = [
        _detection("T1071", "command-and-control", "high"),
        _detection("T1566", "initial-access", "high"),
        _detection("T1059", "execution", "medium"),
    ]
    chain = build_attack_chain(dets)
    labels = [t["label"] for t in chain["tactics"]]
    # initial-access comes before execution before command-and-control
    assert labels.index("Initial Access") < labels.index("Execution") < labels.index("Command And Control")


def test_chain_unknown_tactic_is_last():
    dets = [
        _detection("T1071", "command-and-control", "high"),
        _detection("TX", None, "high"),
    ]
    chain = build_attack_chain(dets)
    assert chain["tactics"][-1]["tactic"] == "unknown"


def test_chain_counts_techniques():
    dets = [
        _detection("T1071", "command-and-control", "high"),
        _detection("T1071", "command-and-control", "high"),
        _detection("T1059", "execution", "medium"),
    ]
    chain = build_attack_chain(dets)
    assert chain["technique_count"] == 2
    c2 = chain["tactics"][-1]["techniques"][0]  # command-and-control is last tactic
    assert c2["count"] == 2


def test_chain_skips_unknown_technique_only():
    dets = [_detection("T1059", "execution", "medium"), _detection("unknown", None, "low")]
    chain = build_attack_chain(dets)
    assert chain["technique_count"] == 1
    assert all(t["technique_id"] != "unknown" for phase in chain["tactics"] for t in phase["techniques"])


def test_recommended_actions_curated_map():
    dets = [_detection("T1059.001", "execution", "high")]
    recs = recommended_actions(dets)
    assert any(r["technique_id"] == "T1059.001" for r in recs)
    assert all(r["action"] for r in recs)


def test_summary_recommendations_dedupes():
    dets = [
        _detection("T1059.001", "execution", "high"),
        _detection("T1059.002", "execution", "high"),
    ]
    out = summary_recommendations(dets)
    # Both map to the T1059 action, which is deduped to one entry.
    assert len(out) == 1