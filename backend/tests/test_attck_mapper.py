"""Tests for the MITRE ATT&CK STIX-based enrichment (attck_mapper).

These tests are hermetic: they point DFIR_STIX_PATH at a small bundled
fixture bundle (backend/tests/fixtures/attack_mini_bundle.json) instead of the
full dfir-refs/ MITRE CTI clone, so they pass in CI where that 442MB dataset is
not checked out.
"""

from pathlib import Path

import pytest

import attck_mapper

FIXTURE = Path(__file__).parent / "fixtures" / "attack_mini_bundle.json"


@pytest.fixture(autouse=True)
def _isolate_stix(monkeypatch):
    """Point enrichment at the bundled fixture and reset the module cache so
    each test starts clean."""
    monkeypatch.setenv("DFIR_STIX_PATH", str(FIXTURE))
    attck_mapper._attack_data = None
    yield


def test_resolve_stix_path_honors_env_override():
    path = attck_mapper.resolve_stix_path()
    assert path is not None
    assert path == FIXTURE
    assert path.name == "attack_mini_bundle.json"


def test_resolve_stix_path_none_when_no_dataset(monkeypatch):
    # Simulate an environment where no dataset exists anywhere: stub the
    # candidate paths to only honor the (unset) env override, so the test is
    # hermetic and does not depend on a dfir-refs/ clone on disk.
    monkeypatch.setattr(attck_mapper, "_candidate_paths", lambda: [Path("")])
    assert attck_mapper.resolve_stix_path() is None


def test_enrich_technique_resolves_known_technique():
    info = attck_mapper.enrich_technique("T1059.001")
    assert info["technique_id"] == "T1059.001"
    assert info["name"] == "PowerShell"
    assert info["tactic"] == "execution"
    assert info["description"]
    assert info.get("error") is None


def test_enrich_technique_unknown_technique_returns_nones():
    info = attck_mapper.enrich_technique("T9999.999")
    assert info["technique_id"] == "T9999.999"
    assert info["name"] is None
    assert info["tactic"] is None


def test_enrich_technique_subtechnique_of_execution():
    # T1566.001 (Spearphishing Attachment) sits under initial-access.
    info = attck_mapper.enrich_technique("T1566.001")
    assert info["name"] == "Spearphishing Attachment"
    assert info["tactic"] == "initial-access"