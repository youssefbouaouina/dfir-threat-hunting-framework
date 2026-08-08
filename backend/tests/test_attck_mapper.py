"""Tests for the MITRE ATT&CK STIX-based enrichment (attck_mapper)."""

from attck_mapper import enrich_technique, resolve_stix_path


def test_resolve_stix_path_finds_dfir_refs():
    """The repo ships the MITRE CTI clone in ./dfir-refs; the mapper should
    find enterprise-attack.json there even with no env var set."""
    import os

    os.environ.pop("DFIR_STIX_PATH", None)
    path = resolve_stix_path()
    assert path is not None
    assert path.name == "enterprise-attack.json"


def test_enrich_technique_resolves_known_technique():
    info = enrich_technique("T1059.001")
    assert info["technique_id"] == "T1059.001"
    assert info["name"] == "PowerShell"
    assert info["tactic"] == "execution"
    assert info["description"]
    assert info.get("error") is None


def test_enrich_technique_unknown_technique_returns_nones():
    info = enrich_technique("T9999.999")
    assert info["technique_id"] == "T9999.999"
    assert info["name"] is None
    assert info["tactic"] is None


def test_enrich_technique_subtechnique_of_execution():
    # T1566.001 (Spearphishing Attachment) sits under initial-access.
    info = enrich_technique("T1566.001")
    assert info["name"] is not None
    assert info["tactic"] == "initial-access"
