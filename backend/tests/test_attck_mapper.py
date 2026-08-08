"""
Unit tests for MITRE ATT&CK enrichment (attck_mapper.py).

Key property under test: the framework must FAIL SOFT when the STIX
dataset is unavailable (that's the production behavior with a missing
bundle), and return real technique names/tactics when it is present.
"""
import os

import pytest

import attck_mapper


def test_stix_unavailable_returns_nones_no_crash():
    # Point at a path that can't exist, mimicking a missing dataset.
    result = attck_mapper.enrich_technique("T1059.001", stix_path="/nonexistent/bundle.json")
    assert result["technique_id"] == "T1059.001"
    assert result["name"] is None
    assert result["tactic"] is None
    assert "error" in result


def test_resolve_stix_path_returns_existing_or_none():
    path = attck_mapper.resolve_stix_path()
    # Either the bundle was vendored, or it's cleanly absent — but never crash.
    assert path is None or os.path.isfile(path)


def test_stix_available_flag_is_boolean():
    assert isinstance(attck_mapper.stix_available(), bool)


def test_env_var_override_respected(monkeypatch, tmp_path):
    fake = tmp_path / "attack.json"
    fake.write_text("{}")
    monkeypatch.setenv(attck_mapper.STIX_ENV_VAR, str(fake))
    assert attck_mapper.resolve_stix_path() == str(fake)


@pytest.mark.skipif(
    not attck_mapper.stix_available(),
    reason="ATT&CK STIX bundle not present (run backend/scripts/fetch_stix.py)",
)
def test_real_enrichment_when_bundle_present():
    result = attck_mapper.enrich_technique("T1059.001")
    assert result["name"] == "PowerShell"
    assert result["tactic"] == "execution"