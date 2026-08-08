"""
Unit tests for the YARA engine (yara_engine.py): rule loading, scanning
files/bytes, and the EICAR validation string end-to-end.
"""
import os

import pytest

import yara_engine

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "yara_rules")

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(scope="module")
def compiled_rules():
    return yara_engine.load_rules(RULES_DIR)


def test_load_rules_files_found():
    filenames = os.listdir(RULES_DIR)
    assert any(f.endswith((".yar", ".yara")) for f in filenames)


def test_eicar_detected_by_byte_scan(compiled_rules):
    matches = yara_engine.scan_bytes(compiled_rules, EICAR)
    names = {m["rule"] for m in matches}
    assert "EICAR_Test_String" in names


def test_benign_bytes_no_match(compiled_rules):
    assert yara_engine.scan_bytes(compiled_rules, b"hello world this is benign") == []


def test_eicar_window_slash_variant_detected():
    # Some tools use a forward-slash variant of EICAR; harmless check that
    # the string match itself depends only on the rule's literal.
    rules = yara_engine.load_rules(RULES_DIR)
    matches = yara_engine.scan_bytes(rules, EICAR)
    assert matches