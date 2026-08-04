"""
YARA-based file/malware detection engine.
Loads every .yar/.yara file from a rules directory into one compiled
ruleset, and exposes functions to scan either a file on disk or raw bytes.
"""
import os

import yara


def load_rules(rules_dir: str):
    rule_files = {}
    for fname in os.listdir(rules_dir):
        if fname.endswith((".yar", ".yara")):
            key = os.path.splitext(fname)[0]
            rule_files[key] = os.path.join(rules_dir, fname)
    if not rule_files:
        raise FileNotFoundError(f"No .yar/.yara rule files found in {rules_dir}")
    return yara.compile(filepaths=rule_files)


def scan_file(compiled_rules, filepath: str) -> list:
    matches = compiled_rules.match(filepath)
    return [
        {"rule": str(m.rule), "tags": list(m.tags), "meta": dict(m.meta)}
        for m in matches
    ]


def scan_bytes(compiled_rules, data: bytes) -> list:
    matches = compiled_rules.match(data=data)
    return [
        {"rule": str(m.rule), "tags": list(m.tags), "meta": dict(m.meta)}
        for m in matches
    ]


if __name__ == "__main__":
    # Quick manual test: create a test file containing the EICAR string
    # (industry-standard harmless "this looks like malware" test string)
    # and confirm a basic rule catches it.
    test_rule_dir = "yara_rules"
    os.makedirs(test_rule_dir, exist_ok=True)
    test_rule_path = os.path.join(test_rule_dir, "test_eicar.yar")
    if not os.path.exists(test_rule_path):
        with open(test_rule_path, "w") as f:
            f.write(
                'rule EICAR_Test_String {\n'
                '  meta:\n'
                '    description = "Detects the EICAR antivirus test string"\n'
                '  strings:\n'
                '    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"\n'
                '  condition:\n'
                '    $eicar\n'
                '}\n'
            )
    rules = load_rules(test_rule_dir)
    eicar_bytes = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    print(scan_bytes(rules, eicar_bytes))
