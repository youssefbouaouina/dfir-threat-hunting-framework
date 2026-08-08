"""
Fetch the MITRE ATT&CK Enterprise STIX 2.0 bundle into the backend's
refs/ directory so attck_mapper can use it locally (offline, no API).

Upstream source: github.com/mitre/cti (STIX 2.0 enterprise-attack.json,
~48 MB). Try-refetch-skip: if the file already exists we leave it alone
unless --force is given.

Usage:
    python scripts/fetch_stix.py [--dest PATH] [--force]
"""
import argparse
import json
import os
import sys
import urllib.request

URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    default_dest = os.path.join(here, "..", "refs", "attack", "enterprise-attack.json")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default=default_dest, help="output path")
    parser.add_argument("--force", action="store_true", help="re-download even if it exists")
    args = parser.parse_args()

    if os.path.exists(args.dest) and not args.force:
        print(f"[fetch_stix] bundle already present: {args.dest}")
        return 0

    os.makedirs(os.path.dirname(args.dest), exist_ok=True)
    print(f"[fetch_stix] downloading ATT&CK STIX bundle from {URL} ...")
    urllib.request.urlretrieve(URL, args.dest)

    # Sanity check: must be a STIX bundle with objects.
    with open(args.dest, "r", encoding="utf-8") as f:
        first = json.load(f)
    assert first.get("type") == "bundle", "downloaded file is not a STIX bundle"
    n_attack_patterns = sum(
        1 for o in first.get("objects", []) if o.get("type") == "attack-pattern"
    )
    print(
        f"[fetch_stix] OK: {os.path.getsize(args.dest)} bytes, "
        f"{n_attack_patterns} attack-pattern objects"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())