"""
MITRE ATT&CK technique lookup, using the local ATT&CK STIX dataset
(cloned from github.com/mitre/cti — ship it in ./dfir-refs at the repo root,
or point DFIR_STIX_PATH at any copy of enterprise-attack.json) via
mitreattack-python. Looking this up locally (instead of calling the
ATT&CK Navigator API) keeps the framework "lightweight" and demo-able
offline.

The STIX bundle is resolved with this priority:
  1. DFIR_STIX_PATH  — env override (used by docker-compose to mount
                       dfir-refs into the container read-only)
  2. known candidate paths relative to this module / the repo root:
        repo_root/dfir-refs/cti/enterprise-attack/enterprise-attack.json
        <backend>/../..   (older sibling-layout: dev/{ framework, dfir-refs })
        /app/dfir-refs/... (container default when volume-mounted)
  3. /dfir/stix/enterprise-attack.json (documented fallback)

If none exist, enrichment fails soft (returns Nones) so a missing
dataset never crashes the /detect pipeline — but the admin sees why in
the `error` field.
"""
import os
from pathlib import Path


def _candidate_paths() -> list[Path]:
    here = Path(__file__).resolve()
    backend_dir = here.parent
    repo_root = backend_dir.parent
    return [
        # 1. env override (highest priority)
        Path(os.getenv("DFIR_STIX_PATH", "")).expanduser(),
        # 2. dfir-refs at the repo root (this repo's documented location)
        repo_root / "dfir-refs" / "cti" / "enterprise-attack" / "enterprise-attack.json",
        # 3. older sibling-tree layout: dev/<framework>/backend + dev/dfir-refs
        backend_dir / ".." / ".." / "dfir-refs" / "cti" / "enterprise-attack" / "enterprise-attack.json",
        # 4. inside the container when dfir-refs is volume-mounted
        Path("/app/dfir-refs/cti/enterprise-attack/enterprise-attack.json"),
        # 5. documented fallback location
        Path("/dfir/stix/enterprise-attack.json"),
    ]


def resolve_stix_path() -> Path | None:
    """Return the first candidate path that actually exists, else None."""
    for p in _candidate_paths():
        if p and p.is_file():
            return p
    return None


def enrich_technique(technique_id: str) -> dict:
    """
    Given an ATT&CK technique ID like 'T1059.001', returns its name,
    tactic, and a short description. Returns Nones if not found or if
    the STIX dataset isn't available yet (fails soft, not hard — a
    missing enrichment shouldn't crash the whole /detect endpoint).
    """
    try:
        data = _get_attack_data()
        technique = data.get_object_by_attack_id(technique_id, "attack-pattern")
    except FileNotFoundError as e:
        return {
            "technique_id": technique_id,
            "name": None,
            "tactic": None,
            "description": None,
            "error": f"ATT&CK STIX dataset not found: {e} — see attck_mapper.py docs",
        }
    except Exception as e:
        return {
            "technique_id": technique_id,
            "name": None,
            "tactic": None,
            "description": None,
            "error": str(e),
        }

    if not technique:
        return {"technique_id": technique_id, "name": None, "tactic": None, "description": None}

    tactics = [p.phase_name for p in technique.get("kill_chain_phases", [])]
    description = technique.get("description") or ""

    return {
        "technique_id": technique_id,
        "name": technique.get("name"),
        "tactic": tactics[0] if tactics else None,
        "description": description[:300],  # trimmed for report/dashboard display
    }


_attack_data = None


def _get_attack_data():
    """Load the MITRE ATT&CK dataset once per process (mitreattack-python
    loads the whole bundle; keep it cached)."""
    global _attack_data
    if _attack_data is not None:
        return _attack_data
    stix_path = resolve_stix_path()
    if stix_path is None or not stix_path.is_file():
        raise FileNotFoundError(
            "no ATT&CK enterprise-attack.json found in any known location "
            "(set DFIR_STIX_PATH or place dfir-refs at the repo root)"
        )
    from mitreattack.stix20 import MitreAttackData  # imported lazily so this
    # module can still be imported (e.g. for testing other functions),
    # and so the heavy dependency isn't needed at import time.

    _attack_data = MitreAttackData(str(stix_path))
    return _attack_data


if __name__ == "__main__":
    # Manual test — requires the STIX bundle to be present (in dfir-refs/ or
    # a mounted location).
    import json

    print("resolved stix path:", resolve_stix_path())
    print(json.dumps(enrich_technique("T1059.001"), indent=1))