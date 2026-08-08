"""
MITRE ATT&CK technique lookup, using the local ATT&CK STIX dataset via
mitreattack-python. Looking this up locally (instead of calling the
ATT&CK Navigator API) keeps the framework lightweight and demo-able
offline.

The dataset is resolved, in order of preference:
  1. $DFIR_STIX_PATH                            (explicit override)
  2. <backend>/refs/attack/enterprise-attack.json   (vendored copy)
  3. <backend>/../../dfir-refs/cti/enterprise-attack/enterprise-attack.json (legacy sibling clone of github.com/mitre/cti)

The vendored copy is fetched by scripts/fetch_stix.py. See that script
for download instructions and the upstream source.
"""
import os

STIX_ENV_VAR = "DFIR_STIX_PATH"

_candidates = None


def _default_stix_paths() -> list:
    """All candidate paths for the STIX bundle, most-preferred first."""
    global _candidates
    if _candidates is None:
        here = os.path.dirname(os.path.abspath(__file__))
        paths = [os.path.join(here, "refs", "attack", "enterprise-attack.json")]
        paths.append(
            os.path.join("..", "..", "dfir-refs", "cti", "enterprise-attack", "enterprise-attack.json")
        )
        _candidates = paths
    return _candidates


def resolve_stix_path() -> str | None:
    """Return the first STIX bundle path that actually exists, else None."""
    env_path = os.environ.get(STIX_ENV_VAR)
    for candidate in ([env_path] if env_path else []) + _default_stix_paths():
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def stix_available() -> bool:
    return resolve_stix_path() is not None


_cache = {}


def _get_attack_data(stix_path: str):
    from mitreattack.stix20 import MitreAttackData  # imported lazily so this
    # module can still be imported (e.g. for testing other functions)
    # even before mitreattack-python / the CTI dataset are set up.

    if stix_path not in _cache:
        _cache[stix_path] = MitreAttackData(stix_path)
    return _cache[stix_path]


def enrich_technique(technique_id: str, stix_path: str | None = None) -> dict:
    """
    Given an ATT&CK technique ID like 'T1059.001', returns its name,
    tactic, and a short description. Returns Nones if not found or if
    the STIX dataset isn't available yet (fails soft, not hard — a
    missing enrichment shouldn't crash the whole /detect endpoint).
    """
    if stix_path is None:
        stix_path = resolve_stix_path()

    if not stix_path:
        return {
            "technique_id": technique_id,
            "name": None,
            "tactic": None,
            "description": None,
            "error": "ATT&CK STIX dataset not found (run scripts/fetch_stix.py)",
        }

    try:
        data = _get_attack_data(stix_path)
        technique = data.get_object_by_attack_id(technique_id, "attack-pattern")
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


if __name__ == "__main__":
    # Manual test — needs the bundle (see scripts/fetch_stix.py).
    print(enrich_technique("T1059.001"))