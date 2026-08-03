"""
MITRE ATT&CK technique lookup, using the local ATT&CK STIX dataset
(dfir-refs/cti/enterprise-attack/enterprise-attack.json, in-repo since
Phase 3) via mitreattack-python. Looking this up locally (instead of calling
the ATT&CK Navigator API) keeps the framework "lightweight" and demo-able
offline.

The dataset lives in the repository tree so enrichment works without any
extra clone step:

    dfir-refs/cti/enterprise-attack/enterprise-attack.json

Override with the STIX_PATH env var if you keep it elsewhere.
"""
import os
from typing import Dict

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_STIX_PATH = os.getenv(
    "STIX_PATH",
    os.path.join(_REPO_ROOT, "dfir-refs", "cti", "enterprise-attack", "enterprise-attack.json"),
)

_cache: Dict[str, dict] = {}


def _get_attack_data(stix_path: str):
    from mitreattack.stix20 import MitreAttackData  # imported lazily so this
    # module can still be imported (e.g. for testing other functions)
    # even before mitreattack-python / the CTI dataset are set up.

    if stix_path not in _cache:
        _cache[stix_path] = MitreAttackData(stix_path)
    return _cache[stix_path]


def enrich_technique(technique_id: str, stix_path: str = DEFAULT_STIX_PATH) -> dict:
    """
    Given an ATT&CK technique ID like 'T1059.001', returns its name,
    tactic, and a short description. Returns Nones if not found or if
    the STIX dataset isn't available yet (fails soft, not hard — a
    missing enrichment shouldn't crash the whole /detect endpoint).
    """
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
    # Manual test — requires the CTI dataset to actually be cloned locally.
    print(enrich_technique("T1059.001"))
