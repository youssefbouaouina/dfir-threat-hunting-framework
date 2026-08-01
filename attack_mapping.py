
"""
Starter MITRE ATT&CK mapping table: rule_id -> ATT&CK technique.
 
This is intentionally a simple dict lookup for now. Later this could be
loaded from a JSON/YAML config file instead of hardcoded, so new rules can
be mapped without touching code.
 
Usage as a library:
    from attack_mapping import ATTACK_MAP, apply_mapping
 
Usage standalone (updates the DB in place):
    python attack_mapping.py --db dfir.db
"""
 
import argparse
import json
import sqlite3
 
 
# rule_id -> attack_mapping object (matches the shared schema's shape)
ATTACK_MAP = {
    "SUSP_Process_Masquerading_As_Update": {
        "tactic": "Defense Evasion",
        "technique_id": "T1036",
        "technique_name": "Masquerading",
        "mapping_confidence": "high",
    },
    "SIGMA_Registry_Run_Key_Suspicious_Path": {
        "tactic": "Persistence",
        "technique_id": "T1547.001",
        "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "mapping_confidence": "high",
    },
    "IOC_Known_C2_IP_Range": {
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "mapping_confidence": "medium",
    },
    "SIGMA_Scheduled_Task_Runs_As_System_Nonstandard_Name": {
        "tactic": "Persistence",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "mapping_confidence": "high",
    },
    "SIGMA_Powershell_EncodedCommand": {
        "tactic": "Execution",
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "mapping_confidence": "high",
    },
    "SUSP_Macro_AutoOpen_Shell_Exec": {
        "tactic": "Initial Access",
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "mapping_confidence": "medium",
    },
    "SIGMA_DNS_Query_Volume_Anomaly": {
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "mapping_confidence": "low",
    },
    "IOC_Known_Malware_Hash_Mimikatz": {
        "tactic": "Credential Access",
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "mapping_confidence": "high",
    },
}
 
 
def apply_mapping(db_path="dfir.db"):
    """Update the attack_mapping_json column for every finding whose
    rule_id has a known mapping."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT finding_id, rule_id FROM findings").fetchall()
 
    updated = 0
    for finding_id, rule_id in rows:
        mapping = ATTACK_MAP.get(rule_id)
        if mapping:
            conn.execute(
                "UPDATE findings SET attack_mapping_json = ? WHERE finding_id = ?",
                (json.dumps(mapping), finding_id),
            )
            updated += 1
 
    conn.commit()
    conn.close()
    print(f"Applied ATT&CK mapping to {updated}/{len(rows)} findings")
 
 
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="dfir.db")
    args = parser.parse_args()
    apply_mapping(args.db)
 
 
if __name__ == "__main__":
    main()
 
