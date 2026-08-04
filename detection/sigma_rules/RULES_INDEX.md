# Detection Ruleset Index

15 Sigma-style rules (`sigma_rules/`) + 6 YARA rules (`yara_rules/curated_ruleset.yar`), covering 13 distinct MITRE ATT&CK techniques across the kill chain: initial execution, persistence, privilege/defense evasion, discovery, lateral movement, C2, and impact. Deliberately scoped and documented rather than importing thousands of generic rules — every rule is explainable in the defense.

## Sigma-style rules (behavioral, matched against collected artifact data)

| ID | Title | Technique | Artifact Type | Severity |
|---|---|---|---|---|
| rule-001 | Suspicious PowerShell EncodedCommand | T1059.001 | process | high |
| rule-002 | Cron entry referencing script outside standard paths | T1053.003 | persistence | medium |
| rule-003 | Registry Run key pointing to Temp folder | T1547.001 | persistence | high |
| rule-004 | Windows service with suspicious binary path | T1543.003 | persistence | high |
| rule-005 | Scheduled task invoking a script interpreter directly | T1053.005 | scheduled_task | medium |
| rule-006 | PsExec-style remote service execution indicator | T1569.002 | scheduled_task | high |
| rule-007 | WMIC process creation (lateral movement) | T1047 | process | medium |
| rule-008 | System/account discovery command execution | T1082 | process | low |
| rule-009 | Network configuration discovery | T1016 | process | low |
| rule-010 | Established connection to common malware/C2 port | T1571 | network | high |
| rule-011 | Ingress tool transfer (download & execute) | T1105 | process | high |
| rule-012 | Shadow copy/backup deletion (ransomware precursor) | T1490 | process | critical |
| rule-013 | rc.local boot script persistence present | T1037.004 | persistence | low |
| rule-014 | Security tooling service stopped/disabled | T1562.001 | persistence | medium |
| rule-015 | Reverse shell one-liner pattern | T1059.004 | process | critical |

## YARA rules (file-based, matched by the collector agent locally, results reported via `file_scan` artifacts)

| Rule | Indicator | Technique |
|---|---|---|
| EICAR_Test_String | Pipeline validation string | N/A (test) |
| Suspicious_Base64_PowerShell_Loader | Base64/reflective-load PowerShell patterns | T1059.001 |
| Possible_Credential_Dumping_Tool | Mimikatz-style string indicators | T1003 |
| Suspicious_Webshell_Indicators | PHP/ASP webshell execution patterns | T1505.003 |
| Suspicious_Ingress_Tool_Transfer | Download-and-execute command patterns | T1105 |
| Suspicious_Shadow_Copy_Deletion | Recovery-inhibiting commands | T1490 |

## Deliberate scope limitations (document these in your technical report)
- **Severity is heuristic, not authoritative** — e.g. `rule-008` (discovery commands) alone is low-confidence; it's meant to correlate with other detections on the same host, not stand alone as an incident
- **Process-injection and in-memory-only techniques are out of scope** — our collector reads process/file/registry metadata, not memory; detecting T1055 (Process Injection) would need a different collection approach (e.g. reading process memory regions), which is a reasonable "future work" note for the report
- **Port-based C2 detection (rule-010) is a weak signal alone** — attackers increasingly use standard ports (443/80) for C2 specifically to evade this kind of rule; this is complemented, not solved, by the IOC correlation layer (checking remote IPs against threat intel feeds)
