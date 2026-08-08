# Ruleset Documentation — YARA + Sigma-style rules

This documents the **actual** rules shipped in this repository. Rules are deliberately small,
curated, and explainable rather than imported from large generic sets.

- YARA rules: `backend/yara_rules/`
- Sigma-style rules: `backend/sigma_rules/`
- IOC lists: `backend/iocs/`

---

## 1. YARA rules (`backend/yara_rules/curated_ruleset.yar`)

Matched by the collector agent **on the endpoint** (via `--yara-rules`), embedded into
`file_scan` artifacts, and turned into detections on the backend.

| Rule name | Purpose | Strings / condition | ATT&CK | Notes / false positives |
|---|---|---|---|---|
| `EICAR_Test_String` | Pipeline validation | `EICAR-STANDARD-ANTIVIRUS-TEST-FILE` | N/A (test) | Av-tool-standard test string; not malware. Used for demos/CI. |
| `Suspicious_Base64_PowerShell_Loader` | Reflective PowerShell loading | `FromBase64String`, `System.Reflection.Assembly`, `Invoke-Expression`, `IEX(` — any 2 | T1059.001 | Could flag legit PowerShell obfuscation tooling |
| `Possible_Credential_Dumping_Tool` | Credential-dumping tool strings | `sekurlsa`, `gentilkiwi`, `lsadump`, `wdigest` — any | T1003 | Mimikatz-style indicators; FP if other cred tools share strings |
| `Suspicious_Webshell_Indicators` | PHP/ASP webshell patterns | `eval(base64_decode`, `eval($_POST`, `Request.Item(`, `cmd.exe /c` — any | T1505.003 | Web-application focus |
| `Suspicious_Ingress_Tool_Transfer` | Download-and-execute commands | `certutil -urlcache`, `Invoke-WebRequest`, `DownloadString(`, `curl -o`, `wget -O` — any | T1105 | Also matches admin tool downloads |
| `Suspicious_Shadow_Copy_Deletion` | Recovery inhibition (ransomware precursor) | `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set` — any | T1490 | Very unlikely in legit ops |

`backend/yara_rules/test_eicar.yar` contains the `EICAR_Test_String` rule used by the
collector smoke/CI path.

## 2. Sigma-style rules (`backend/sigma_rules/rule001..rule015_*.yml`)

The backend matcher (`backend/sigma_matcher.py`) is a lightweight, transparent
implementation of Sigma-style conditions (not a full pySigma backend). Each rule declares an
`artifact_type` and a `condition` (`field: value`, `field: [..]`, or `field_contains: [..]`).
Wire the 15 canonical rules:

| ID | Title | Artifact | Technique | Severity | Condition |
|---|---|---|---|---|---|
| rule-001 | Suspicious PowerShell EncodedCommand | process | T1059.001 | high | `cmdline_contains` `-enc`, `-EncodedCommand` |
| rule-002 | Cron entry referencing script outside standard paths | persistence | T1053.003 | medium | `entry_contains` `.sh`, `/tmp/`, `/dev/shm/` |
| rule-003 | Registry Run key pointing to Temp | persistence | T1547.001 | high | `value_data_contains` `\Temp\`, `/tmp/`, AppData |
| rule-004 | Windows service with suspicious binary path | persistence | T1543.003 | high | `display_name_contains` Temp |
| rule-005 | Scheduled task invoking script interpreter | scheduled_task | T1053.005 | medium | `task_to_run_contains` powershell/cmd/wscript/mshta |
| rule-006 | PsExec-style service naming | scheduled_task | T1569.002 | high | `task_name_contains` PSEXESVC/psexec |
| rule-007 | WMIC process call create | process | T1047 | medium | `cmdline_contains` process call create, `/node:` |
| rule-008 | System/account discovery commands | process | T1082 | low | `cmdline_contains` whoami/systeminfo/net user... |
| rule-009 | Network config discovery | process | T1016 | low | `cmdline_contains` ipconfig /all, ifconfig -a... |
| rule-010 | Established connection to malware/C2 port | network | T1571 | high | `status: ESTABLISHED` + `remote_addr: :4444/:1337/:6666/:31337` |
| rule-011 | Ingress tool transfer | process | T1105 | high | `cmdline_contains` certutil/Invoke-WebRequest/curl/wget |
| rule-012 | Shadow copy/backup deletion | process | T1490 | critical | `cmdline_contains` vssadmin/wbadmin/bcdedit |
| rule-013 | rc.local boot persistence | persistence | T1037.004 | low | `type: rc.local` |
| rule-014 | Defensive service stopped/disabled | persistence | T1562.001 | medium | `display_name` Defender/Antivirus/Firewall + `status: STOPPED` |
| rule-015 | Reverse-shell one-liner | process | T1059.004 | critical | `cmdline_contains` `/dev/tcp/`, `nc -e`, `bash -i >&` |

### Note on legacy duplicate rule files

`backend/sigma_rules/` also contains four older YAML files —
`suspicious_powershell.yml`, `suspicious_cron.yml`, `suspicious_run_key_temp.yml`, and
`test_encoded_ps.yml` — which are duplicates of `rule-001`/`rule-002`/`rule-003` but **without
a `severity` field**. Because the matcher (`load_rules`) loads *every* `.yml` in the directory,
these are loaded too and their detections get `severity: unknown`. They are kept for
backward compatibility; the canonical, severity-carrying versions are the `rule0NN_*.yml`
files listed above.

## 3. IOC lists (`backend/iocs/`)

| File | Purpose | Notes |
|---|---|---|
| `known_bad_hashes.txt` | Known-bad SHA256 hashes → `hash-match` detection at T1204 | Seeded with the EICAR hash for demo/validation |
| `malicious_ips.txt` | Local IP blocklist → `ioc-blocklist` detection | Seeded with a reserved TEST-NET IP (203.0.113.66, RFC 5737) |

Network IOC correlation also optionally queries AbuseIPDB (`ABUSEIPDB_API_KEY`) — see
`backend/ioc_correlation.py`.