/*
 * DFIR Framework — Curated YARA Ruleset
 * Each rule targets a specific, explainable indicator class. Kept small
 * and deliberately documented rather than importing thousands of
 * generic rules — every rule here should be explainable in the defense.
 */

rule Suspicious_Base64_PowerShell_Loader
{
    meta:
        description = "Base64/reflective-load indicators commonly seen in PowerShell-based loaders"
        technique_id = "T1059.001"
    strings:
        $a = "FromBase64String" nocase
        $b = "System.Reflection.Assembly" nocase
        $c = "Invoke-Expression" nocase
        $d = "IEX(" nocase
    condition:
        2 of them
}

rule Possible_Credential_Dumping_Tool
{
    meta:
        description = "String indicators associated with common credential-dumping tooling (e.g. Mimikatz-style utilities)"
        technique_id = "T1003"
    strings:
        $a = "sekurlsa" nocase
        $b = "gentilkiwi" nocase
        $c = "lsadump" nocase
        $d = "wdigest" nocase
    condition:
        any of them
}

rule Suspicious_Webshell_Indicators
{
    meta:
        description = "Common PHP/ASP webshell execution patterns"
        technique_id = "T1505.003"
    strings:
        $a = "eval(base64_decode" nocase
        $b = "eval($_POST" nocase
        $c = "eval($_GET" nocase
        $d = "Request.Item(" nocase
        $e = "cmd.exe /c" nocase
    condition:
        any of them
}

rule Suspicious_Ingress_Tool_Transfer
{
    meta:
        description = "Command patterns commonly used to download and execute a second-stage payload"
        technique_id = "T1105"
    strings:
        $a = "certutil -urlcache" nocase
        $b = "certutil.exe -urlcache" nocase
        $c = "Invoke-WebRequest" nocase
        $d = "DownloadString(" nocase
        $e = "curl -o" nocase
        $f = "wget -O" nocase
    condition:
        any of them
}

rule Suspicious_Shadow_Copy_Deletion
{
    meta:
        description = "Commands used to inhibit system recovery (common ransomware precursor behavior)"
        technique_id = "T1490"
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wbadmin delete catalog" nocase
        $c = "bcdedit /set" nocase
    condition:
        any of them
}
