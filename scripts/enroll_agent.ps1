#Requires -Version 5.1
# DFIR endpoint enrollment (Windows) — one-shot collect + push, then daemon.
# Usage:  .\enroll_agent.ps1 -BackendUrl http://192.168.56.1:8000 [-Interval 300]
#
# Installs the collector's Python deps, enrolls this host with the backend,
# pushes one collection batch immediately, then runs as a daemon that
# collects + pushes every interval (default 300s).
param(
    [Parameter(Mandatory = $true)]
    [string]$BackendUrl,
    [int]$Interval = 300
)

$ErrorActionPreference = "Stop"
$CollectorDir = Join-Path $PSScriptRoot "..\collector"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] python not found. Install Python 3 and add it to PATH." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Installing collector dependencies..."
if (-not (Test-Path (Join-Path $CollectorDir ".venv"))) {
    python -m venv (Join-Path $CollectorDir ".venv")
}
& (Join-Path $CollectorDir ".venv\Scripts\python.exe") -m pip install -q -r (Join-Path $CollectorDir "requirements.txt")

Write-Host "[*] Enrolling with backend at $BackendUrl ..."
& (Join-Path $CollectorDir ".venv\Scripts\python.exe") (Join-Path $CollectorDir "collector_agent.py") --api-url $BackendUrl --enroll

Write-Host "[*] Starting daemon (collect + push every ${Interval}s) ..."
& (Join-Path $CollectorDir ".venv\Scripts\python.exe") (Join-Path $CollectorDir "collector_agent.py") --api-url $BackendUrl --daemon --interval $Interval
