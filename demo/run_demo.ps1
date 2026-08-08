# End-to-end demo driver (run on the host laptop).
# 1. Reset backend history (keep endpoint registry)
# 2. Plant the attack story on the VM
# 3. Run Now -> detections -> report
# 4. Save screenshot + JSON evidence into demo/output/
$ErrorActionPreference = 'Stop'

$Backend  = 'http://localhost:8000'
$VM       = '192.168.50.128'
$VMUser   = 'amen'
$Key      = Join-Path $PSScriptRoot '..\backend\ssh_keys\dfir_orchestrator_key'
$Out      = Join-Path $PSScriptRoot 'output'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Ssh      = { param($c) ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -i $Key "$VMUser@$VM" $c }

# --- 1. reset
docker exec dfir_backend_V5 python -c "import models; from database import SessionLocal; db=SessionLocal(); db.query(models.Artifact).delete(); db.query(models.Detection).delete(); db.query(models.Report).delete(); db.commit(); print('reset: history wiped, endpoint registry kept')"

# --- 2. plant
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -i $Key (Join-Path $PSScriptRoot 'plant_scenario.ps1') "$VMUser@$VM`:/C:/Users/amen/demo_plant.ps1"
& $Ssh "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\amen\demo_plant.ps1"

# --- 3. run now (endpoint id 1)
$resp = curl.exe -s -X POST "$Backend/endpoints/1/run-now" | ConvertFrom-Json
$resp.detect_result | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Out 'detect_result.json')

# --- 4. evidence
$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$png = Join-Path $Out 'dashboard.png'
Start-Process -FilePath $edge -ArgumentList '--headless','--disable-gpu','--no-sandbox',"--screenshot=$png",'--window-size=1600,1000',"$Backend/dashboard" -WindowStyle Hidden -Wait
Start-Sleep -Seconds 4
if (-not (Test-Path $png)) {
    Start-Process -FilePath $edge -ArgumentList '--headless','--disable-gpu','--no-sandbox',"--screenshot=$png",'--window-size=1600,1000',"$Backend/dashboard" -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 4
}
if (Test-Path $png) { Write-Output "screenshot: $((Get-Item $png).Length) bytes" }

$lastReport = $resp.report
if ($lastReport.report_id) {
    curl.exe -s -o (Join-Path $Out "report_$($lastReport.report_id).pdf") "$Backend/reports/$($lastReport.report_id)/download"
}

Write-Output "Detections: $($resp.detect_result.detections_found) | Report: $($lastReport.report_id)"
Write-Output "Evidence written to: $Out"
