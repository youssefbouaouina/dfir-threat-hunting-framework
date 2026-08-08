# Plant the attack story on the Win10 VM (run on the VM, via SSH).
# Each stage keeps a process alive long enough for the next collection run:
# Start-Sleep in a loop = still running when the collector snapshots.
$ErrorActionPreference = 'SilentlyContinue'

# --- Stage 1: EICAR payload + Run-key persistence (T1547.001 / YARA / hash)
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path 'C:\Users\amen\AppData\Local\Temp\update_agent.exe' -Value $eicar -Encoding Ascii -NoNewline
reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v DFIRUpdateAgent /t REG_SZ /d 'C:\Users\amen\AppData\Local\Temp\update_agent.exe' /f

# --- Stage 2: encoded PowerShell execution (T1059.001) — sleeps 25 min
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 1500'))
Start-Process powershell -ArgumentList "-NoProfile -EncodedCommand $enc" -WindowStyle Hidden

# --- Stage 3: C2 beacon to the lab host on 4444 (T1571) — reconnect loop
Start-Process powershell -ArgumentList '-NoProfile -Command', "while($true){ try{ (New-Object Net.Sockets.TcpClient).Connect('192.168.50.1',4444) }catch{}; Start-Sleep -Seconds 60 }" -WindowStyle Hidden

# --- Stage 4: discovery loops (T1082 / T1016)
Start-Process cmd -ArgumentList '/c', 'echo whoami /all & echo ipconfig /all & timeout /t 900' -WindowStyle Hidden

# --- Stage 5: shadow-copy deletion calls (T1490) — echo-only, harmless
Start-Process cmd -ArgumentList '/c', 'echo vssadmin delete shadows & timeout /t 900' -WindowStyle Hidden

# --- Stage 6: scheduled-task persistence (T1053.005)
schtasks /create /tn 'EvilUpdateTask' /tr 'powershell.exe -w hidden -nop -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAUwBlAGMAbwBuAGQAcwAgADkAMAAw' /sc once /st 23:59 /f
schtasks /create /tn 'PSEXESVC' /tr 'cmd.exe /c exit' /sc once /st 23:59 /f

Write-Output 'Plant complete.'
