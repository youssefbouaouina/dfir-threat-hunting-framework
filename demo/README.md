# DFIR Framework — End-to-End Demo (replayable)
#
# Run:  powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
# Prereqs (already provisioned on this laptop):
#   - backend container `dfir_backend_V5` running on localhost:8000
#   - Win10 VM at 192.168.50.128 with the collector + OpenSSH (user amen)
#   - endpoint #1 registered in the backend, platform `windows`
#
# What happens:
#   1. Wipes artifact/detection/report history (keeps the endpoint registry)
#   2. Plants a 6-stage attack story on the VM (EICAR + Run key, encoded PS,
#      C2 beacon, discovery, shadow-copy calls, scheduled-task persistence)
#   3. Triggers the one-click "Run Now" orchestration
#   4. Saves dashboard screenshot + detection JSON + summary to demo/output/