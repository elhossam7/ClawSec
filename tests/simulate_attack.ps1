# ==============================================================================
# Sentinel - Complex Attack Simulation Script
# ==============================================================================
# This script simulates a realistic multi-stage attack scenario:
#   Stage 1: Reconnaissance (SSH brute force from multiple IPs)
#   Stage 2: Web exploitation (SQL injection + path traversal)
#   Stage 3: Privilege escalation (sudo abuse)
#   Stage 4: Lateral movement (RDP brute force)
#   Stage 5: Container escape attempt
#
# Usage:
#   .\sentinel.exe run          # Start agent first (in another terminal)
#   .\tests\simulate_attack.ps1 # Run this script
#
# WebUI: http://127.0.0.1:8082 (login: admin / sentinel)
# ==============================================================================

$ErrorActionPreference = "SilentlyContinue"

# Colors for output
function Write-Stage($text) { Write-Host "`n[*] $text" -ForegroundColor Cyan }
function Write-Attack($text) { Write-Host "    [!] $text" -ForegroundColor Red }
function Write-Info($text) { Write-Host "    [i] $text" -ForegroundColor Yellow }
function Write-OK($text) { Write-Host "    [+] $text" -ForegroundColor Green }

$webLog = ".\data\test.log"
$authLog = ".\data\auth.log"
$containerLog = ".\data\container.log"

# Ensure log files exist
"" | Set-Content $webLog
"" | Set-Content $authLog
"" | Set-Content $containerLog

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  SENTINEL ATTACK SIMULATION - Multi-Stage Intrusion Test  " -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""
Write-Info "Log sources: web=$webLog, auth=$authLog, container=$containerLog"
Write-Info "Open http://127.0.0.1:8082 to watch detections in real-time"
Write-Host ""

# Give the file watcher time to pick up the cleared files
Start-Sleep -Seconds 2

# ==============================================================================
# STAGE 1: SSH Brute Force Attack (needs 5+ events from same IP to trigger)
# ==============================================================================
Write-Stage "STAGE 1: SSH Brute Force from 10.20.30.40 (5 attempts = threshold)"

$attackerIP = "10.20.30.40"
for ($i = 1; $i -le 6; $i++) {
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    $line = "$ts sshd[1234]: Failed password for root from $attackerIP port 22 ssh2"
    Add-Content -Path $authLog -Value $line
    Write-Attack "SSH attempt $i/6: Failed password for root from $attackerIP"
    Start-Sleep -Milliseconds 800
}

Write-Info "Waiting for correlation engine (threshold=5, window=5m)..."
Start-Sleep -Seconds 3

# ==============================================================================
# STAGE 2a: SQL Injection Attacks (single event triggers)
# ==============================================================================
Write-Stage "STAGE 2a: SQL Injection attacks from 192.168.1.100"

$sqliPayloads = @(
    "GET /api/users?id=1 UNION SELECT username,password FROM admin_users-- HTTP/1.1 source_ip=192.168.1.100",
    "POST /login username=admin' OR 1=1-- password=x HTTP/1.1 source_ip=192.168.1.100",
    "GET /products?cat=1; DROP TABLE orders;-- HTTP/1.1 source_ip=192.168.1.100",
    "GET /search?q=1' AND SLEEP(5)-- HTTP/1.1 source_ip=192.168.1.150"
)

foreach ($payload in $sqliPayloads) {
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    Add-Content -Path $webLog -Value "$ts WARNING $payload"
    Write-Attack "SQLi: $($payload.Substring(0, [Math]::Min(80, $payload.Length)))..."
    Start-Sleep -Seconds 2
}

# ==============================================================================
# STAGE 2b: Path Traversal Attacks
# ==============================================================================
Write-Stage "STAGE 2b: Path Traversal from 172.16.0.50"

$traversalPayloads = @(
    "GET /download?file=../../../etc/passwd HTTP/1.1 source_ip=172.16.0.50",
    "GET /static/%2e%2e%2f%2e%2e%2fetc/shadow HTTP/1.1 source_ip=172.16.0.50",
    "GET /files?path=..\..\..\..\windows\system32\config\sam source_ip=172.16.0.50",
    "GET /api/read?f=/proc/self/environ HTTP/1.1 source_ip=172.16.0.50"
)

foreach ($payload in $traversalPayloads) {
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    Add-Content -Path $webLog -Value "$ts WARNING $payload"
    Write-Attack "Traversal: $($payload.Substring(0, [Math]::Min(80, $payload.Length)))..."
    Start-Sleep -Seconds 2
}

# ==============================================================================
# STAGE 3: Privilege Escalation
# ==============================================================================
Write-Stage "STAGE 3: Privilege Escalation on compromised host"

$privEscPayloads = @(
    "sudo: user=compromised : TTY=pts/0 ; PWD=/home/compromised ; USER=root ; COMMAND=/bin/bash",
    "FAILED su for root by user=hacker",
    "pkexec --user root /bin/sh called by user=compromised",
    "chmod +s /tmp/backdoor executed by user=attacker",
    "chown root:root /tmp/rootkit executed by user=attacker"
)

foreach ($payload in $privEscPayloads) {
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    Add-Content -Path $authLog -Value "$ts CRITICAL $payload"
    Write-Attack "PrivEsc: $($payload.Substring(0, [Math]::Min(80, $payload.Length)))..."
    Start-Sleep -Seconds 2
}

# ==============================================================================
# STAGE 4: RDP Brute Force (needs 5+ to trigger)
# ==============================================================================
Write-Stage "STAGE 4: RDP Brute Force from 10.99.99.99 (5 attempts = threshold)"

$rdpAttacker = "10.99.99.99"
for ($i = 1; $i -le 6; $i++) {
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    $line = "$ts Microsoft-Windows-Security-Auditing event_id=4625 An account failed to log on source_ip=$rdpAttacker user=Administrator LogonType=10"
    Add-Content -Path $authLog -Value $line
    Write-Attack "RDP attempt $i/6: Failed logon event_id=4625 from $rdpAttacker"
    Start-Sleep -Milliseconds 800
}

Write-Info "Waiting for RDP correlation..."
Start-Sleep -Seconds 3

# ==============================================================================
# STAGE 5: Container Escape Attempts
# ==============================================================================
Write-Stage "STAGE 5: Container Escape from container abc123def456"

$containerPayloads = @(
    "docker run -v /var/run/docker.sock:/var/run/docker.sock container_id=abc123def456 mount docker.sock detected",
    "nsenter -t 1 -m -u -i -n -p -- /bin/bash container_id=abc123def456 namespace breakout",
    "capsh --print showing capabilities container_id=abc123def456 privilege check",
    "kubectl exec --privileged pod/escape container_id=abc123def456 hostPID=true"
)

foreach ($payload in $containerPayloads) {
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    Add-Content -Path $containerLog -Value "$ts CRITICAL $payload"
    Write-Attack "Escape: $($payload.Substring(0, [Math]::Min(80, $payload.Length)))..."
    Start-Sleep -Seconds 2
}

# ==============================================================================
# STAGE 6: Second wave - different attacker IPs (tests correlation reset)
# ==============================================================================
Write-Stage "STAGE 6: Second SSH brute force wave from NEW attacker 10.50.60.70"

$attacker2 = "10.50.60.70"
for ($i = 1; $i -le 5; $i++) {
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    Add-Content -Path $authLog -Value "$ts sshd[5678]: authentication failure for admin from $attacker2 port 22"
    Write-Attack "SSH wave 2 attempt $i/5 from $attacker2"
    Start-Sleep -Milliseconds 600
}

Start-Sleep -Seconds 3

# ==============================================================================
# SUMMARY & VERIFICATION
# ==============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  SIMULATION COMPLETE" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

Write-Info "Expected detections:"
Write-Host "    - ssh_brute_force       x2 (two attacker IPs hit threshold)" -ForegroundColor White
Write-Host "    - sqli_detection        x4 (each SQLi payload)" -ForegroundColor White
Write-Host "    - web_path_traversal    x4 (each traversal payload)" -ForegroundColor White
Write-Host "    - privilege_escalation  x5 (each priv-esc pattern)" -ForegroundColor White
Write-Host "    - rdp_brute_force       x1 (threshold reached)" -ForegroundColor White
Write-Host "    - container_escape      x4 (each escape pattern)" -ForegroundColor White
Write-Host ""
Write-Host "    TOTAL: ~20 detections, ~20 pending response actions" -ForegroundColor Yellow
Write-Host ""

# Query the API for stats
Write-Info "Querying Sentinel API..."
try {
    # Create a web session with login cookie
    $loginBody = @{ username = "admin"; password = "sentinel" }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:8082/login" -Method POST -Body $loginBody -WebSession $session -UseBasicParsing

    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8082/api/health" -WebSession $session
    Write-Host ""
    Write-OK "Agent Status: $($health.status)"
    Write-OK "Total Events: $($health.events)"
    Write-OK "Open Incidents: $($health.incidents)"
    Write-OK "Pending Actions: $($health.pending_actions)"
    Write-OK "Active Rules: $($health.active_rules)"
} catch {
    Write-Info "Could not query API (is sentinel running on :8082?)"
}

Write-Host ""
Write-Info "Now go to http://127.0.0.1:8082 to:"
Write-Host "    1. View all detections on the Dashboard" -ForegroundColor White
Write-Host "    2. Approve/Deny actions on the Approval Queue page" -ForegroundColor White
Write-Host "    3. Check the Incidents page for grouped incidents" -ForegroundColor White
Write-Host "    4. Review the Audit Log for full timeline" -ForegroundColor White
Write-Host ""

# ==============================================================================
# BONUS: Test the approval workflow via API
# ==============================================================================
Write-Stage "BONUS: Testing approval workflow via API"

try {
    # Get pending actions
    $approvalPage = Invoke-WebRequest -Uri "http://127.0.0.1:8082/approval" -WebSession $session -UseBasicParsing
    
    # Extract first action ID from the page (look for act_ pattern)
    $actionIds = [regex]::Matches($approvalPage.Content, 'act_\d+') | Select-Object -ExpandProperty Value -Unique
    
    if ($actionIds.Count -gt 0) {
        $firstAction = $actionIds[0]
        Write-Info "Found $($actionIds.Count) pending actions"
        Write-Attack "Approving action: $firstAction (dry-run mode - won't actually execute)"
        
        $null = Invoke-WebRequest -Uri "http://127.0.0.1:8082/api/approve/$firstAction" `
            -Method POST -WebSession $session -UseBasicParsing
        Write-OK "Action $firstAction approved successfully!"
        
        if ($actionIds.Count -gt 1) {
            $secondAction = $actionIds[1]
            Write-Attack "Denying action: $secondAction"
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:8082/api/deny/$secondAction" `
                -Method POST -WebSession $session -UseBasicParsing
            Write-OK "Action $secondAction denied!"
        }
        
        Write-Host ""
        Write-Info "Check the Approval Queue and Audit Log to see the results!"
    } else {
        Write-Info "No pending actions found to test workflow"
    }
} catch {
    Write-Info "Approval workflow test skipped: $_"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  ALL TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
