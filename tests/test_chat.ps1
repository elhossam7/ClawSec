$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# Login
Invoke-WebRequest -Uri "http://127.0.0.1:8082/login" `
    -Method POST `
    -Body "username=admin&password=sentinel" `
    -ContentType "application/x-www-form-urlencoded" `
    -UseBasicParsing -WebSession $session | Out-Null

Write-Host "Logged in. Sending chat..."

# Chat request
$body = @{
    message    = "i want to detect the ntlmrelay attack"
    session_id = "test-glm-1"
} | ConvertTo-Json

$resp = Invoke-RestMethod -Uri "http://127.0.0.1:8082/api/chat" `
    -Method POST -Body $body `
    -ContentType "application/json" `
    -WebSession $session -TimeoutSec 120

Write-Host "=== RESPONSE ==="
Write-Host "Response: $($resp.response)"
Write-Host ""
Write-Host "Tools Used: $($resp.tools_used)"
Write-Host "Actions: $($resp.actions_taken)"
