$headers = @{
    "Authorization" = "Bearer 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"
    "Content-Type"  = "application/json"
}

$body = @{
    model    = "z-ai/glm-4.5-air:free"
    messages = @(
        @{ role = "system"; content = "You are a security assistant. Use tools when needed." }
        @{ role = "user"; content = "List all detection rules" }
    )
    tools = @(
        @{
            type     = "function"
            function = @{
                name        = "list_rules"
                description = "List all detection rules"
                parameters  = @{ type = "object"; properties = @{} }
            }
        }
    )
    max_tokens = 500
} | ConvertTo-Json -Depth 10

try {
    $resp = Invoke-RestMethod -Uri "https://openrouter.ai/api/v1/chat/completions" `
        -Method POST -Headers $headers -Body $body -TimeoutSec 60
    Write-Host "=== SUCCESS ==="
    Write-Host "Model: $($resp.model)"
    Write-Host "Finish Reason: $($resp.choices[0].finish_reason)"
    Write-Host "Content: $($resp.choices[0].message.content)"
    if ($resp.choices[0].message.tool_calls) {
        Write-Host "Tool Calls:"
        $resp.choices[0].message.tool_calls | ForEach-Object {
            Write-Host "  - $($_.function.name)($($_.function.arguments))"
        }
    }
} catch {
    Write-Host "=== FAIL ==="
    Write-Host $_.Exception.Message
    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
    Write-Host $reader.ReadToEnd()
}
