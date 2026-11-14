param([string]$BaseUrl = 'http://localhost')
$ErrorActionPreference = 'Stop'

function Read-Setting([string]$Name) {
    $envPath = Join-Path $PSScriptRoot '../api/.env'
    $lines = @(Get-Content -LiteralPath $envPath | Where-Object { $_ -match "^\s*$Name\s*=" })
    if ($lines.Count -ne 1) { throw "Expected exactly one $Name setting in api/.env" }
    $value = ($lines[0] -split '=', 2)[1].Trim()
    # Quotes delimit dotenv values; they are not part of the credential.
    if ($value.Length -ge 2 -and (
        ($value.StartsWith("'") -and $value.EndsWith("'")) -or
        ($value.StartsWith('"') -and $value.EndsWith('"')))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    return $value
}

$body = @{
    username = Read-Setting 'JUDGE_USERNAME'
    password = Read-Setting 'JUDGE_PASSWORD'
} | ConvertTo-Json

try {
    $login = Invoke-RestMethod "$BaseUrl/api/auth/login" -Method Post -ContentType 'application/json' -Body $body
    if (-not $login.access_token) { throw 'Login returned no access token' }
    Invoke-RestMethod "$BaseUrl/api/auth/me" -Headers @{ Authorization = "Bearer $($login.access_token)" }
} finally {
    $body = $null
    $login = $null
}
