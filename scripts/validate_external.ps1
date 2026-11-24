<#
.SYNOPSIS
    Runs MANTIS against crAPI and VAmPI (requires Docker).
.DESCRIPTION
    This script expects the target lab to be running locally.
    It will scan the API, save the results, and print a summary.
#>

param (
    [string]$Target = "vampi", # "vampi" or "crapi"
    [string]$OutputDir = "docs/validation/results"
)

$ErrorActionPreference = "Stop"

# Configuración de los laboratorios
$Labs = @{
    "vampi" = @{
        Spec = "examples/openapi/vampi.json" # Necesitaremos generar esto
        BaseUrl = "http://localhost:5000"
        AdminKey = "admin_token"
        UserKey = "user_token"
    }
    "crapi" = @{
        Spec = "examples/openapi/crapi.json" # Necesitaremos generar esto
        BaseUrl = "http://localhost:8888"
        AdminKey = "admin_token"
        UserKey = "user_token"
    }
}

if (-not $Labs.ContainsKey($Target)) {
    Write-Error "Target '$Target' not supported. Use 'vampi' or 'crapi'."
}

$Config = $Labs[$Target]

Write-Host "=== MANTIS External Validation: $($Target.ToUpper()) ===" -ForegroundColor Cyan

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# 1. Verificar que el laboratorio está corriendo
Write-Host "[1/3] Checking if $Target is running at $($Config.BaseUrl)..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$($Config.BaseUrl)/health" -TimeoutSec 5 -ErrorAction Stop
    Write-Host "  -> OK" -ForegroundColor Green
} catch {
    Write-Error "Could not reach $($Config.BaseUrl). Is Docker running?"
}

# 2. Verificar que tenemos la especificación OpenAPI
if (-not (Test-Path $Config.Spec)) {
    Write-Warning "Spec file not found: $($Config.Spec)"
    Write-Warning "Please generate it (e.g. curl $($Config.BaseUrl)/openapi.json > $($Config.Spec))"
    Write-Warning "Skipping scan."
    exit 0
}

# 3. Ejecutar MANTIS
Write-Host "[2/3] Running MANTIS scan..." -ForegroundColor Yellow
$outputFile = Join-Path $OutputDir "$Target-results.json"

$env:MANTIS_KEY_ADMIN = $Config.AdminKey
$env:MANTIS_KEY_USER = $Config.UserKey

python -m mantis scan $Config.Spec `
    --base-url $Config.BaseUrl `
    --identity admin `
    --identity user `
    --sequences `
    --privileged-operations "admin" `
    --reset-endpoint "/reset" `
    --max-requests 300 `
    --format json `
    --no-log > $outputFile

$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "  -> No findings." -ForegroundColor Green
} elseif ($exitCode -eq 1) {
    Write-Host "  -> Findings detected. Saved to $outputFile" -ForegroundColor Red
} else {
    Write-Warning "  -> Scan exited with code $exitCode. Check $outputFile."
}

# 4. Imprimir resumen
Write-Host "[3/3] Summary" -ForegroundColor Yellow
$json = Get-Content $outputFile -Raw | ConvertFrom-Json
$count = $json.findings.Count
Write-Host "  Total findings: $count"

if ($count -gt 0) {
    $json.findings | Group-Object type | ForEach-Object {
        Write-Host "  - $($_.Name): $($_.Count)"
    }
}

Write-Host "Done." -ForegroundColor Cyan