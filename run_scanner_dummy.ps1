<#
.SYNOPSIS
  Setup Python venv, install deps, and run the scanner in dummy mode.

.DESCRIPTION
  - Intended for Windows PowerShell.
  - Runs: python main.py --mode dummy --file <json> --print-table
  - Does not touch AWS or create resources.
#>

param(
  [string] $VenvDir = ".venv",
  [string] $DummyFile = "dummy_data/sample_aws_resources.json",
  [switch] $RecreateVenv
)

function Fail($msg) {
  Write-Host "ERROR: $msg" -ForegroundColor Red
  exit 1
}

Write-Host "=== Dummy scan: setup and run ===" -ForegroundColor Cyan

# 1. Check Python
Write-Host "`n1) Checking Python installation..."
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Fail "Python not found in PATH. Install Python 3.8+ and re-run this script." }
Write-Host "Python found: $($py.Path)"

# 2. Optionally recreate venv
if ($RecreateVenv -and (Test-Path $VenvDir)) {
  Write-Host "`n2) Recreating virtual environment (removing existing $VenvDir)..."
  Remove-Item -Recurse -Force $VenvDir
}

# 3. Create venv if missing
if (-not (Test-Path $VenvDir)) {
  Write-Host "`n3) Creating virtual environment at $VenvDir..."
  & python -m venv $VenvDir
  if ($LASTEXITCODE -ne 0) { Fail "Failed to create virtual environment." }
} else {
  Write-Host "`n3) Virtual environment already exists at $VenvDir"
}

# 4. Activate venv for this session
Write-Host "`n4) Activating virtual environment..."
$activate = Join-Path $VenvDir "Scripts\Activate.ps1"
if (-not (Test-Path $activate)) { Fail "Activation script not found at $activate" }
. $activate
if (-not $env:VIRTUAL_ENV) { Fail "Failed to activate virtual environment." }
Write-Host "Activated venv: $env:VIRTUAL_ENV"

# 5. Install dependencies
Write-Host "`n5) Installing dependencies from requirements.txt..."
if (-not (Test-Path "requirements.txt")) { Fail "requirements.txt not found in project root." }
# Ensure pip is available via python -m pip to avoid launcher issues
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { Fail "pip install failed. Check output for errors." }

# 6. Validate dummy file exists
Write-Host "`n6) Validating dummy input file..."
if (-not (Test-Path $DummyFile)) {
  Fail "Dummy file not found: $DummyFile. Place your JSON at that path or pass -DummyFile <path>."
}
Write-Host "Using dummy file: $DummyFile"

# 7. Run the scanner in dummy mode
Write-Host "`n7) Running scanner in dummy mode..."
$cmd = "python main.py --mode dummy --file `"$DummyFile`" --print-table"
Write-Host "Command: $cmd" -ForegroundColor DarkCyan
Invoke-Expression $cmd
if ($LASTEXITCODE -ne 0) {
  Write-Host "Scanner returned a non-zero exit code. Check output above." -ForegroundColor Yellow
} else {
  Write-Host "Scanner completed." -ForegroundColor Green
}

# 8. Show reports directory contents (if any)
Write-Host "`n8) Reports directory (latest files):"
if (Test-Path "reports") {
  Get-ChildItem -Path "reports" -File | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime, Length | Format-Table
} else {
  Write-Host "No reports directory found. The scanner may not have produced output." -ForegroundColor Yellow
}

Write-Host "`nDone." -ForegroundColor Cyan
