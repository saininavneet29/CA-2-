<#
.SYNOPSIS
  Automate environment setup and run the S3 misconfiguration scanner end to end.

.DESCRIPTION
  - Creates and activates a Python virtual environment
  - Installs Python dependencies from requirements.txt
  - Validates AWS Vault profile (scanner-user)
  - Runs the test harness that creates a temporary public bucket, runs the scanner, and cleans up
  - Runs a full live scan and saves reports to the reports directory

.NOTES
  Run this script from the project root (where main.py, test_public_bucket.py, and requirements.txt live).
#>

param(
  [string] $ProfileName = "scanner-user",
  [string] $Region = "eu-west-1",
  [string] $VenvDir = ".venv"
)

function Fail($msg) {
  Write-Host "ERROR: $msg" -ForegroundColor Red
  exit 1
}

Write-Host "=== Scanner setup and run script (AWS Vault version) ===" -ForegroundColor Cyan

# 1. Check Python
Write-Host "`n1) Checking Python installation..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
  Fail "Python not found in PATH. Install Python 3.8+ and re-run this script."
}
Write-Host "Python found at $($python.Path)"

# 2. Create virtual environment if missing
if (-not (Test-Path $VenvDir)) {
  Write-Host "`n2) Creating virtual environment in $VenvDir..."
  python -m venv $VenvDir
  if ($LASTEXITCODE -ne 0) { Fail "Failed to create virtual environment." }
} else {
  Write-Host "`n2) Virtual environment already exists at $VenvDir"
}

# 3. Activate virtual environment
Write-Host "`n3) Activating virtual environment..."
$activateScript = Join-Path $VenvDir "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) { Fail "Activation script not found at $activateScript" }
. $activateScript
if (-not $env:VIRTUAL_ENV) { Fail "Failed to activate virtual environment." }
Write-Host "Virtual environment activated: $env:VIRTUAL_ENV"

# 4. Install dependencies
Write-Host "`n4) Installing Python dependencies from requirements.txt..."
if (-not (Test-Path "requirements.txt")) { Fail "requirements.txt not found in project root." }
pip install --upgrade pip
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { Fail "pip install failed. Check output and fix dependency issues." }

# 5. Verify AWS Vault
Write-Host "`n5) Verifying AWS Vault and credentials for profile '$ProfileName'..."
$vault = Get-Command aws-vault -ErrorAction SilentlyContinue
if (-not $vault) { Fail "aws-vault not found. Install AWS Vault before running live mode." }

Write-Host "Attempting to call sts get-caller-identity using AWS Vault..."
try {
    $identity = aws-vault exec $ProfileName -- aws sts get-caller-identity 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "Unable to validate AWS Vault credentials for profile $ProfileName." }
    Write-Host "AWS identity (raw):"
    Write-Host $identity
} catch {
    Fail "AWS Vault call failed: $_"
}

# 6. Run test harness
Write-Host "`n6) Running test harness (temporary public bucket)..."
if (-not (Test-Path "test_public_bucket.py")) { Fail "test_public_bucket.py not found in project root." }
aws-vault exec $ProfileName -- python test_public_bucket.py
if ($LASTEXITCODE -ne 0) {
  Write-Host "Warning: test harness returned a non-zero exit code." -ForegroundColor Yellow
} else {
  Write-Host "Test harness completed successfully." -ForegroundColor Green
}

# 7. Run full live scanner
Write-Host "`n7) Running full live scanner (mode aws) and saving reports..."
aws-vault exec $ProfileName -- python main.py --mode aws --region $Region --print-table
if ($LASTEXITCODE -ne 0) {
  Write-Host "Scanner returned a non-zero exit code." -ForegroundColor Yellow
} else {
  Write-Host "Scanner run completed successfully." -ForegroundColor Green
}

# 8. Show report files
Write-Host "`n8) Listing reports directory..."
if (Test-Path "reports") {
  Get-ChildItem -Path "reports" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, LastWriteTime, Length |
    Format-Table
  Write-Host "`nOpen the latest HTML report in your browser to review findings."
} else {
  Write-Host "No reports directory found. The scanner may not have produced output." -ForegroundColor Yellow
}

Write-Host "`nScript finished." -ForegroundColor Cyan
