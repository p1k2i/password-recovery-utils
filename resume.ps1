# Resume hashcat cracking session
# Prompts user for the hashcat run directory and executes the resume command

# Display banner
Write-Host "================================" -ForegroundColor Cyan
Write-Host "  Hashcat Resume Script" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Prompt user for hashcat run directory
$hashcatRunDir = Read-Host "Enter the hashcat run directory name or path (e.g., hashcat_run_1787673413)"

# Validate that directory was provided
if ([string]::IsNullOrWhiteSpace($hashcatRunDir)) {
    Write-Host "Error: Directory path cannot be empty." -ForegroundColor Red
    exit 1
}

# Check if directory exists
$fullPath = Join-Path -Path (Get-Location) -ChildPath $hashcatRunDir
if (-not (Test-Path -Path $fullPath -PathType Container)) {
    Write-Host "Error: Directory '$fullPath' does not exist." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Resuming crack session from: $hashcatRunDir" -ForegroundColor Green
Write-Host ""

# Execute the resume command
python crack_runner.py --resume $hashcatRunDir

# Check exit code
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Resume completed successfully." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Resume failed with exit code: $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
