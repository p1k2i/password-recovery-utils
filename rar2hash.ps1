# Convert RAR file to hashcat-compatible hash format
# Prompts user for RAR file path and generates hash output

# Display banner
Write-Host "================================" -ForegroundColor Cyan
Write-Host "  RAR to Hash Converter" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Prompt user for RAR file path
$rarFile = Read-Host "Enter the RAR file path (e.g., file.rar)"

# Validate that input was provided
if ([string]::IsNullOrWhiteSpace($rarFile)) {
    Write-Host "Error: RAR file path cannot be empty." -ForegroundColor Red
    exit 1
}

# Check if RAR file exists
if (-not (Test-Path -Path $rarFile -PathType Leaf)) {
    Write-Host "Error: File '$rarFile' does not exist." -ForegroundColor Red
    exit 1
}

# Check if file is a RAR file
if (-not ($rarFile -match '\.rar$')) {
    Write-Host "Warning: File does not have .rar extension. Proceeding anyway..." -ForegroundColor Yellow
}

# Set output file (RAR filename with .hash extension)
$outputFile = "$rarFile.hash"

# Check if output file already exists
if (Test-Path -Path $outputFile -PathType Leaf) {
    Write-Host ""
    $overwrite = Read-Host "Output file '$outputFile' already exists. Overwrite? (y/n)"
    if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""
Write-Host "Processing RAR file: $rarFile" -ForegroundColor Green

# Run rar2john and capture the output
try {
    $output = & rar2john $rarFile 2>&1
    
    # Check if rar2john executed successfully
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: rar2john failed. Make sure rar2john is installed and the file is valid." -ForegroundColor Red
        Write-Host "Output: $output" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error: Could not execute rar2john. Make sure it is installed and in PATH." -ForegroundColor Red
    exit 1
}

# Process the output: remove everything up to and including the first ":"
# rar2john outputs: "file.rar:$rar5$16$..." we need to keep only "$rar5$16$..."
$processedOutput = $output -replace '^[^:]*:', ''

# Validate that we got valid hash output
if ([string]::IsNullOrWhiteSpace($processedOutput)) {
    Write-Host "Error: No hash data extracted. The RAR file may be invalid or unencrypted." -ForegroundColor Red
    exit 1
}

# Write to file with UTF-8 encoding (without BOM) and LF line endings
try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($outputFile, $processedOutput, $utf8NoBom)
    Write-Host ""
    Write-Host "Success! Hash written to: $outputFile" -ForegroundColor Green
    Write-Host "Hash length: $($processedOutput.Length) characters" -ForegroundColor Green
} catch {
    Write-Host "Error: Could not write to output file '$outputFile'." -ForegroundColor Red
    Write-Host "Details: $_" -ForegroundColor Red
    exit 1
}
