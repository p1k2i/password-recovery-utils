param(
    [string]$RarFile = "file.rar",
    [string]$OutputFile
)

# If OutputFile is not specified, use the RAR filename with .hash extension
if (-not $OutputFile) {
    $OutputFile = "$RarFile.hash"
}

# Run rar2john and capture the output
$output = & rar2john $RarFile

# Process the output: remove everything up to and including the first ":"
# rar2john outputs: "file.rar:$rar5$16$..." we need to keep only "$rar5$16$..."
$processedOutput = $output -replace '^[^:]*:', ''

# Write to file with UTF-8 encoding (without BOM) and LF line endings
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutputFile, $processedOutput, $utf8NoBom)

Write-Host "Hash written to $OutputFile"
