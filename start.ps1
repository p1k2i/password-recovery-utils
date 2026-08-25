<#
.SYNOPSIS
    Guided entry point for password-recovery-utils: checks prerequisites and
    walks the user through hashing a RAR archive, resuming a run, preparing a
    seed file, or launching a new hashcat_run.

.DESCRIPTION
    This script only orchestrates the other scripts/tools in this repo
    (rar2hash.ps1, resume.ps1, crack_runner.py) -- it does not duplicate their
    logic. Menu choices simply collect the arguments crack_runner.py expects
    and invoke it, or dispatch to the existing helper scripts.
#>

$ErrorActionPreference = 'Stop'

# Repo root = directory this script lives in, regardless of caller's cwd
$RepoRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -Path $RepoRoot

# --- Helpers ----------------------------------------------------------------

function Write-Banner {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Test-CommandExists {
    param([string]$Name)
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
    return $null -ne $cmd
}

function Test-Prerequisite {
    param(
        [string]$Name,
        [string]$InstallHint
    )
    if (Test-CommandExists -Name $Name) {
        Write-Host "  [OK]   $Name found" -ForegroundColor Green
        return $true
    } else {
        Write-Host "  [MISS] $Name not found on PATH" -ForegroundColor Red
        if ($InstallHint) {
            Write-Host "         $InstallHint" -ForegroundColor Yellow
        }
        return $false
    }
}

function Read-NonEmpty {
    param(
        [string]$Prompt,
        [string]$Default = $null
    )
    while ($true) {
        if ($Default) {
            $value = Read-Host "$Prompt [default: $Default]"
            if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
            return $value
        } else {
            $value = Read-Host $Prompt
            if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
            Write-Host "  This value is required." -ForegroundColor Yellow
        }
    }
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$DefaultYes = $false
    )
    $suffix = if ($DefaultYes) { "(Y/n)" } else { "(y/N)" }
    $answer = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultYes }
    return ($answer -eq 'y' -or $answer -eq 'Y')
}

function Wait-ForKey {
    Write-Host ""
    Read-Host "Press Enter to return to the menu" | Out-Null
}

function Read-DictGenArgs {
    Write-Host ""
    Write-Host "Dictionary generation options (passed to dict_gen.py):" -ForegroundColor Cyan

    $parts = New-Object System.Collections.Generic.List[string]

    $minLength = Read-NonEmpty -Prompt "  Minimum password length" -Default "0"
        $parts.Add("--min-length"); $parts.Add($minLength)

    $maxLength = Read-NonEmpty -Prompt "  Maximum password length" -Default "32"
        $parts.Add("--max-length"); $parts.Add($maxLength)

    $maxRepeat = Read-Host "  Max times a single piece may repeat per password (blank = unlimited)"
    if (-not [string]::IsNullOrWhiteSpace($maxRepeat)) {
        $parts.Add("--max-repeat"); $parts.Add($maxRepeat)
    }

    Write-Host "  Split generated dictionary files by size or by word count:" -ForegroundColor DarkGray
    $splitSize = Read-Host "  Split by file size, e.g. 10MB, 500K, 2GiB (blank = skip)"
    if (-not [string]::IsNullOrWhiteSpace($splitSize)) {
        $parts.Add("--split-size"); $parts.Add($splitSize)
    } else {
        $splitCount = Read-NonEmpty -Prompt "  Split by word count (or 'skip')" -Default "1000000"
        if ($splitCount.Trim().ToLower() -ne 'skip') {
            $parts.Add("--split-count"); $parts.Add($splitCount)
        }
    }

    $quiet = Read-YesNo -Prompt "  Suppress dict_gen's live progress display (--quiet)?" -DefaultYes $false
    if ($quiet) { $parts.Add("--quiet") }

    $advanced = Read-Host "  Any other dict_gen.py arguments, quoted as one string (advanced, optional)"
    if (-not [string]::IsNullOrWhiteSpace($advanced)) {
        $parts.Add($advanced)
    }

    return ($parts -join ' ')
}

# --- Prerequisite checks ------------------------------------------------------

function Invoke-PrereqCheck {
    Write-Banner "Prerequisite Check"

    $hashcatOk = Test-Prerequisite -Name "hashcat" `
        -InstallHint "Download from https://hashcat.net/hashcat/ and add its folder to PATH."
    $rar2johnOk = Test-Prerequisite -Name "rar2john" `
        -InstallHint "Install John the Ripper (jumbo build) and add its 'run' folder to PATH."
    $pythonOk = Test-Prerequisite -Name "python" `
        -InstallHint "Install Python 3 from https://python.org and add it to PATH."

    Write-Host ""
    if ($hashcatOk -and $rar2johnOk -and $pythonOk) {
        Write-Host "All prerequisites are satisfied." -ForegroundColor Green
    } else {
        Write-Host "One or more prerequisites are missing. Install them before starting a crack." -ForegroundColor Yellow
    }

    Wait-ForKey
}

# --- Menu actions -------------------------------------------------------------

function Invoke-Rar2Hash {
    Write-Banner "Get Hash From RAR Archive"

    if (-not (Test-CommandExists -Name "rar2john")) {
        Write-Host "rar2john was not found on PATH. Run the prerequisite check first." -ForegroundColor Red
        Wait-ForKey
        return
    }

    $scriptPath = Join-Path $RepoRoot "rar2hash.ps1"
    if (-not (Test-Path -Path $scriptPath -PathType Leaf)) {
        Write-Host "Error: rar2hash.ps1 not found at $scriptPath" -ForegroundColor Red
        Wait-ForKey
        return
    }

    & $scriptPath
    Wait-ForKey
}

function Invoke-Resume {
    Write-Banner "Resume Existing Run"

    $scriptPath = Join-Path $RepoRoot "resume.ps1"
    if (-not (Test-Path -Path $scriptPath -PathType Leaf)) {
        Write-Host "Error: resume.ps1 not found at $scriptPath" -ForegroundColor Red
        Wait-ForKey
        return
    }

    # List existing hashcat_run_* directories as a convenience, if any exist
    $runDirs = Get-ChildItem -Path $RepoRoot -Directory -Filter "hashcat_run_*" -ErrorAction SilentlyContinue
    if ($runDirs) {
        Write-Host "Existing run directories:" -ForegroundColor Cyan
        foreach ($dir in $runDirs) {
            Write-Host "  - $($dir.Name)"
        }
        Write-Host ""
    }

    & $scriptPath
    Wait-ForKey
}

function Invoke-NewSeed {
    Write-Banner "Create New Seed File"

    $examplePath = Join-Path $RepoRoot "seed_example.json"
    if (-not (Test-Path -Path $examplePath -PathType Leaf)) {
        Write-Host "Error: seed_example.json not found at $examplePath" -ForegroundColor Red
        Wait-ForKey
        return
    }

    $newName = Read-NonEmpty -Prompt "Name for the new seed file" -Default "seed.json"
    if (-not ($newName -match '\.json$')) {
        $newName = "$newName.json"
    }
    $newPath = Join-Path $RepoRoot $newName

    if (Test-Path -Path $newPath -PathType Leaf) {
        $overwrite = Read-YesNo -Prompt "File '$newName' already exists. Overwrite?" -DefaultYes $false
        if (-not $overwrite) {
            Write-Host "Cancelled." -ForegroundColor Yellow
            Wait-ForKey
            return
        }
    }

    Copy-Item -Path $examplePath -Destination $newPath -Force
    Write-Host "Created $newName from seed_example.json." -ForegroundColor Green

    try {
        Invoke-Item -Path $newPath
        Write-Host "Opened $newName in the default editor." -ForegroundColor Green
    } catch {
        Write-Host "Could not open the file automatically. Edit it manually at: $newPath" -ForegroundColor Yellow
    }

    Wait-ForKey
}

function Invoke-NewRun {
    Write-Banner "Start New Hashcat Run"

    if (-not (Test-CommandExists -Name "python")) {
        Write-Host "python was not found on PATH. Run the prerequisite check first." -ForegroundColor Red
        Wait-ForKey
        return
    }
    if (-not (Test-CommandExists -Name "hashcat")) {
        Write-Host "hashcat was not found on PATH. Run the prerequisite check first." -ForegroundColor Red
        Wait-ForKey
        return
    }

    # --- Required: seed file ---
    $defaultSeed = if (Test-Path (Join-Path $RepoRoot "seed.json")) { "seed.json" } else { $null }
    $seed = Read-NonEmpty -Prompt "Seed dictionary file (.txt or .json)" -Default $defaultSeed
    if (-not (Test-Path -Path (Join-Path $RepoRoot $seed) -PathType Leaf)) {
        Write-Host "Error: seed file '$seed' does not exist." -ForegroundColor Red
        Wait-ForKey
        return
    }

    # --- Required: target hash ---
    $defaultTarget = $null
    $hashFiles = Get-ChildItem -Path $RepoRoot -Filter "*.hash" -File -ErrorAction SilentlyContinue
    if ($hashFiles) {
        Write-Host "Found hash file(s):" -ForegroundColor Cyan
        foreach ($f in $hashFiles) { Write-Host "  - $($f.Name)" }
        Write-Host ""
        $defaultTarget = $hashFiles[0].Name
    }
    $target = Read-NonEmpty -Prompt "Target: a hash string, or a path to a file containing the hash" -Default $defaultTarget

    # --- Required: hash type ---
    Write-Host ""
    Write-Host "Common RAR hash types: 13000 = RAR5, 23800 = RAR4" -ForegroundColor DarkGray
    $hashType = Read-NonEmpty -Prompt "Hashcat hash type (-m)" -Default "13000"

    # --- Optional: work dir / prefix ---
    $workDir = Read-Host "Work directory for dictionary files [default: ./hashcat_run_<timestamp>]"
    $prefix = Read-Host "Output file prefix [default: dict]"

    # --- Optional: performance mode ---
    $performance = Read-YesNo -Prompt "Enable performance mode (-O, workload, --force)?" -DefaultYes $true
    $workload = "3"
    if ($performance) {
        Write-Host "Workload profiles: 1=Low, 2=Default, 3=High, 4=Nightmare" -ForegroundColor DarkGray
        $workload = Read-NonEmpty -Prompt "Workload" -Default "3"
    }

    # --- Optional: dictgen-args (guided, one question per option) / hashcat-args ---
    $dictgenArgs = Read-DictGenArgs
    $hashcatArgs = Read-Host "Extra hashcat arguments, e.g. `"-w 2`" [optional]"

    # --- Optional: keep dictionaries / force ---
    $keepDicts = Read-YesNo -Prompt "Keep generated dictionary files instead of deleting after use?" -DefaultYes $false
    $forceReuse = Read-YesNo -Prompt "Allow reusing an existing work directory (deletes matching files first)?" -DefaultYes $false

    # --- Build command line ---
    $pyArgs = @($seed, $target, "-m", $hashType)

    if ($workDir) { $pyArgs += @("--work-dir", $workDir) }
    if ($prefix) { $pyArgs += @("--prefix", $prefix) }
    if ($performance) {
        $pyArgs += "--performance"
        $pyArgs += @("--workload", $workload)
    }
    if ($dictgenArgs) { $pyArgs += @("--dictgen-args", $dictgenArgs) }
    if ($hashcatArgs) { $pyArgs += @("--hashcat-args", $hashcatArgs) }
    if ($keepDicts) { $pyArgs += "--keep-dictionaries" }
    if ($forceReuse) { $pyArgs += "--force" }

    Write-Host ""
    Write-Host "About to run:" -ForegroundColor Cyan
    $displayArgs = ($pyArgs | ForEach-Object {
        if ($_ -match '\s') { "`"$_`"" } else { $_ }
    }) -join ' '
    Write-Host "  python crack_runner.py $displayArgs" -ForegroundColor White
    Write-Host ""

    $confirm = Read-YesNo -Prompt "Proceed?" -DefaultYes $true
    if (-not $confirm) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        Wait-ForKey
        return
    }

    Write-Host ""
    & python crack_runner.py @pyArgs

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Run completed successfully." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "Run exited with code: $LASTEXITCODE" -ForegroundColor Red
    }

    Wait-ForKey
}

# --- Main menu ----------------------------------------------------------------

function Show-MainMenu {
    Write-Banner "Password Recovery Utils"
    Write-Host "  1. Check prerequisites (hashcat, rar2john)"
    Write-Host "  2. Get hash from a RAR archive"
    Write-Host "  3. Resume an existing run"
    Write-Host "  4. Create a new seed.json and open it"
    Write-Host "  5. Start a new hashcat run"
    Write-Host "  Q. Quit"
    Write-Host ""
}

while ($true) {
    Show-MainMenu
    $choice = Read-Host "Select an option"

    switch ($choice.Trim().ToUpper()) {
        "1" { Invoke-PrereqCheck }
        "2" { Invoke-Rar2Hash }
        "3" { Invoke-Resume }
        "4" { Invoke-NewSeed }
        "5" { Invoke-NewRun }
        "Q" { Write-Host "Goodbye." -ForegroundColor Cyan; exit 0 }
        default {
            Write-Host "Invalid option: $choice" -ForegroundColor Yellow
            Start-Sleep -Milliseconds 800
        }
    }
}
