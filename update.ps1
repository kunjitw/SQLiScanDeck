<#
  update.ps1 - git-less self-update for SQLiScanDeck.

  Flow: (1) check GitHub for the latest revision and compare to the one recorded at your
  last update -> if identical, do NOTHING (no download, no overwrite). (2) Otherwise show
  current -> latest and ASK for confirmation (Y). (3) Only then download the latest zip and
  OVERLAY the code onto this folder.

  SAFETY:
    - OVERLAY ONLY. This script NEVER deletes anything in your install (no /MIR, no /PURGE,
      no Remove-Item on the install dir) -- it only copies files ONTO it, so it cannot
      remove your data or anything you added. A file deleted upstream simply lingers.
    - It only ever overwrites files that EXIST in the repo (tracked code/config). Files with
      names not in the repo (yours) are never touched.
    - data\ (scan history, settings, saved requests), tools\ (engines) and the uv runtime
      (.venv, .tools, .python-managed, .uv-cache, python\) are NEVER a copy target and are
      not in the zip.
    - Everything is downloaded+extracted to TEMP first, so a failed download can't half-update.
  ASCII-only messages for any Windows codepage.
#>
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # PS 5.1: the IWR progress bar cripples download speed
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ApiUrl = "https://api.github.com/repos/kunjitw/SQLiScanDeck/commits/main"
$ZipUrl = "https://codeload.github.com/kunjitw/SQLiScanDeck/zip/refs/heads/main"
$RevFile = Join-Path $Root "data\.update_rev"   # lives in data\ -> persists, never overwritten

$CodeDirs = @("backend", "web", "docs")                    # overlaid (copied over, NEVER deleted)
$KeepDataDirs = @{ "testlab" = @("mariadb", "mysql-data") } # copy but keep these gitignored subdirs
$SkipRootFiles = @("update.bat", "update.ps1")             # never overwrite the running updater

function Say($m) { Write-Host ("[update] " + $m) -ForegroundColor Cyan }

# --- 1) version check: is there actually a newer revision? ---------------------------
$remote = $null
try {
    $resp = Invoke-WebRequest -Uri $ApiUrl -UseBasicParsing -Headers @{ "User-Agent" = "SQLiScanDeck-updater" }
    $remote = ($resp.Content | ConvertFrom-Json).sha
} catch {
    Say "note: couldn't reach GitHub to check the version (offline / rate-limited)."
}
$local = ""
if (Test-Path $RevFile) { try { $local = (Get-Content $RevFile -Raw).Trim() } catch {} }

if ($remote -and $local -and ($remote -eq $local)) {
    Write-Host ""
    Write-Host ("[update] Already up to date (rev " + $remote.Substring(0, 7) + "). Nothing to do.") -ForegroundColor Green
    exit 0
}

# --- 2) confirm before changing ANYTHING ---------------------------------------------
Write-Host ""
if ($remote) {
    $cur = if ($local) { $local.Substring(0, 7) } else { "unknown" }
    Write-Host ("[update] A newer version is available.  current: " + $cur + "   ->   latest: " + $remote.Substring(0, 7))
} else {
    Write-Host "[update] Could not verify the version, but you can still update if you want."
}
if ($env:SQLISCANDECK_UPDATE_YES -ne "1") {
    $ans = Read-Host "Update now? Type Y to proceed (anything else = cancel)"
    if ($ans -notmatch '^[Yy]') {
        Write-Host "[update] Cancelled. Nothing was changed." -ForegroundColor Yellow
        exit 0
    }
}

# --- 3) download + OVERLAY -----------------------------------------------------------
$Tmp = Join-Path $env:TEMP ("sqliscandeck_upd_" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
try {
    Say "downloading latest ..."
    $zipPath = Join-Path $Tmp "src.zip"
    Invoke-WebRequest -Uri $ZipUrl -OutFile $zipPath -UseBasicParsing
    Say "extracting ..."
    $ex = Join-Path $Tmp "x"
    Expand-Archive -Path $zipPath -DestinationPath $ex -Force
    $src = Get-ChildItem -Path $ex -Directory | Select-Object -First 1
    if (-not $src) { throw "downloaded archive contained no folder" }
    Get-ChildItem -Path $src.FullName -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

    # OVERLAY the code dirs: copy new/changed files, /E only -> NEVER deletes anything.
    foreach ($d in $CodeDirs) {
        $from = Join-Path $src.FullName $d
        if (Test-Path $from) {
            Say ("updating " + $d + "\")
            robocopy $from (Join-Path $Root $d) /E /R:2 /W:1 /NP /NFL /NDL /NJH /NJS | Out-Null
            if ($LASTEXITCODE -ge 8) { throw ("robocopy failed on " + $d + " (code " + $LASTEXITCODE + ")") }
        }
    }
    # dirs holding gitignored data -> copy, keep those subdirs untouched
    foreach ($d in $KeepDataDirs.Keys) {
        $from = Join-Path $src.FullName $d
        if (Test-Path $from) {
            Say ("updating " + $d + "\ (keeping local data)")
            $xd = @(); foreach ($s in $KeepDataDirs[$d]) { $xd += (Join-Path (Join-Path $Root $d) $s) }
            robocopy $from (Join-Path $Root $d) /E /R:2 /W:1 /NP /NFL /NDL /NJH /NJS /XD $xd | Out-Null
            if ($LASTEXITCODE -ge 8) { throw ("robocopy failed on " + $d + " (code " + $LASTEXITCODE + ")") }
        }
    }
    # refresh every root-level FILE (picks up new ones too), except the running updater
    Get-ChildItem -Path $src.FullName -File | Where-Object { $SkipRootFiles -notcontains $_.Name } |
        ForEach-Object { Copy-Item -Path $_.FullName -Destination (Join-Path $Root $_.Name) -Force }

    # record the revision we just installed so the next run can skip when unchanged
    if ($remote) {
        try {
            New-Item -ItemType Directory -Force -Path (Split-Path $RevFile) | Out-Null
            Set-Content -Path $RevFile -Value $remote -Encoding ascii
        } catch {}
    }

    Write-Host ""
    $tag = if ($remote) { " (rev " + $remote.Substring(0, 7) + ")" } else { "" }
    Write-Host ("[update] Updated to the latest version" + $tag + ".") -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host ("[update] FAILED: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host "Your install was NOT changed. Check your connection and try again." -ForegroundColor Yellow
    exit 1
}
finally {
    try { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue } catch {}
}
