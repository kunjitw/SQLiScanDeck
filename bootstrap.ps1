<#
  bootstrap.ps1 - one-time setup for the PORTABLE runtime.

  Downloads a self-contained embeddable Python into .\python (never touches the
  user's system python), enables pip, installs the backend deps + ghauri, and
  fetches sqlmap into .\tools\sqlmap. Safe to re-run; it skips finished steps.

  Requires internet ONLY for this first run. Afterwards the folder is portable.
  ASCII-only messages so it is safe under any Windows codepage.
#>
$ErrorActionPreference = "Stop"   # cmdlet failures throw and are caught below
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyDir     = Join-Path $Root "python"
$PyExe     = Join-Path $PyDir "python.exe"
$ToolsDir  = Join-Path $Root "tools"
$SqlmapDir = Join-Path $ToolsDir "sqlmap"
$ReqFile   = Join-Path $Root "backend\requirements.txt"
$Tmp       = Join-Path $env:TEMP ("sqlmap_auto_boot_" + [System.Guid]::NewGuid().ToString("N").Substring(0,8))
$PyVersion = "3.11.9"

New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
function Say($m) { Write-Host ("[bootstrap] " + $m) -ForegroundColor Cyan }
function Get-File($url, $out) {
  Say ("download " + $url)
  Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
}

# Download a GitHub source zip and move its top-level folder to $dest.
# Robust to the archive folder name (ghauri-master / sqlmap-master / *-main ...):
# we extract into a private subfolder and take whatever single dir appears.
function Fetch-Source($url, $dest, $name) {
  $zip = Join-Path $Tmp ($name + ".zip")
  Get-File $url $zip
  $ex = Join-Path $Tmp ($name + "_x")
  if (Test-Path $ex) { Remove-Item -Recurse -Force $ex }
  New-Item -ItemType Directory -Force -Path $ex | Out-Null
  Expand-Archive -Path $zip -DestinationPath $ex -Force
  $top = Get-ChildItem -Path $ex -Directory | Select-Object -First 1
  if (-not $top) { throw ("${name}: extracted archive contained no folder") }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
  if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
  Move-Item $top.FullName $dest
}

# Find an already-present tool dir under tools/, tolerating version suffixes
# (e.g. user dropped in sqlmap-1.10 / ghauri-1.4.3). Returns path or $null.
function Find-ToolDir($prefix, $markerRel) {
  if (-not (Test-Path $ToolsDir)) { return $null }
  $dirs = Get-ChildItem -Path $ToolsDir -Directory -ErrorAction SilentlyContinue |
          Where-Object { $_.Name.ToLower().StartsWith($prefix.ToLower()) } | Sort-Object Name
  foreach ($d in $dirs) {
    if (Test-Path (Join-Path $d.FullName $markerRel)) { return $d.FullName }
  }
  return $null
}

# Run the portable python and check ONLY its exit code. Native stderr must not
# turn into a terminating PowerShell error, so drop to Continue during the call.
function Run-Py {
  param([Parameter(Mandatory=$true)][string[]]$PyArgs, [string]$What = "python")
  $old = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  & $PyExe @PyArgs
  $code = $LASTEXITCODE
  $ErrorActionPreference = $old
  if ($code -ne 0) { throw ("$What failed (exit code $code)") }
}

try {
  # 1) portable python -------------------------------------------------------
  if (-not (Test-Path $PyExe)) {
    Say "fetching portable Python $PyVersion (embeddable) ..."
    $embedZip = Join-Path $Tmp "python-embed.zip"
    Get-File "https://www.python.org/ftp/python/$PyVersion/python-$PyVersion-embed-amd64.zip" $embedZip
    New-Item -ItemType Directory -Force -Path $PyDir | Out-Null
    Expand-Archive -Path $embedZip -DestinationPath $PyDir -Force
  } else { Say "python\python.exe already present, skipping download." }

  # 2) enable site + site-packages so pip works in the embeddable build -------
  $pth = Get-ChildItem -Path $PyDir -Filter "python*._pth" | Select-Object -First 1
  if ($pth) {
    $lines = Get-Content $pth.FullName
    $out = @()
    foreach ($l in $lines) {
      if ($l -match "^\s*#\s*import site") { $out += "import site" }
      else { $out += $l }
    }
    if (-not ($out -contains "import site")) { $out += "import site" }
    if (-not ($out -contains "Lib\site-packages")) { $out += "Lib\site-packages" }
    Set-Content -Path $pth.FullName -Value $out -Encoding ascii
    Say ("enabled site-packages (" + $pth.Name + ")")
  }

  # 3) pip (embeddable python ships WITHOUT pip -> install via get-pip) -------
  $pipPkg = Join-Path $PyDir "Lib\site-packages\pip"
  if (-not (Test-Path $pipPkg)) {
    Say "installing pip (embeddable python has none by default) ..."
    $getpip = Join-Path $Tmp "get-pip.py"
    Get-File "https://bootstrap.pypa.io/get-pip.py" $getpip
    Run-Py @($getpip, "--no-warn-script-location") "get-pip"
  } else { Say "pip already present." }

  # 4) backend deps ----------------------------------------------------------
  Say "installing backend dependencies (fastapi / uvicorn) ..."
  Run-Py @("-m", "pip", "install", "--upgrade", "pip", "--no-warn-script-location") "pip upgrade"
  Run-Py @("-m", "pip", "install", "--no-warn-script-location", "-r", $ReqFile) "pip install requirements"

  # 4b) ghauri (GitHub SOURCE, run directly; NOT pip-installed) ---------------
  #     Accept a version-suffixed dir the user dropped in (ghauri-1.4.3, ...).
  $existingGhauri = Find-ToolDir "ghauri" "ghauri\scripts\ghauri.py"
  if ($existingGhauri) {
    Say ("found ghauri source: " + $existingGhauri + " (skipping download)")
  } else {
    Say "fetching ghauri source from GitHub (latest) ..."
    Fetch-Source "https://github.com/r0oth3x49/ghauri/archive/refs/heads/master.zip" (Join-Path $ToolsDir "ghauri") "ghauri"
  }
  # ghauri is run from source; only its dependency LIBRARIES are pip-installed.
  Say "installing ghauri's dependency libraries (not ghauri itself) ..."
  Run-Py @("-m", "pip", "install", "--no-warn-script-location",
           "tldextract", "colorama", "requests", "chardet", "ua_generator") "pip install ghauri deps"

  # 5) sqlmap (GitHub SOURCE; accept a version-suffixed dir too) --------------
  $existingSqlmap = Find-ToolDir "sqlmap" "sqlmapapi.py"
  if ($existingSqlmap) {
    Say ("found sqlmap source: " + $existingSqlmap + " (skipping download)")
  } else {
    Say "fetching sqlmap source from GitHub (latest) ..."
    Fetch-Source "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip" $SqlmapDir "sqlmap"
  }

  # 6) verify ----------------------------------------------------------------
  Say "verifying environment ..."
  Run-Py @("-c", "import fastapi, uvicorn; print('  fastapi/uvicorn OK')") "verify fastapi"
  $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  & $PyExe -c "import requests, colorama, tldextract, chardet, ua_generator; print('  ghauri deps OK')"
  if ($LASTEXITCODE -ne 0) { Write-Host "  (warning) ghauri deps missing; ghauri scans may not work" -ForegroundColor Yellow }
  $ErrorActionPreference = $old
  if (Find-ToolDir "ghauri" "ghauri\scripts\ghauri.py") { Write-Host "  ghauri source OK" }
  else { Write-Host "  (warning) ghauri source not found under tools\" -ForegroundColor Yellow }
  if (Find-ToolDir "sqlmap" "sqlmapapi.py") { Write-Host "  sqlmap OK" }
  else { Write-Host "  (warning) sqlmap not found under tools\" -ForegroundColor Yellow }

  Write-Host ""
  Write-Host "==============================================" -ForegroundColor Green
  Write-Host " Setup complete. Now run  start.bat  to open the web UI." -ForegroundColor Green
  Write-Host "==============================================" -ForegroundColor Green
}
catch {
  Write-Host ""
  Write-Host ("[bootstrap] FAILED: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host "Check your internet connection and retry. On an intranet you can" -ForegroundColor Yellow
  Write-Host "manually place python\ and tools\sqlmap\ from another machine." -ForegroundColor Yellow
  exit 1
}
finally {
  try { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue } catch {}
}
