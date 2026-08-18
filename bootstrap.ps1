<#
  bootstrap.ps1 - fetch the ENGINES (sqlmap + ghauri SOURCE) into .\tools.

  Python and all Python dependencies are handled by uv (see start.bat / pyproject.toml),
  NOT here. This script ONLY grabs the two scanners, which are run from source and are
  not PyPI packages, so uv cannot manage them.

  start.bat calls this automatically on first run. You can also run it standalone (via
  bootstrap.bat) to pre-fetch the engines. Safe to re-run: it skips whatever is present.
  Requires internet for the first fetch only. ASCII-only messages for any codepage.
#>
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$ToolsDir  = Join-Path $Root "tools"
$SqlmapDir = Join-Path $ToolsDir "sqlmap"
$Tmp       = Join-Path $env:TEMP ("sqliscandeck_boot_" + [System.Guid]::NewGuid().ToString("N").Substring(0,8))

New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
function Say($m) { Write-Host ("[bootstrap] " + $m) -ForegroundColor Cyan }
function Get-File($url, $out) {
  Say ("download " + $url)
  Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
}

# Download a GitHub source zip and move its top-level folder to $dest. Tolerant of the
# archive's inner folder name (ghauri-master / sqlmap-master / *-main ...).
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
# (e.g. a user dropped in sqlmap-1.10 / ghauri-1.4.3). Returns path or $null.
function Find-ToolDir($prefix, $markerRel) {
  if (-not (Test-Path $ToolsDir)) { return $null }
  $dirs = Get-ChildItem -Path $ToolsDir -Directory -ErrorAction SilentlyContinue |
          Where-Object { $_.Name.ToLower().StartsWith($prefix.ToLower()) } | Sort-Object Name
  foreach ($d in $dirs) {
    if (Test-Path (Join-Path $d.FullName $markerRel)) { return $d.FullName }
  }
  return $null
}

try {
  # 1) ghauri (GitHub SOURCE; accept a version-suffixed dir the user dropped in) -------
  $existingGhauri = Find-ToolDir "ghauri" "ghauri\scripts\ghauri.py"
  if ($existingGhauri) {
    Say ("found ghauri source: " + $existingGhauri + " (skip)")
  } else {
    Say "fetching ghauri source from GitHub (latest) ..."
    Fetch-Source "https://github.com/r0oth3x49/ghauri/archive/refs/heads/master.zip" (Join-Path $ToolsDir "ghauri") "ghauri"
  }

  # 2) sqlmap (GitHub SOURCE; accept a version-suffixed dir too) -----------------------
  $existingSqlmap = Find-ToolDir "sqlmap" "sqlmapapi.py"
  if ($existingSqlmap) {
    Say ("found sqlmap source: " + $existingSqlmap + " (skip)")
  } else {
    Say "fetching sqlmap source from GitHub (latest) ..."
    Fetch-Source "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip" $SqlmapDir "sqlmap"
  }

  # 3) verify --------------------------------------------------------------------------
  if (Find-ToolDir "ghauri" "ghauri\scripts\ghauri.py") { Write-Host "  ghauri source OK" }
  else { Write-Host "  (warning) ghauri source not found under tools\" -ForegroundColor Yellow }
  if (Find-ToolDir "sqlmap" "sqlmapapi.py") { Write-Host "  sqlmap OK" }
  else { Write-Host "  (warning) sqlmap not found under tools\" -ForegroundColor Yellow }

  Write-Host ""
  Write-Host "[bootstrap] engines ready. start.bat will handle Python + deps via uv." -ForegroundColor Green
}
catch {
  Write-Host ""
  Write-Host ("[bootstrap] FAILED: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host "Check your connection and retry. On an intranet you can manually place" -ForegroundColor Yellow
  Write-Host "tools\sqlmap\ and tools\ghauri\ from another machine." -ForegroundColor Yellow
  exit 1
}
finally {
  try { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue } catch {}
}
