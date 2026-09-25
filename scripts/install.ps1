# curl-style installer for the enclava CLI (native Windows, PowerShell 5.1+).
#
#   irm https://raw.githubusercontent.com/enclava-labs/cap/main/scripts/install.ps1 | iex
#
# Env overrides:
#   ENCLAVA_VERSION     release tag (default: latest)
#   ENCLAVA_INSTALL_DIR default: %USERPROFILE%\.enclava\bin
$ErrorActionPreference = 'Stop'

$Repo = 'enclava-labs/cap'
$Asset = 'enclava-windows-x86_64.tar.gz'

function Die([string]$msg) { Write-Error $msg; exit 1 }

# --- resolve version ---------------------------------------------------------
$version = if ($env:ENCLAVA_VERSION) { $env:ENCLAVA_VERSION } else { (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name }
if (-not $version.StartsWith('v')) { $version = "v$version" }

# --- detect architecture -------------------------------------------------------
switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { }
  'ARM64' { Die "Windows ARM64 builds are not published yet; see https://github.com/$Repo/releases" }
  default { Die "unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'" }
}

$installDir = if ($env:ENCLAVA_INSTALL_DIR) { $env:ENCLAVA_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.enclava\bin' }
Write-Host "Installing enclava $version (windows/x86_64) to $installDir"

# --- download + verify ---------------------------------------------------------
$tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName()))
$base = "https://github.com/$Repo/releases/download/$version"
Invoke-WebRequest "$base/$Asset" -OutFile "$tmp\$Asset"
Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile "$tmp\SHA256SUMS.txt"

$sumLine = Get-Content "$tmp\SHA256SUMS.txt" | Where-Object { $_ -match "$Asset`$" } | Select-Object -First 1
if (-not $sumLine) { Die "no checksum entry for $Asset in SHA256SUMS.txt" }
$expected = ($sumLine -split '\s+')[0]
$actual = (Get-FileHash -Algorithm SHA256 "$tmp\$Asset").Hash
if ($actual -ne $expected) { Die "checksum mismatch for ${Asset}: got $actual, want $expected" }

# --- install ---------------------------------------------------------------------
tar -xzf "$tmp\$Asset" -C $tmp
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item "$tmp\enclava.exe" (Join-Path $installDir 'enclava.exe') -Force
Remove-Item -Recurse -Force $tmp

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$installDir*") {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$installDir", 'User')
  Write-Host "Added $installDir to your user PATH; open a new terminal for it to take effect."
}
$env:Path = "$env:Path;$installDir"

& (Join-Path $installDir 'enclava.exe') --version
Write-Host "Installed enclava $version -> $installDir\enclava.exe"
