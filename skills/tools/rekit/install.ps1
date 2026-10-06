# install.ps1 — rekit installer (Windows parity with install.sh)
#
# Steps:
#   1. install the optional fastembed dependency (py -m pip or python -m pip)
#   2. write the %USERPROFILE%\.local\bin\rekit.cmd shim
#   3. hint if the shim dir is not on PATH
#   4. verify with `rekit --version`
# Idempotent: safe to re-run; an existing shim is overwritten.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rekitDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$shimDir = Join-Path $env:USERPROFILE '.local\bin'
$shim = Join-Path $shimDir 'rekit.cmd'
$fastembedPin = 'fastembed==0.8.1'

Write-Host "rekit dir: $rekitDir"

# 1. optional fastembed (required by corpus build/search/similar, match, findings similar)
$fastembedOk = $false
foreach ($exe in @('py', 'python')) {
    if (Get-Command $exe -ErrorAction SilentlyContinue) {
        & $exe -c 'import fastembed' *> $null
        if ($LASTEXITCODE -eq 0) { $fastembedOk = $true; break }
    }
}
if ($fastembedOk) {
    Write-Host 'fastembed: already installed'
}
else {
    $installed = $false
    foreach ($exe in @('py', 'python')) {
        if (Get-Command $exe -ErrorAction SilentlyContinue) {
            & $exe -m pip install --user $fastembedPin
            if ($LASTEXITCODE -eq 0) { $installed = $true; break }
        }
    }
    if (-not $installed) {
        Write-Warning 'fastembed install failed — corpus/match/findings-similar will be unavailable'
    }
}

# 2. shim
New-Item -ItemType Directory -Force -Path $shimDir | Out-Null
$shimContent = @"
@echo off
set "PYTHONPATH=$rekitDir;%PYTHONPATH%"
python -m rekit %*
"@
Set-Content -LiteralPath $shim -Value $shimContent -Encoding ascii
Write-Host "shim: $shim"

# 3. PATH hint
$pathEntries = $env:Path -split ';'
if ($pathEntries -notcontains $shimDir) {
    Write-Host "note: $shimDir is not on PATH — add it via: setx PATH `"$shimDir;%PATH%`""
}

# 4. verification
Write-Host '== rekit --version =='
& $shim --version
if ($LASTEXITCODE -ne 0) {
    throw 'rekit --version failed'
}
Write-Host 'rekit installed OK'
