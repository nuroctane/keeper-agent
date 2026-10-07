param([string]$Python = 'py', [switch]$ClientOnly, [switch]$InstallChromium)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$venvPath = Join-Path $projectRoot '.venv'
if (-not (Test-Path -LiteralPath $venvPath)) {
    if ($Python -eq 'py') { & $Python -3.12 -m venv $venvPath }
    else { & $Python -m venv $venvPath }
    if ($LASTEXITCODE -ne 0) { throw 'Creating the environment failed. Supply -Python with a Python 3.11+ executable path.' }
}
$runtimePath = Join-Path $venvPath 'Scripts/python.exe'
$packageSpec = if ($ClientOnly) { $projectRoot } else { "$projectRoot[keeper,browser]" }
$constraints = Join-Path $projectRoot 'constraints-windows-py312.txt'
if (Test-Path -LiteralPath $constraints) {
    & $runtimePath -m pip install -c $constraints $packageSpec
} else {
    & $runtimePath -m pip install $packageSpec
}
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
if ($InstallChromium -and -not $ClientOnly) {
    & $runtimePath -m playwright install chromium
    if ($LASTEXITCODE -ne 0) { throw 'Browser installation failed.' }
}
Write-Host "Ready: $venvPath\Scripts\keeper-agent.exe"
Write-Host 'Read README.md before connecting a real vault. No Keeper credentials were requested or stored by setup.'
