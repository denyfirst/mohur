# Builds Mohur's Windows package (MSIX/APPX) into .work/dist/windows.
# The Microsoft Store signs what it publishes, so this build is unsigned.
# Pass the identity Partner Center gives the app; the defaults are for local tests.
param(
    [string]$IdentityName = 'Denyfirst.Mohur',
    [string]$Publisher = 'CN=Mohur Test'
)
# npm and electron-builder print warnings on stderr, which Windows PowerShell
# 5.1 would treat as fatal; each step is judged by its exit code instead.
$ErrorActionPreference = 'Continue'
Push-Location $PSScriptRoot
try {
    npm ci --ignore-scripts --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    npx electron-builder --projectDir ../../client --config ../packaging/windows/electron-builder.yml --win appx --x64 `
        "-c.appx.identityName=$IdentityName" "-c.appx.publisher=$Publisher"
    if ($LASTEXITCODE -ne 0) { throw 'electron-builder failed' }
} finally { Pop-Location }
