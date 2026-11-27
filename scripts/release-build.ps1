# Builds a Mohur release's server binaries so that any machine with the same
# source gets the same bytes, and writes SHA256SUMS for denyfirst's release key
# to sign. Nothing is signed or published here; docs/RELEASING.md has the steps.
# It runs in Windows PowerShell and in PowerShell on Linux: CI builds with it
# on both on every change, and the Reproduce workflow rebuilds each release.
#
#   ./scripts/release-build.ps1 -Version v0.1.0           # from the tagged commit
#   ./scripts/release-build.ps1 -Version v0.1.0 -DryRun   # any clean commit
param(
  [Parameter(Mandatory)][ValidatePattern('^v\d{1,4}\.\d{1,4}\.\d{1,4}$')][string]$Version,
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
# Every Go setting that can change the bytes is set here, not taken from the
# machine: its shell, or what `go env -w` stored.
$vars = 'GOENV', 'GOTOOLCHAIN', 'GOFLAGS', 'CGO_ENABLED', 'GOOS', 'GOARCH', 'GOAMD64', 'GOARM64', 'GOEXPERIMENT', 'GOFIPS140'
$saved = @{}
foreach ($k in $vars) { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
try {
  if (git status --porcelain) { throw 'The working tree has changes; a release is built from a clean commit.' }
  if (-not $DryRun) {
    $tags = @(git tag --points-at HEAD)
    if ($tags -notcontains $Version) { throw "HEAD is not tagged $Version. Check out the tag, or pass -DryRun." }
  }
  $out = Join-Path $root ".work/release/$Version"
  if (Test-Path $out) { throw "$out exists; move it away first." }

  # The Go that go.mod names, whichever is installed, and Go's defaults for
  # the rest. The same flags everywhere: no cgo, no paths, no VCS stamp, no
  # build id.
  $line = Select-String -Path go.mod -Pattern '^go (\d+\.\d+\.\d+)\s*$' -CaseSensitive | Select-Object -First 1
  if (-not $line) { throw 'go.mod names no exact Go version.' }
  $go = 'go' + $line.Matches[0].Groups[1].Value
  foreach ($k in $vars) { [Environment]::SetEnvironmentVariable($k, $null) }
  $env:GOENV = 'off'
  $env:GOTOOLCHAIN = $go
  $env:CGO_ENABLED = '0'
  $env:GOOS = 'linux'
  $env:GOFLAGS = '-trimpath -buildvcs=false'
  $have = go env GOVERSION
  if ($LASTEXITCODE -or $have -ne $go) { throw "A release is built with $go; go reports '$have'." }

  New-Item -ItemType Directory -Force $out | Out-Null
  foreach ($arch in 'amd64', 'arm64') {
    $env:GOARCH = $arch
    $name = "mohurd_${Version}_linux_$arch"
    go build -ldflags "-s -w -buildid= -X main.version=$Version" -o (Join-Path $out $name) ./cmd/mohurd
    if ($LASTEXITCODE) { throw "The $arch build failed." }
  }

  # sha256sum's format, sorted by name, LF line ends.
  $lines = Get-ChildItem $out -File | Where-Object Name -like 'mohurd_*' | Sort-Object Name |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
  [IO.File]::WriteAllText((Join-Path $out 'SHA256SUMS'), (($lines -join "`n") + "`n"))
  Get-Content (Join-Path $out 'SHA256SUMS')
  Write-Host ''
  Write-Host "Built with $go from $(git rev-parse HEAD) in $out."
  Write-Host 'Sign SHA256SUMS on the release machine:'
  Write-Host "  ssh-keygen -Y sign -f `$HOME\.ssh\id_ed25519_denyfirst_release -n file $out\SHA256SUMS"
} finally {
  foreach ($k in $vars) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
  Pop-Location
}
