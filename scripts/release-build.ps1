# Builds a Mohur release's server binaries so that any machine with the same
# Go gets the same bytes, and writes SHA256SUMS for denyfirst's release key to
# sign. Nothing is signed or published here; docs/RELEASING.md has the steps.
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
$saved = @{}
foreach ($k in 'CGO_ENABLED', 'GOOS', 'GOARCH', 'GOFLAGS') { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
try {
  if (git status --porcelain) { throw 'The working tree has changes; a release is built from a clean commit.' }
  if (-not $DryRun) {
    $tags = @(git tag --points-at HEAD)
    if ($tags -notcontains $Version) { throw "HEAD is not tagged $Version. Check out the tag, or pass -DryRun." }
  }
  $out = Join-Path $root ".work/release/$Version"
  if (Test-Path $out) { throw "$out exists; move it away first." }
  New-Item -ItemType Directory -Force $out | Out-Null

  # The same flags everywhere: no cgo, no paths, no VCS stamp, no build id.
  $env:CGO_ENABLED = '0'
  $env:GOOS = 'linux'
  $env:GOFLAGS = '-trimpath -buildvcs=false'
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
  Write-Host "Built in $out. Sign SHA256SUMS on the release machine:"
  Write-Host "  ssh-keygen -Y sign -f `$HOME\.ssh\id_ed25519_denyfirst_release -n file $out\SHA256SUMS"
} finally {
  foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
  Pop-Location
}
