param([switch]$Analysis)
# Mohur's local gates: Go format, module check, vet, shuffled tests and build;
# then the app's end-to-end test, which builds mohur-lab and runs two real
# servers with real libsignal. -Analysis adds staticcheck, gosec and govulncheck.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $unformatted = @(gofmt -l cmd internal web)
    if ($LASTEXITCODE -ne 0 -or $unformatted.Count -ne 0) { throw "format check failed: $unformatted" }
    go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'module verification failed' }
    $deps = @(go list -deps -test ./...)
    if ($LASTEXITCODE -ne 0) { throw 'dependency inventory failed' }
    if ($deps -match '^golang.org/x/crypto/openpgp($|/)') { throw 'unmaintained OpenPGP dependency is forbidden' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'vet failed' }
    go test -shuffle=on -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
    go build -trimpath ./...
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
    # The app window and the admin pages run only in a browser, so no test
    # loads them: check that each script at least parses.
    foreach ($script in @(git ls-files 'client/src/*.mjs' 'client/src/*.cjs' 'web/*.mjs')) {
        node --check $script
        if ($LASTEXITCODE -ne 0) { throw "syntax error in $script" }
    }
    Push-Location client
    try {
        node --test test/
        if ($LASTEXITCODE -ne 0) { throw 'app end-to-end tests failed' }
    } finally { Pop-Location }
    if ($Analysis) {
        staticcheck ./cmd/... ./internal/... ./web/...
        if ($LASTEXITCODE -ne 0) { throw 'staticcheck failed' }
        gosec -severity medium -confidence medium ./cmd/... ./internal/... ./web/...
        if ($LASTEXITCODE -ne 0) { throw 'gosec failed' }
        govulncheck ./cmd/... ./internal/... ./web/...
        if ($LASTEXITCODE -ne 0) { throw 'govulncheck failed' }
    }
}
finally { Pop-Location }
