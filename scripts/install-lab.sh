#!/bin/sh
# Installs mohurd with scripts/install.sh on this Linux host, as an operator
# would, then checks it: refusals, file modes, HTTPS, the systemd sandbox, a
# whole setup through the API, and an upgrade that keeps everything. CI runs
# it on a fresh runner; do not run it on a host that matters (it uses sudo).
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fail() { printf 'install lab failed: %s\n' "$1" >&2; exit 1; }
expect_refusal() {
  # expect_refusal "words the refusal must contain" install.sh arguments...
  words="$1"; shift
  if sudo sh "${root}/scripts/install.sh" "$@" > "${work}/out" 2>&1; then fail "accepted: $*"; fi
  grep -q "install refused: .*${words}" "${work}/out" || { cat "${work}/out" >&2; fail "refused for another reason: $*"; }
}

cd "${root}"
go build -trimpath -o "${work}/mohurd" ./cmd/mohurd
# Operators copy the binary with scp, which drops the execute bit; install that way.
chmod 0644 "${work}/mohurd"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=mohur.ci.test \
  -addext subjectAltName=DNS:mohur.ci.test -keyout "${work}/key.pem" -out "${work}/cert.pem" 2>/dev/null
printf '#!/bin/sh\necho not mohurd\n' > "${work}/fake"
chmod 755 "${work}/fake"

echo '--- refusals before any change'
expect_refusal 'give --binary' --server=mohur.ci.test
expect_refusal 'is not mohurd' --binary="${work}/fake" --server=mohur.ci.test --tls-cert="${work}/cert.pem" --tls-key="${work}/key.pem"
expect_refusal 'is not mohurd' --binary=/bin/true --server=mohur.ci.test --tls-cert="${work}/cert.pem" --tls-key="${work}/key.pem"
expect_refusal 'give --server' --binary="${work}/mohurd" --tls-cert="${work}/cert.pem" --tls-key="${work}/key.pem"
expect_refusal 'give --tls-cert' --binary="${work}/mohurd" --server=mohur.ci.test
expect_refusal 'holds no PEM private key' --binary="${work}/mohurd" --server=mohur.ci.test --tls-cert="${work}/cert.pem" --tls-key="${work}/cert.pem"
expect_refusal 'unknown option' --binary="${work}/mohurd" --server mohur.ci.test
test ! -e /etc/mohur || fail 'a refused install left /etc/mohur behind'
getent passwd mohur >/dev/null && fail 'a refused install created the account'

echo '--- install'
sudo sh scripts/install.sh --binary="${work}/mohurd" --server=mohur.ci.test --tls-cert="${work}/cert.pem" \
  --tls-key="${work}/key.pem" --listen=127.0.0.1:8443 | tee "${work}/install.out"
code="$(sed -n 's/^ \{7\}\([A-Z2-7-]\{20,\}\)$/\1/p' "${work}/install.out")"
test -n "${code}" || fail 'no setup code shown'

echo '--- files'
check_mode() { test "$(sudo stat -c '%a %U %G' "$1")" = "$2" || fail "$1 is $(sudo stat -c '%a %U %G' "$1"), want $2"; }
check_mode /etc/mohur '750 root mohur'
check_mode /etc/mohur/instance.key '640 root mohur'
check_mode /etc/mohur/tls/privkey.pem '640 root mohur'
check_mode /var/lib/mohur '700 mohur mohur'
check_mode /var/lib/mohur/mohur.db '600 mohur mohur'
check_mode /usr/local/bin/mohurd '755 root root'
test "$(sudo stat -c %s /etc/mohur/instance.key)" = 32 || fail 'instance key is not 32 bytes'

echo '--- HTTPS and the sandbox'
url=https://mohur.ci.test:8443
curl_lab() { curl --silent --show-error --cacert "${work}/cert.pem" --resolve mohur.ci.test:8443:127.0.0.1 "$@"; }
test "$(curl_lab -o /dev/null -w '%{http_code}' "${url}/setup")" = 200 || fail 'the setup page did not load'
test "$(curl_lab -o /dev/null -w '%{http_code}' "${url}/.well-known/mohur")" = 404 || fail 'an organization document before setup'
curl_lab -sI "${url}/" | grep -qi '^content-security-policy:' || fail 'no content security policy'
systemctl show mohurd -p User -p NoNewPrivileges -p ProtectSystem -p MemoryDenyWriteExecute | tee "${work}/props"
grep -qx 'User=mohur' "${work}/props" && grep -qx 'NoNewPrivileges=yes' "${work}/props" && grep -qx 'ProtectSystem=strict' "${work}/props" \
  || fail 'the unit is not sandboxed as written'
systemd-analyze security mohurd.service --no-pager | tail -n 1

echo '--- an admin reset code: only with sudo, while the service runs'
if /usr/local/bin/mohurd reset-admin > "${work}/reset.out" 2>&1; then fail 'reset-admin worked without sudo'; fi
grep -q 'run this with sudo' "${work}/reset.out" || { cat "${work}/reset.out" >&2; fail 'reset-admin without sudo did not say why'; }
reset="$(sudo /usr/local/bin/mohurd reset-admin | sed -n 's/^ \{4\}\([A-Z2-7-]\{20,\}\)$/\1/p')"
test -n "${reset}" || fail 'reset-admin showed no code'
systemctl is-active --quiet mohurd || fail 'reset-admin stopped the service'

echo '--- setup, invite, join, sign-in and reset through the sandboxed service'
grep -q mohur.ci.test /etc/hosts || echo '127.0.0.1 mohur.ci.test' | sudo tee -a /etc/hosts >/dev/null
MOHUR_LAB_URL="${url}" MOHUR_LAB_CA="${work}/cert.pem" MOHUR_LAB_CODE="${code}" MOHUR_LAB_RESET="${reset}" \
  go test -tags=installlab -run '^TestInstalledServer$' -count=1 -v ./internal/server/ > "${work}/flow.out" 2>&1 \
  || { cat "${work}/flow.out" >&2; fail 'the setup flow failed'; }
grep -q -- '--- PASS: TestInstalledServer' "${work}/flow.out" || { cat "${work}/flow.out" >&2; fail 'the setup flow did not run'; }

echo '--- upgrade keeps keys and data'
before_key="$(sudo sha256sum /etc/mohur/instance.key)"
expect_refusal 'upgrade takes only --binary' --binary="${work}/mohurd" --server=mohur.ci.test
sudo sh scripts/install.sh --binary="${work}/mohurd"
test "$(sudo sha256sum /etc/mohur/instance.key)" = "${before_key}" || fail 'the upgrade changed the instance key'
test "$(curl_lab -o /dev/null -w '%{http_code}' "${url}/.well-known/mohur")" = 200 || fail 'the organization is gone after the upgrade'
echo 'install lab passed'
