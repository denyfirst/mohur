#!/bin/sh
# Installs or upgrades mohurd on a Linux x86-64 host with systemd. Run as root.
#
# First install:
#   sh install.sh --binary=./mohurd --server=mohur.example.com \
#     --tls-cert=fullchain.pem --tls-key=privkey.pem
# Upgrade (keeps the data, keys and settings):
#   sh install.sh --binary=./mohurd
#
# Optional, first install only:
#   --listen=ADDR             HTTPS address, default :443
#   --resolver=HOST:PORT      DNS server for partner lookups (a private resolver)
#   --extra-ca=FILE           extra certificate authority to trust (a private CA)
#   --allow-private-partners  allow partner servers on private addresses
#
# Every check runs before the first change. The one-time setup code is shown
# at the end of a first install. See docs/INSTALL.md.
set -eu
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

refuse() { printf 'install refused: %s\n' "$1" >&2; exit 1; }
say() { printf '==> %s\n' "$1"; }

binary='' server='' cert='' key='' listen=':443' resolver='' extra_ca='' private=no
for argument in "$@"; do
  case "${argument}" in
    --binary=*) binary="${argument#*=}" ;;
    --server=*) server="${argument#*=}" ;;
    --tls-cert=*) cert="${argument#*=}" ;;
    --tls-key=*) key="${argument#*=}" ;;
    --listen=*) listen="${argument#*=}" ;;
    --resolver=*) resolver="${argument#*=}" ;;
    --extra-ca=*) extra_ca="${argument#*=}" ;;
    --allow-private-partners) private=yes ;;
    *) refuse "unknown option ${argument} (options take the --name=value form)" ;;
  esac
done

etc=/etc/mohur
conf="${etc}/mohurd.conf"
unit=/etc/systemd/system/mohurd.service
bin=/usr/local/bin/mohurd

# --- Checks -----------------------------------------------------------------
test "$(id -u)" = 0 || refuse 'run as root'
test "$(uname -sm)" = 'Linux x86_64' || refuse 'Linux x86-64 only'
test "$(cat /proc/1/comm)" = systemd || refuse 'systemd must be PID 1'
for tool in systemctl journalctl getent useradd install head sha256sum; do
  command -v "${tool}" >/dev/null 2>&1 || refuse "missing ${tool}"
done
test -n "${binary}" || refuse 'give --binary=PATH'
test -f "${binary}" || refuse "${binary} is not a file"
"${binary}" -h 2>&1 | grep -q -- '-instance-key' || refuse "${binary} is not mohurd"

upgrade=no
had_data=no
if test -f /var/lib/mohur/mohur.db; then had_data=yes; fi
if test -f "${conf}" && test -f "${unit}"; then
  upgrade=yes
  for option in "${server}" "${cert}" "${key}" "${resolver}" "${extra_ca}"; do
    test -z "${option}" || refuse 'this host already has Mohur; an upgrade takes only --binary'
  done
  test "${private}" = no || refuse 'this host already has Mohur; an upgrade takes only --binary'
else
  test ! -e "${unit}" || refuse "${unit} exists without ${conf}; remove it first"
  if test "${had_data}" = yes && test ! -f "${etc}/instance.key"; then
    refuse "/var/lib/mohur holds data but ${etc}/instance.key is missing; restore it from the backup first"
  fi
  case "${server}" in
    '' | *[!a-z0-9.:-]* | .* | *..* ) refuse 'give --server=NAME, the name people and partners use, such as mohur.example.com' ;;
  esac
  test -f "${cert}" || refuse 'give --tls-cert=FILE, the certificate chain for the server name (PEM)'
  test -f "${key}" || refuse 'give --tls-key=FILE, its private key (PEM)'
  grep -q 'BEGIN CERTIFICATE' "${cert}" || refuse "${cert} holds no PEM certificate"
  grep -q 'PRIVATE KEY' "${key}" || refuse "${key} holds no PEM private key"
  case "${listen}" in *:[0-9]*) ;; *) refuse '--listen takes HOST:PORT or :PORT' ;; esac
  case "${resolver}" in '' | *:[0-9]*) ;; *) refuse '--resolver takes HOST:PORT' ;; esac
  if test -n "${extra_ca}"; then
    grep -q 'BEGIN CERTIFICATE' "${extra_ca}" || refuse "${extra_ca} holds no PEM certificate"
  fi
fi

# --- Upgrade ----------------------------------------------------------------
if test "${upgrade}" = yes; then
  say 'Upgrading mohurd; data, keys and settings stay as they are'
  install -m 0755 -o root -g root "${binary}" "${bin}.new"
  mv -f "${bin}.new" "${bin}"
  systemctl restart mohurd.service
  sleep 2
  systemctl is-active --quiet mohurd.service || { journalctl -u mohurd.service -n 30 --no-pager >&2; refuse 'mohurd did not start; the log is above'; }
  say "Upgraded: $(sha256sum "${bin}" | cut -c1-16)…"
  exit 0
fi

# --- First install ----------------------------------------------------------
say 'Creating the mohur service account'
getent group mohur >/dev/null || groupadd --system mohur
getent passwd mohur >/dev/null || useradd --system --gid mohur --no-create-home --home-dir /var/lib/mohur --shell /usr/sbin/nologin mohur

say 'Installing files'
install -m 0755 -o root -g root "${binary}" "${bin}"
install -d -m 0750 -o root -g mohur "${etc}" "${etc}/tls"
install -m 0640 -o root -g mohur "${cert}" "${etc}/tls/fullchain.pem"
install -m 0640 -o root -g mohur "${key}" "${etc}/tls/privkey.pem"
if test ! -f "${etc}/instance.key"; then
  # The instance key seals the organization key and authenticator seeds in the
  # database. Keep a copy with every backup of /var/lib/mohur, apart from it.
  head -c 32 /dev/urandom > "${etc}/instance.key.new"
  chown root:mohur "${etc}/instance.key.new"
  chmod 0640 "${etc}/instance.key.new"
  mv "${etc}/instance.key.new" "${etc}/instance.key"
fi
options="-listen ${listen}"
test -z "${resolver}" || options="${options} -resolver ${resolver}"
if test -n "${extra_ca}"; then
  install -m 0644 -o root -g root "${extra_ca}" "${etc}/extra-ca.pem"
  options="${options} -extra-ca ${etc}/extra-ca.pem"
fi
test "${private}" = no || options="${options} -allow-private-partners"
{
  printf '# Written by install.sh. Server: %s\n' "${server}"
  printf 'MOHURD_OPTIONS=%s\n' "${options}"
} > "${conf}.new"
chmod 0644 "${conf}.new"
mv "${conf}.new" "${conf}"

cat > "${unit}.new" <<'UNIT'
[Unit]
Description=Mohur server
Documentation=https://github.com/denyfirst/mohur
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mohur
Group=mohur
EnvironmentFile=/etc/mohur/mohurd.conf
ExecStart=/usr/local/bin/mohurd -data /var/lib/mohur -instance-key /etc/mohur/instance.key -cert /etc/mohur/tls/fullchain.pem -cert-key /etc/mohur/tls/privkey.pem $MOHURD_OPTIONS
Restart=on-failure
RestartSec=5
StateDirectory=mohur
StateDirectoryMode=0700
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
SystemCallErrorNumber=EPERM
LimitNOFILE=8192
TasksMax=512
MemoryMax=1G

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "${unit}.new"
mv "${unit}.new" "${unit}"

say 'Starting mohurd'
systemctl daemon-reload
systemctl enable --now mohurd.service >/dev/null
code=''
for _ in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  code="$(journalctl -u mohurd.service -n 50 --no-pager -o cat | grep -E '^ +[A-Z2-7]{4}(-[A-Z2-7]{1,4})+$' | tail -n 1 | tr -d ' ')" || true
  test -z "${code}" || break
done
systemctl is-active --quiet mohurd.service || { journalctl -u mohurd.service -n 30 --no-pager >&2; refuse 'mohurd did not start; the log is above'; }
if test "${had_data}" = yes; then
  say "Mohur is installed over its existing data. Open https://${server}/ and sign in as before."
  exit 0
fi
test -n "${code}" || refuse 'mohurd started but showed no setup code; see journalctl -u mohurd'

cat <<DONE

Mohur is installed.

  1. Open https://${server}/ in a browser.
  2. Enter this setup code. It works once, for 24 hours:

       ${code}

  3. Then add the DNS record the Domain page shows.

DONE
