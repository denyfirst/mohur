# Install

Mohur runs on a Linux x86-64 server with systemd, such as Ubuntu 24.04.

## You need

- A name for the server under your domain, such as `mohur.example.com`,
  pointing at the server, with port 443 open.
- A TLS certificate for that name and its key, as PEM files. Rootwell,
  certbot or your provider can make them. When the certificate file changes,
  Mohur uses the new one within a minute; no restart is needed.
- The `mohurd` binary for Linux, from the
  [latest release](https://github.com/denyfirst/mohur/releases/latest):
  `mohurd_vX.Y.Z_linux_amd64` (or `_arm64`), with `SHA256SUMS` and
  `SHA256SUMS.sig`. Check that denyfirst signed the list and that the file
  is on it, with this repository's `.allowed_signers`:

  ```sh
  ssh-keygen -Y verify -f .allowed_signers -I releases@denyfirst.dev \
    -n file -s SHA256SUMS.sig < SHA256SUMS
  sha256sum --check --ignore-missing SHA256SUMS
  mv mohurd_*_linux_amd64 mohurd
  ```

  Or build it yourself; [RELEASING.md](RELEASING.md) builds the same bytes.

## Install

Copy `mohurd`, `scripts/install.sh` and the certificate files to the server,
then:

```sh
sudo sh install.sh --binary=./mohurd --server=mohur.example.com \
  --tls-cert=fullchain.pem --tls-key=privkey.pem
```

It prints a one-time setup code. Open `https://mohur.example.com/`, enter the
code, and follow the page: your organization, your admin account and an
authenticator app. Then the Domain page shows the one DNS record to add.

Options for special networks, at first install only:

| Option | When |
|---|---|
| `--listen=ADDR` | Another address or port than `:443` |
| `--resolver=HOST:PORT` | Partners must be looked up through a private DNS server |
| `--extra-ca=FILE` | Partners use certificates from a private authority |
| `--allow-private-partners` | Partner servers are on private addresses, as in a lab |

## What it sets up

| Path | What |
|---|---|
| `/usr/local/bin/mohurd` | The program |
| `/etc/mohur/instance.key` | The key that seals the organization key in the database |
| `/etc/mohur/tls/` | Your certificate and key |
| `/etc/mohur/mohurd.conf` | The options above |
| `/var/lib/mohur/` | The database and encrypted files in transit |
| `mohurd.service` | Runs as the `mohur` account, sandboxed by systemd |

## Updates

The admin's **Server** page shows which release runs and, when asked, whether
a newer one is out. **Check now** asks GitHub for the latest release list;
**Check once a day** does it daily, and is off until an admin turns it on.
GitHub sees the server's address and nothing else. A newer release is shown
on every page, never installed by itself.

To upgrade, on the server:

```sh
sudo mohurd upgrade
```

It fetches the latest release list, checks denyfirst's signature and the
file's hash, keeps the current program as `/usr/local/bin/mohurd.previous`,
replaces it and restarts every running `mohurd` service. If a service does
not come back, the previous program is put back and restarted. Data, keys
and settings stay as they are.

Without internet access on the server, check a release elsewhere as under
"You need", copy it over and run `sudo sh install.sh --binary=./mohurd`.

## If the admin cannot sign in

A forgotten password, or a lost phone together with the recovery codes: on the
server, run

```sh
sudo mohurd reset-admin
```

It prints a one-time code and the server keeps running. On the sign-in page,
choose **Forgot your password?**, enter the code, then set a new password and
scan a new authenticator. The old password, authenticator and recovery codes
stop working, and the admin's other sessions end. The code works once, within
an hour.

## Back up

Copy `/var/lib/mohur` and, separately, `/etc/mohur/instance.key`. The
database is useless without the instance key, and the instance key alone
reveals nothing. Messages are not in the backup in readable form: servers
only ever hold ciphertext, and people's keys stay on their computers.
