# Install

Mohur runs on a Linux x86-64 server with systemd, such as Ubuntu 24.04.

## You need

- A name for the server under your domain, such as `mohur.example.com`,
  pointing at the server, with port 443 open.
- A TLS certificate for that name and its key, as PEM files. Rootwell,
  certbot or your provider can make them. When the certificate file changes,
  Mohur uses the new one within a minute; no restart is needed.
- The `mohurd` binary for Linux:

  ```sh
  GOOS=linux GOARCH=amd64 go build -trimpath -o mohurd ./cmd/mohurd
  ```

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

## Upgrade

```sh
sudo sh install.sh --binary=./mohurd
```

Data, keys and settings stay as they are.

## Back up

Copy `/var/lib/mohur` and, separately, `/etc/mohur/instance.key`. The
database is useless without the instance key, and the instance key alone
reveals nothing. Messages are not in the backup in readable form: servers
only ever hold ciphertext, and people's keys stay on their computers.
