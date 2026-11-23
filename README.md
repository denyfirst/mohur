# mohur.

**Verified. Sealed. Private.**

Mohur lets two organizations that each run their own server talk privately.
People send end-to-end encrypted one-to-one messages and files. Servers carry
only ciphertext, and no central service is involved.

Everything that keeps it safe happens on its own:

1. **Publish one DNS record.** The admin adds one TXT record and presses
   **Check**. It proves the domain and tells partners where the server is.
2. **Invite your people.** Each gets a one-time invite and pastes it into the
   Mohur app. Keys are made on their computer and never leave it.
3. **Connect a partner.** Type their domain and press **Connect**; they press
   **Accept**. Mohur verifies them by DNS, certificate and signature. No codes
   to read aloud.

Then people write to each other. Messages use the official libsignal library
(PQXDH with ML-KEM and the Double Ratchet), unchanged.

How it works and what it protects: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Where it stands: [docs/STATUS.md](docs/STATUS.md).

## Parts

| Path | What |
|---|---|
| `cmd/mohurd` | The server: one Go binary with the admin pages, the app API and federation |
| `cmd/mohur-lab` | Two or more organizations on one computer, for development and tests |
| `client/` | The desktop app: Electron and libsignal |
| `web/` | The admin pages, built into `mohurd` |

## Run the checks

Needs Go 1.27.4 (fetched by the toolchain line in `go.mod`) and Node 26.

```powershell
./scripts/check.ps1
```

## Try it on one computer

```powershell
go build -o .work/bin/mohur-lab.exe ./cmd/mohur-lab
.work/bin/mohur-lab.exe -dir .work/lab -invite "alpha.test:aylin:Aylin" -invite "beta.test:kamran:Kamran"
```

`.work/lab/lab.json` then lists the DNS server, the lab CA and the invites.
Start one app window per person:

```powershell
cd client
npm ci
$env:MOHUR_RESOLVER = "<resolver from lab.json>"
$env:MOHUR_EXTRA_CA = "..\.work\lab\ca.pem"
npx electron . --profile=aylin
```

## Licence

AGPL-3.0-only, as libsignal requires. By denyfirst.
