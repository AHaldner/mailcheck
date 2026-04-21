# ✉️ mailcheck

`mailcheck` is a small Go CLI for checking a domain's mail DNS setup.

It inspects `MX`, `SPF`, `DMARC`, and guessed `DKIM` selectors.

## Install

From source in the current repo:

```bash
go install .
```

From GitHub:

```bash
go install github.com/AHaldner/mailcheck@latest
```

From a GitHub release on macOS or Linux:

```bash
BIN_DIR="$HOME/.local/bin" curl -fsSL https://raw.githubusercontent.com/AHaldner/mailcheck/main/scripts/install.sh | sh
```

From a GitHub release on Windows PowerShell:

```powershell
iwr https://raw.githubusercontent.com/AHaldner/mailcheck/main/scripts/install.ps1 -useb | iex
```

Tagged releases are built automatically with GitHub Actions and GoReleaser. The installers verify the downloaded archive against the release `checksums.txt` before installing.

## Usage

```bash
mailcheck example.com
```

Build locally:

```bash
go build -o mailcheck .
```

Run tests:

```bash
go test ./...
```

## Flags

| Flag | Description |
|------|-------------|
| `--selector <name>` | Add extra DKIM selectors to try |
| `--json` | Output JSON |
| `--no-color` | Disable ANSI colors |
| `--timeout <duration>` | Set the total DNS lookup timeout |

## Notes

- DKIM uses a built-in selector library plus any selectors passed with `--selector`.
- Common ESP-style subdomain setups are handled, including cases where helper records live on `send.<domain>` or DMARC is inherited from the parent domain.
- A DKIM pass reports the selectors found.
- The tool only checks DNS records. It does not test SMTP, TLS, inbox placement, or message signing end-to-end.

## Example

```text
Mailcheck: example.com
Rating: A

MX      PASS  2 records found
SPF     PASS  v=spf1 include:_spf.google.com ~all
DMARC   PASS  v=DMARC1; p=quarantine
DKIM    PASS  found 2 DKIM selectors: google, selector1
```
