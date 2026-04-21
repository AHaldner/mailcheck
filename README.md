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

See [CHANGELOG.md](/Users/andrinhaldner/Documents/Dev/OpenSource/mailcheck/CHANGELOG.md) for versioned release notes.

## Usage

```bash
mailcheck example.com
mailcheck --version
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
| `--no-progress` | Disable the live progress line in interactive text mode |
| `--version` | Print the current version and exit |
| `--timeout <duration>` | Set the total DNS lookup timeout |

## Notes

- DKIM uses a built-in selector library plus any selectors passed with `--selector`.
- Common ESP-style subdomain setups are handled, including cases where helper records live on `send.<domain>` or DMARC is inherited from the parent domain.
- A DKIM pass reports the selectors found.
- In interactive text mode, a single live progress line is shown on `stderr` while checks are running.
- The tool only checks DNS records. It does not test SMTP, TLS, inbox placement, or message signing end-to-end.

## Example

```text
Mailcheck: example.com
Rating: A

MX      PASS  MX via example.com [2 records]: 10 mx1.example.com., 20 mx2.example.com.
SPF     PASS  SPF via example.com [1 record]: v=spf1 include:_spf.google.com ~all
DMARC   PASS  DMARC via example.com [1 record]: v=DMARC1; p=quarantine
DKIM    PASS  DKIM via example.com [2 selectors]: google, selector1
```
