# ✉️ mailcheck

`mailcheck` is a small Go CLI for checking a domain's mail DNS setup.

It inspects core mail authentication records (`MX`, `SPF`, `DMARC`, and guessed `DKIM` selectors). With `--advanced`, it also reports mail-focused DNS diagnostics such as MX target `A`/`AAAA`, reverse DNS, `NS`, `SOA` support, DNSSEC validation support, and DNS query timing.

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

See [CHANGELOG.md](./CHANGELOG.md) for versioned release notes.

## Usage

```bash
mailcheck example.com
mailcheck --advanced example.com
mailcheck --advanced --details example.com
mailcheck -h
mailcheck --help
mailcheck -v
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
| `--advanced` | Include mail DNS diagnostic checks |
| `--dkim-deep` | Try the extended DKIM selector list |
| `--json` | Output JSON |
| `--no-color` | Disable ANSI colors |
| `--no-progress` | Disable the live progress line in interactive text mode |
| `--details`, `--verbose` | Show raw DNS records and lookup details in text output |
| `--help`, `-h` | Print the help message and exit |
| `--version`, `-v` | Print the current version and exit |
| `--timeout <duration>` | Set the total DNS lookup timeout (default `30s`) |

## Notes

- DKIM uses a bounded common selector library plus any selectors passed with `--selector`.
- `--dkim-deep` opts into the extended selector sweep. This is slower and can make DNS resolvers rate-limit or time out.
- A missing guessed DKIM selector is reported as a warning because DKIM cannot be proven absent without a selector from a real `DKIM-Signature` header.
- Common ESP-style subdomain setups are handled, including cases where helper records live on `send.<domain>` or DMARC is inherited from the parent domain.
- A DKIM pass reports the selectors found.
- Text output is optimized for readability. Use `--details` or `--verbose` to show raw DNS records and per-lookup details.
- `--advanced` adds a separate `Advanced DNS` section with `MX-A`, `MX-AAAA`, `PTR`, `NS`, `SOA`, `DNSSEC`, and `DNS-TIME` diagnostics.
- MX targets are checked for usable `A` or `AAAA` addresses as part of the core `MX` check. In advanced mode, separate `MX-A` and `MX-AAAA` diagnostics show IPv4 and IPv6 availability.
- Advanced reverse DNS diagnostics check MX target IPs, including IPv6 addresses, and report whether PTR names forward-confirm to the original IP.
- SOA and DNSSEC diagnostics use `codeberg.org/miekg/dns` for direct DNS queries. DNSSEC reports resolver AD-bit validation; it does not claim full local chain validation.
- `CAA`, `TLSA`, and zone transfer probes are intentionally not checked by default because they are not core mail deliverability checks or can be noisy/intrusive without explicit advanced mode support.
- In interactive text mode, a single live progress line is shown on `stderr` while checks are running.
- The tool only checks DNS records. It does not test SMTP, TLS, inbox placement, or message signing end-to-end.

## Example

```text
┌─────────────────────────┐
│    Mailcheck Results    │
└─────────────────────────┘

Domain: example.com
Rating: A
Reason: Core mail records pass.

== Core mail checks ==
MX    PASS  2 mail servers found; all resolve to IP addresses
SPF   PASS  SPF is valid and ends with -all
DMARC PASS  Policy quarantines failing mail
DKIM  PASS  DKIM records found for common selectors
```
