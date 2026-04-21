# mailcheck

`mailcheck` is a small Go CLI for checking a domain's mail DNS setup.

It inspects:

- `MX`
- `SPF`
- `DMARC`
- guessed `DKIM` selectors

The goal is fast local inspection, not full deliverability analysis.

## Usage

```bash
go run . example.com
```

Or build a binary:

```bash
go build -o mailcheck .
./mailcheck example.com
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
