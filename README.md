
# Security Posture Scanner

A lightweight, **read-only** reconnaissance tool for **authorized** security
assessments. It reviews the externally observable security posture of a web
asset and produces a prioritized, risk-rated report.

> ⚠️ **Authorized use only.** Scan assets you own or have explicit written
> permission to test. This tool is passive (it only reads publicly available
> configuration data), but running any assessment against systems you do not
> control may still be illegal.

## What it checks

All checks are passive and non-intrusive — no exploitation, brute-forcing, or
control bypass:

- **HTTP security headers** — HSTS, Content-Security-Policy, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **TLS configuration** — negotiated protocol version, certificate validity and
  expiry
- **Cookie security flags** — Secure, HttpOnly, SameSite
- **Email / DNS anti-spoofing records** — SPF, DMARC, DKIM, CAA
- **Basic information disclosure** — `Server` / `X-Powered-By` banners

Each finding is rated by severity, and the tool prints an overall posture score
(0–100) with a letter grade.

## Requirements

- Python 3.9 or newer
- `requests` and `dnspython`

## Installation

```bash
git clone https://github.com/<your-username>/security-posture-scanner.git
cd security-posture-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Interactive (asks you to confirm authorization)
python security_posture_scanner.py example.com

# Skip the prompt when you have confirmed authorization
python security_posture_scanner.py https://example.com --yes

# Save a machine-readable report
python security_posture_scanner.py example.com --yes --json report.json

# Plain output (no ANSI colors)
python security_posture_scanner.py example.com --yes --no-color
```

### Example output

```
====================================================================
  SECURITY POSTURE REPORT  —  example.com
  Scanned: 2026-09-29 22:15 UTC
====================================================================
  [High    ] Header: Content-Security-Policy
           Header not set.
           -> Add the 'Content-Security-Policy' response header. ...
  [Pass    ] TLS Version
           Modern protocol: TLSv1.3
  ...
--------------------------------------------------------------------
  POSTURE SCORE: 72/100   (Grade C)
  OPEN ISSUES:   2 High, 1 Medium, 3 Low
====================================================================
```
## Demo & Evidence

The scanner was run against **[badssl.com](https://badssl.com)** — a site
intentionally maintained for TLS and web-security testing — to demonstrate the
tool on a sanctioned target. All checks are passive and read-only.

The scan returned a posture score of **26/100 (Grade F)**, flagging 2 high,
4 medium and 4 low issues: missing HSTS and Content-Security-Policy headers,
no SPF/DMARC records, and server version disclosure.

**Terminal output**
<img width="1297" height="875" alt="Captura de tela 2026-10-04 184426" src="https://github.com/user-attachments/assets/7ad6e182-55d6-4374-9d93-d6c72fee390e" />

> ⚠️ Targets used for demonstration are either reserved for testing
> (`example.com`), explicitly authorized (`scanme.nmap.org`, `badssl.com`), or
> owned by the author. Never scan systems you are not authorized to test.

## How it works

The scanner is a single self-contained module organized into independent check
functions (`check_http`, `check_tls`, `check_dns_email`), each appending
`Finding` records to a `ScanResult`. Results are sorted by severity and rendered
to the console and, optionally, to JSON.

## Roadmap

- [ ] Configurable DKIM selectors
- [ ] HTML report export
- [ ] Optional subdomain enumeration (passive sources)
- [ ] CI mode with a non-zero exit code below a score threshold

## Disclaimer

This project is provided for legitimate security assessment and educational
purposes. The author accepts no liability for misuse. Always obtain written
authorization before testing any system.

## License

Released under the MIT License. See [LICENSE](LICENSE).






<img width="1297" height="875" alt="Captura de tela 2026-10-04 184426" src="https://github.com/user-attachments/assets/fca006aa-a17c-48a8-9bd7-cd2a67081c4a" />

