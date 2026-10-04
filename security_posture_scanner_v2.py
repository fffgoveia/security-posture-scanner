#!/usr/bin/env python3
"""
Security Posture Scanner
------------------------
A lightweight, read-only reconnaissance tool for AUTHORIZED security
assessments. It reviews the externally observable security posture of a
web asset and produces a prioritized, risk-rated report.

Checks performed (all passive / non-intrusive):
  - HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
  - TLS configuration (protocol version, certificate validity/expiry)
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - Email/DNS anti-spoofing records (SPF, DMARC, DKIM, CAA)
  - Basic information disclosure (Server / X-Powered-By banners)

The tool does NOT exploit, brute-force, or attempt to bypass any control.
It only reads publicly available configuration data.

Usage:
    python security_posture_scanner.py example.com
    python security_posture_scanner.py https://example.com --json report.json

Requirements:
    pip install requests dnspython

Author: <your name> — Penetration Tester / Security Consultant
License: MIT
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: run 'pip install requests dnspython'")

try:
    import dns.resolver
except ImportError:
    sys.exit("Missing dependency: run 'pip install requests dnspython'")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Pass": 5}


@dataclass
class Finding:
    check: str
    severity: str          # Critical | High | Medium | Low | Info | Pass
    detail: str
    recommendation: str = ""


@dataclass
class ScanResult:
    target: str
    scanned_at: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, check: str, severity: str, detail: str, recommendation: str = "") -> None:
        self.findings.append(Finding(check, severity, detail, recommendation))

    def score(self) -> int:
        """Simple 0-100 posture score. Weighted by severity of open issues."""
        weights = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0, "Pass": 0}
        penalty = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("High", "Enforces HTTPS and protects against protocol downgrade / MITM."),
    "Content-Security-Policy": ("High", "Mitigates cross-site scripting (XSS) and data injection."),
    "X-Frame-Options": ("Medium", "Prevents clickjacking via framing."),
    "X-Content-Type-Options": ("Medium", "Stops MIME-type sniffing."),
    "Referrer-Policy": ("Low", "Controls how much referrer information is leaked."),
    "Permissions-Policy": ("Low", "Restricts access to browser features (camera, geolocation, etc.)."),
}


def check_http(result: ScanResult, base_url: str) -> Optional[requests.Response]:
    try:
        resp = requests.get(base_url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        result.add("HTTP Connectivity", "Info", f"Could not reach {base_url}: {exc}")
        return None

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # Security headers
    for header, (sev, why) in SECURITY_HEADERS.items():
        if header.lower() in headers:
            result.add(f"Header: {header}", "Pass", f"Present: {headers[header.lower()][:80]}")
        else:
            result.add(
                f"Header: {header}", sev,
                "Header not set.",
                f"Add the '{header}' response header. {why}",
            )

    # Information disclosure
    for banner in ("server", "x-powered-by"):
        if banner in headers and headers[banner].strip():
            result.add(
                f"Info Disclosure: {banner}", "Low",
                f"Exposes: {headers[banner]}",
                "Remove or genericize version banners to reduce fingerprinting.",
            )

    # Cookie flags
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
            issues.append("missing HttpOnly")
        if "samesite" not in str(cookie._rest).lower():
            issues.append("missing SameSite")
        if issues:
            result.add(
                f"Cookie: {cookie.name}", "Medium",
                ", ".join(issues),
                "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
            )

    return resp


def check_tls(result: ScanResult, hostname: str, port: int = 443) -> None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                proto = ssock.version()
                cert = ssock.getpeercert()
    except (ssl.SSLError, socket.error, socket.timeout) as exc:
        result.add("TLS Handshake", "High", f"TLS check failed: {exc}",
                   "Ensure a valid certificate and a modern TLS stack are in place.")
        return

    # Protocol version
    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
        result.add("TLS Version", "High", f"Weak protocol negotiated: {proto}",
                   "Disable TLS 1.0/1.1; require TLS 1.2 or 1.3.")
    else:
        result.add("TLS Version", "Pass", f"Modern protocol: {proto}")

    # Certificate expiry
    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days
        if days_left < 0:
            result.add("Certificate", "Critical", f"Certificate EXPIRED {abs(days_left)} days ago.",
                       "Renew the TLS certificate immediately.")
        elif days_left < 21:
            result.add("Certificate", "Medium", f"Certificate expires in {days_left} days.",
                       "Renew soon and consider automated renewal (ACME).")
        else:
            result.add("Certificate", "Pass", f"Valid, expires in {days_left} days.")


def _dns_query(name: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, record_type, lifetime=8)
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []


def check_dns_email(result: ScanResult, domain: str) -> None:
    # SPF
    txt = _dns_query(domain, "TXT")
    spf = [r for r in txt if r.lower().startswith("v=spf1")]
    if spf:
        result.add("SPF", "Pass", spf[0][:90])
    else:
        result.add("SPF", "Medium", "No SPF record found.",
                   "Publish an SPF record to reduce email spoofing.")

    # DMARC
    dmarc = _dns_query(f"_dmarc.{domain}", "TXT")
    dmarc_rec = [r for r in dmarc if r.lower().startswith("v=dmarc1")]
    if dmarc_rec:
        policy = "none"
        for part in dmarc_rec[0].split(";"):
            if "p=" in part:
                policy = part.split("p=")[1].strip()
        sev = "Pass" if policy in ("quarantine", "reject") else "Medium"
        result.add("DMARC", sev, f"Policy: p={policy}",
                   "" if sev == "Pass" else "Move policy to quarantine/reject after monitoring.")
    else:
        result.add("DMARC", "Medium", "No DMARC record found.",
                   "Publish a DMARC record (start with p=none, then tighten).")

    # DKIM (common selectors)
    found_dkim = False
    for selector in ("default", "google", "selector1", "selector2", "k1", "dkim", "mail"):
        if _dns_query(f"{selector}._domainkey.{domain}", "TXT"):
            result.add("DKIM", "Pass", f"Selector '{selector}' present.")
            found_dkim = True
            break
    if not found_dkim:
        result.add("DKIM", "Info", "No DKIM found on common selectors (may use a custom one).",
                   "Confirm DKIM signing with the mail provider.")

    # CAA
    caa = _dns_query(domain, "CAA")
    if caa:
        result.add("CAA", "Pass", f"{len(caa)} CAA record(s) present.")
    else:
        result.add("CAA", "Low", "No CAA record.",
                   "Add a CAA record to restrict which CAs may issue certificates.")


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
COLORS = {
    "Critical": "\033[95m", "High": "\033[91m", "Medium": "\033[93m",
    "Low": "\033[94m", "Info": "\033[90m", "Pass": "\033[92m", "reset": "\033[0m",
}

# Hex colors used by the HTML report (semantic severity scale).
HTML_SEV = {
    "Critical": "#7c3aed", "High": "#dc2626", "Medium": "#d97706",
    "Low": "#2563eb", "Info": "#64748b", "Pass": "#16a34a",
}


def grade_for(score: int) -> str:
    return ("A" if score >= 90 else "B" if score >= 75 else
            "C" if score >= 60 else "D" if score >= 40 else "F")


def print_report(result: ScanResult, color: bool = True) -> None:
    def c(sev: str) -> str:
        return f"{COLORS.get(sev,'')}{sev:<8}{COLORS['reset']}" if color else f"{sev:<8}"

    print("\n" + "=" * 68)
    print(f"  SECURITY POSTURE REPORT  —  {result.target}")
    print(f"  Scanned: {result.scanned_at}")
    print("=" * 68)

    ordered = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    for f in ordered:
        print(f"  [{c(f.severity)}] {f.check}")
        print(f"           {f.detail}")
        if f.recommendation and f.severity not in ("Pass", "Info"):
            print(f"           -> {f.recommendation}")
    print("-" * 68)

    score = result.score()
    grade = grade_for(score)
    print(f"  POSTURE SCORE: {score}/100   (Grade {grade})")
    counts = {}
    for f in result.findings:
        if f.severity not in ("Pass", "Info"):
            counts[f.severity] = counts.get(f.severity, 0) + 1
    if counts:
        summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda x: SEVERITY_ORDER[x[0]]))
        print(f"  OPEN ISSUES:   {summary}")
    print("=" * 68 + "\n")


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #
def write_html_report(result: ScanResult, path: str) -> None:
    """Render the scan as a self-contained, theme-aware HTML report."""
    import html as _html

    score = result.score()
    grade = grade_for(score)
    ordered = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    counts = {}
    for f in result.findings:
        if f.severity not in ("Pass", "Info"):
            counts[f.severity] = counts.get(f.severity, 0) + 1
    open_issues = sum(counts.values())

    # severity distribution (only severities that occur)
    tiles = "".join(
        f'<div class="tile"><div class="n" style="color:{HTML_SEV[s]}">{counts.get(s,0)}</div>'
        f'<div class="l">{s}</div></div>'
        for s in ("Critical", "High", "Medium", "Low") if counts.get(s)
    )

    rows = []
    for f in ordered:
        rec = (f'<div class="rec">&rarr; {_html.escape(f.recommendation)}</div>'
               if f.recommendation and f.severity not in ("Pass", "Info") else "")
        rows.append(
            f'<article class="finding" style="--sev:{HTML_SEV[f.severity]}">'
            f'<div class="fh"><span class="pill">{f.severity}</span>'
            f'<span class="check">{_html.escape(f.check)}</span></div>'
            f'<div class="detail">{_html.escape(f.detail)}</div>{rec}</article>'
        )
    findings_html = "\n".join(rows)
    grade_color = HTML_SEV["Pass"] if score >= 75 else HTML_SEV["Medium"] if score >= 40 else HTML_SEV["High"]

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Posture — {_html.escape(result.target)}</title>
<style>
  :root{{--bg:#f4f5f7;--surface:#fff;--fg:#1a1d24;--soft:#565c6b;--faint:#8a90a0;
    --line:#dcdfe6;--accent:#2d4de0;--mono:ui-monospace,"SFMono-Regular",Menlo,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
  @media (prefers-color-scheme:dark){{:root{{--bg:#0e1016;--surface:#171a22;--fg:#e8eaf0;
    --soft:#a6adbd;--faint:#6b7284;--line:#2b303c;--accent:#6d84ff;color-scheme:dark}}}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.55;font-size:15px}}
  .wrap{{max-width:780px;margin:0 auto;padding:32px max(16px,5vw) 72px}}
  .eyebrow{{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint)}}
  h1{{font-size:clamp(24px,5vw,34px);margin:8px 0 2px;letter-spacing:-.01em;word-break:break-all}}
  .meta{{font-family:var(--mono);font-size:12.5px;color:var(--soft);margin-bottom:22px}}
  .scorebar{{display:flex;flex-wrap:wrap;align-items:center;gap:18px;background:var(--surface);
    border:1px solid var(--line);border-left:6px solid {grade_color};border-radius:12px;padding:18px 22px;margin-bottom:8px}}
  .scorebar .g{{font-size:40px;font-weight:700;color:{grade_color};line-height:1}}
  .scorebar .s{{font-size:15px;color:var(--soft)}}
  .scorebar .s b{{color:var(--fg);font-size:22px}}
  .tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:10px;margin:16px 0 28px}}
  .tile{{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
  .tile .n{{font-size:26px;font-weight:700;line-height:1}}
  .tile .l{{font-size:12px;color:var(--soft);margin-top:4px}}
  .finding{{background:var(--surface);border:1px solid var(--line);border-left:5px solid var(--sev);
    border-radius:10px;padding:14px 16px;margin:12px 0}}
  .fh{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
  .pill{{font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
    color:var(--sev);border:1px solid var(--sev);border-radius:20px;padding:2px 9px}}
  .check{{font-weight:600}}
  .detail{{color:var(--soft);font-size:14px;margin-top:6px}}
  .rec{{font-size:13.5px;margin-top:6px;padding-top:6px;border-top:1px dashed var(--line)}}
  .foot{{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);font-size:11.5px;color:var(--faint)}}
</style>
</head>
<body>
<div class="wrap">
  <div class="eyebrow">Security Posture Report</div>
  <h1>{_html.escape(result.target)}</h1>
  <div class="meta">Scanned: {_html.escape(result.scanned_at)} · passive assessment</div>
  <div class="scorebar">
    <div class="g">{grade}</div>
    <div class="s"><b>{score}/100</b><br>{open_issues} open issue(s)</div>
  </div>
  <div class="tiles">{tiles}</div>
  {findings_html}
  <div class="foot">Generated by Security Posture Scanner · read-only, authorized use only.</div>
</div>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def normalize(target: str) -> tuple[str, str]:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    return target, parsed.hostname or target


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read-only security posture scanner for AUTHORIZED assessments.",
    )
    parser.add_argument("target", help="Domain or URL (e.g. example.com)")
    parser.add_argument("--json", metavar="FILE", help="Write results to a JSON file")
    parser.add_argument("--html", metavar="FILE", help="Write a formatted HTML report")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--yes", action="store_true",
                        help="Confirm you are authorized to assess this target")
    args = parser.parse_args()

    base_url, hostname = normalize(args.target)

    # Authorization gate — professional and ethical guardrail.
    if not args.yes:
        print("\n[!] Only scan assets you own or are explicitly authorized to test.")
        answer = input(f"    Confirm you are authorized to assess '{hostname}'? [y/N] ").strip().lower()
        if answer != "y":
            sys.exit("Aborted. Authorization not confirmed.")

    result = ScanResult(
        target=hostname,
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    print(f"\n[*] Scanning {hostname} ...")
    check_http(result, base_url)
    check_tls(result, hostname)
    check_dns_email(result, hostname)

    print_report(result, color=not args.no_color)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "target": result.target,
                    "scanned_at": result.scanned_at,
                    "score": result.score(),
                    "findings": [asdict(f) for f in result.findings],
                },
                fh, indent=2, ensure_ascii=False,
            )
        print(f"[*] JSON report written to {args.json}")

    if args.html:
        write_html_report(result, args.html)
        print(f"[*] HTML report written to {args.html}")


if __name__ == "__main__":
    main()
