#!/usr/bin/env python3
"""
cli.py — Command-line interface for the WordPress Security Scanner.

Usage:
    python cli.py <target_url> [options]
    python cli.py https://example.com
    python cli.py https://example.com --delay 1.0 --no-active-probe --output /tmp/report
"""

import argparse
import logging
import sys
import time
import os

# Suppress InsecureRequestWarning for SSL verify=False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_banner():
    banner = r"""
  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║     WordPress Security Scanner  v1.0                 ║
  ║     Non-intrusive black-box vulnerability assessment ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
  ⚠  For authorised use only. Scan only sites you own
     or have explicit written permission to test.
"""
    print(banner)


def print_progress(step: str, pct: int, width: int = 45):
    """Render an inline progress bar."""
    filled  = int(pct / 100 * width)
    bar     = "█" * filled + "░" * (width - filled)
    # \r to overwrite the line; end='' to stay on same line
    print(f"\r  [{bar}] {pct:>3}%  {step:<45}", end="", flush=True)
    if pct == 100:
        print()  # newline when done


def main():
    parser = argparse.ArgumentParser(
        prog="wp-scanner",
        description="WordPress Security Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py https://example.com
  python cli.py https://example.com --delay 1.5 --timeout 15
  python cli.py https://example.com --no-active-probe --output /tmp/scan
  python cli.py https://example.com --verbose

Disclaimer:
  Only scan websites you own or have explicit authorisation to test.
  Unauthorised scanning may violate computer crime laws.
        """
    )

    parser.add_argument(
        "target",
        help="Target URL (e.g. https://example.com)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int, default=12,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 12)",
    )
    parser.add_argument(
        "--delay", "-d",
        type=float, default=0.6,
        metavar="SECONDS",
        help="Delay between requests in seconds (default: 0.6)",
    )
    parser.add_argument(
        "--no-active-probe",
        action="store_true",
        help="Disable active plugin probing (passive scan only, faster but less thorough)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PATH",
        help="Save JSON report to this path (e.g. /tmp/report.json). "
             "If omitted, saves to scans/ directory automatically.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save reports to disk",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output raw JSON report to stdout (suppresses terminal report)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output (useful for piping / CI)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()

    setup_logging(args.verbose)

    use_color = not args.no_color and sys.stdout.isatty()

    if not args.json_only:
        print_banner()
        print(f"  Target : {args.target}")
        print(f"  Delay  : {args.delay}s between requests")
        print(f"  Probing: {'passive only' if args.no_active_probe else 'active + passive'}")
        print()

    # Import here so logging is configured first
    from scanner.core import Scanner
    from scanner.report import print_terminal_report, save_json_report, save_text_report

    scanner = Scanner(
        target_url=args.target,
        timeout=args.timeout,
        delay=args.delay,
        active_probe=not args.no_active_probe,
        save_reports=not args.no_save,
    )

    report = None
    start  = time.time()

    try:
        for event in scanner.scan_with_progress():
            etype = event["type"]

            if etype == "progress" and not args.json_only:
                print_progress(event["step"], event["pct"])

            elif etype == "error" and not args.json_only:
                print(f"\n  ⚠  [{event['step']}] {event['message']}")

            elif etype == "complete":
                report = event["report"]

    except KeyboardInterrupt:
        print("\n\n  Scan interrupted by user.")
        sys.exit(1)

    if report is None:
        print("\n  Scan failed to produce a report.", file=sys.stderr)
        sys.exit(2)

    elapsed = time.time() - start
    if not args.json_only:
        print(f"\n  Scan completed in {elapsed:.1f}s\n")

    # ── Output ──────────────────────────────────────────────────────────────
    if args.json_only:
        import json
        print(json.dumps(report, indent=2, default=str))
    else:
        print_terminal_report(report, use_color=use_color)

    # ── Save to custom path if specified ─────────────────────────────────────
    if args.output:
        import json
        out_path = args.output
        if not out_path.endswith(".json"):
            out_path += ".json"
        save_json_report(report, out_path)
        print(f"\n  Report saved to: {out_path}")

    # ── Exit code reflects severity ───────────────────────────────────────────
    risk_summary = report.get("risk_summary", {})
    if risk_summary.get("Critical", 0) > 0:
        sys.exit(4)
    elif risk_summary.get("High", 0) > 0:
        sys.exit(3)
    elif risk_summary.get("Medium", 0) > 0:
        sys.exit(2)
    elif risk_summary.get("Low", 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
