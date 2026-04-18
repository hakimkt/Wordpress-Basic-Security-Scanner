"""
core.py — Orchestrator that runs all scan modules in sequence and
produces the final report. Yields progress events for Flask SSE streaming.
"""

import json
import logging
import datetime
import os
from pathlib import Path
from typing import Generator, Dict, Any, Optional

from .utils import build_session, RateLimiter, normalize_url
from .detector import detect_wordpress
from .version import enumerate_version
from .plugins import enumerate_plugins
from .endpoints import run_all_endpoint_checks
from .headers import run_all_header_checks
from .report import build_report, print_terminal_report, save_json_report, save_text_report

logger = logging.getLogger("wp_scanner.core")

# Path to bundled CVE data
_DATA_DIR  = Path(__file__).parent.parent / "data"
_CVE_PATH  = _DATA_DIR / "cve_data.json"
_SCANS_DIR = Path(__file__).parent.parent / "scans"
_SCANS_DIR.mkdir(exist_ok=True)


def load_cve_data() -> Dict:
    """Load the bundled CVE JSON database."""
    with open(_CVE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class Scanner:
    """
    Main scanner class.  Run `scanner.scan()` for a blocking full scan,
    or `scanner.scan_with_progress()` for a generator that yields status
    events suitable for SSE streaming.
    """

    def __init__(
        self,
        target_url: str,
        timeout: int = 12,
        delay: float = 0.6,
        active_probe: bool = True,
        verify_ssl: bool = False,
        save_reports: bool = True,
    ):
        self.target_url   = normalize_url(target_url)
        self.timeout      = timeout
        self.delay        = delay
        self.active_probe = active_probe
        self.verify_ssl   = verify_ssl
        self.save_reports = save_reports

        self.session      = build_session(timeout=timeout, verify_ssl=verify_ssl)
        self.rate_limiter = RateLimiter(delay=delay)
        self.cve_data     = load_cve_data()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> Dict[str, Any]:
        """
        Run the full scan synchronously.
        Returns the completed report dict.
        """
        report = None
        for event in self.scan_with_progress():
            if event["type"] == "complete":
                report = event["report"]
        return report

    def scan_with_progress(self) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that runs the scan and yields progress dicts:

            {"type": "progress", "step": str, "pct": int}
            {"type": "result",   "step": str, "data": dict}
            {"type": "error",    "step": str, "message": str}
            {"type": "complete", "report": dict}
        """
        scan_start = datetime.datetime.utcnow()
        all_findings = []

        # Collected intermediate results
        wp_detected  = False
        wp_confidence = 0
        wp_signals   = []
        wp_version   = None
        wp_version_source = None
        wp_outdated  = False
        plugins      = []
        theme        = None
        waf_info     = {"waf_detected": False, "waf_name": None}

        # ── Step 1: WordPress Detection ──────────────────────────────────────
        yield _progress("Detecting WordPress installation…", 5)
        try:
            det = detect_wordpress(self.session, self.target_url, self.rate_limiter)
            wp_detected   = det["is_wordpress"]
            wp_confidence = det["confidence"]
            wp_signals    = det["signals"]
            all_findings.extend(det.get("findings", []))
            yield _result("detection", det)
        except Exception as e:
            logger.exception("Detection error")
            yield _error("detection", str(e))

        if not wp_detected:
            yield _progress("Target does not appear to be WordPress. Aborting.", 100)
            report = build_report(
                self.target_url, scan_start, datetime.datetime.utcnow(),
                False, wp_confidence, wp_signals,
                None, None, False, [], None,
                {"waf_detected": False, "waf_name": None}, [],
            )
            yield {"type": "complete", "report": report}
            return

        # ── Step 2: Version Enumeration ───────────────────────────────────────
        yield _progress("Enumerating WordPress version…", 15)
        try:
            ver = enumerate_version(self.session, self.target_url,
                                    self.cve_data, self.rate_limiter)
            wp_version        = ver["version"]
            wp_version_source = ver["source"]
            wp_outdated       = ver["is_outdated"]
            all_findings.extend(ver["findings"])
            yield _result("version", ver)
        except Exception as e:
            logger.exception("Version enumeration error")
            yield _error("version", str(e))

        # ── Step 3: Plugin & Theme Enumeration ────────────────────────────────
        yield _progress("Enumerating plugins and themes…", 30)
        try:
            plug = enumerate_plugins(
                self.session, self.target_url, self.cve_data,
                self.rate_limiter, active_probe=self.active_probe,
            )
            plugins = plug["plugins_detected"]
            theme   = plug["theme_detected"]
            all_findings.extend(plug["findings"])
            yield _result("plugins", plug)
        except Exception as e:
            logger.exception("Plugin enumeration error")
            yield _error("plugins", str(e))

        # ── Step 4: Endpoint Checks ───────────────────────────────────────────
        yield _progress("Checking endpoints and sensitive files…", 55)
        try:
            ep = run_all_endpoint_checks(self.session, self.target_url,
                                         self.rate_limiter)
            waf_info = ep["waf_info"]
            all_findings.extend(ep["findings"])
            yield _result("endpoints", ep)
        except Exception as e:
            logger.exception("Endpoint check error")
            yield _error("endpoints", str(e))

        # ── Step 5: Header & SSL Checks ───────────────────────────────────────
        yield _progress("Analysing security headers and SSL/TLS…", 75)
        try:
            hdr = run_all_header_checks(self.session, self.target_url,
                                        self.rate_limiter)
            all_findings.extend(hdr["findings"])
            yield _result("headers", hdr)
        except Exception as e:
            logger.exception("Header check error")
            yield _error("headers", str(e))

        # ── Step 6: Build & Output Report ─────────────────────────────────────
        yield _progress("Building report…", 90)
        scan_end = datetime.datetime.utcnow()

        report = build_report(
            self.target_url, scan_start, scan_end,
            wp_detected, wp_confidence, wp_signals,
            wp_version, wp_version_source, wp_outdated,
            plugins, theme, waf_info, all_findings,
        )

        if self.save_reports:
            _save(report, self.target_url, scan_start)

        yield _progress("Scan complete!", 100)
        yield {"type": "complete", "report": report}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _progress(step: str, pct: int) -> Dict:
    logger.info("[%d%%] %s", pct, step)
    return {"type": "progress", "step": step, "pct": pct}


def _result(step: str, data: Dict) -> Dict:
    return {"type": "result", "step": step, "data": data}


def _error(step: str, message: str) -> Dict:
    logger.error("[%s] %s", step, message)
    return {"type": "error", "step": step, "message": message}


def _save(report: Dict, url: str, ts: datetime.datetime) -> None:
    """Save JSON and text reports to the scans/ directory."""
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.replace(":", "_")
        stamp  = ts.strftime("%Y%m%d_%H%M%S")
        base   = _SCANS_DIR / f"{domain}_{stamp}"

        save_json_report(report, str(base) + ".json")

        # Generate and save text report (suppressing print)
        import io, sys
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        txt = print_terminal_report(report, use_color=False)
        sys.stdout = old
        save_text_report(txt, str(base) + ".txt")

    except Exception as e:
        logger.warning("Could not save reports: %s", e)
