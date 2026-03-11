#!/usr/bin/env python3
"""
vendor.py — Asset vendoring for the mDL dashboard
Peculiar Ventures

Downloads all external JS/CSS/font/data assets and writes them to docs/assets/
so the compiled dashboard makes zero third-party requests at runtime.

Run once, or re-run to pick up version bumps.  The workflow runs this before
pipeline.py so that docs/assets/ is populated before the HTML is committed.

Usage:
    python vendor.py                 # vendor everything
    python vendor.py --check         # verify all expected files exist, exit 1 if not
    python vendor.py --list          # print what would be downloaded

Output layout:
    docs/assets/
      fonts/
        fonts.css                    # rewritten Google Fonts CSS (local src())
        dm-sans/
          *.woff2
        jetbrains-mono/
          *.woff2
      js/
        d3.min.js
        topojson-client.min.js
      peculiar/                      # @peculiar/certificates-viewer dist files
        peculiar.esm.js
        peculiar.js
        peculiar.css
        p-*.js                       # Stencil chunk files
      data/
        states-10m.json              # us-atlas TopoJSON (for map)
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DOCS_ASSETS = Path("docs/assets")

USER_AGENT_BROWSER = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
USER_AGENT_PIPELINE = (
    "mDL-Dashboard-Vendor/1.0 (Peculiar Ventures; https://peculiarventures.com)"
)
REQUEST_TIMEOUT = 30

# Pinned CDN URLs
D3_URL = "https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"
TOPOJSON_URL = "https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js"
USATLAS_URL = "https://cdn.jsdelivr.net/npm/us-atlas@3/states-10m.json"
GOOGLE_FONTS_URL = (
    "https://fonts.googleapis.com/css2"
    "?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;"
    "0,9..40,600;0,9..40,700;0,9..40,800"
    "&family=JetBrains+Mono:wght@400;500;600"
    "&display=swap"
)

# @peculiar/certificates-viewer — resolve @latest once, then pin to that version
PECULIAR_BASE_UNPKG = "https://unpkg.com/@peculiar/certificates-viewer@latest/dist/peculiar/"
PECULIAR_ESM = "peculiar.esm.js"
PECULIAR_NOMODULE = "peculiar.js"
PECULIAR_CSS = "peculiar.css"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vendor")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(session: requests.Session, url: str, browser_ua: bool = False) -> requests.Response:
    headers = {}
    if browser_ua:
        headers["User-Agent"] = USER_AGENT_BROWSER
    resp = session.get(url, timeout=REQUEST_TIMEOUT, headers=headers, allow_redirects=True)
    resp.raise_for_status()
    return resp


def _write(path: Path, content: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    log.info("  ✓  %s  (%d bytes)", path, len(content))


# ---------------------------------------------------------------------------
# Google Fonts via Fontsource — woff2 files + local CSS
# ---------------------------------------------------------------------------

# Fontsource hosts Google Fonts on jsdelivr (no UA gating)
FONTSOURCE_BASE = "https://cdn.jsdelivr.net/fontsource/fonts"
FONT_SPECS = [
    ("dm-sans", [300, 400, 500, 600, 700, 800]),
    ("jetbrains-mono", [400, 500, 600]),
]


def vendor_google_fonts(session: requests.Session) -> None:
    log.info("Vendoring Google Fonts via Fontsource …")
    fonts_dir = DOCS_ASSETS / "fonts"

    css_lines = ["/* Vendored Google Fonts — DM Sans + JetBrains Mono (latin subset) */"]

    for family_slug, weights in FONT_SPECS:
        family_dir = fonts_dir / family_slug
        family_name = family_slug.replace("-", " ").title()
        if family_slug == "dm-sans":
            family_name = "DM Sans"
        elif family_slug == "jetbrains-mono":
            family_name = "JetBrains Mono"

        for weight in weights:
            filename = f"latin-{weight}-normal.woff2"
            url = f"{FONTSOURCE_BASE}/{family_slug}@latest/{filename}"
            font_data = _get(session, url).content
            _write(family_dir / filename, font_data)

            css_lines.append(
                f"@font-face {{ font-family:'{family_name}'; font-style:normal; "
                f"font-weight:{weight}; font-display:swap; "
                f"src:url({family_slug}/{filename}) format('woff2'); }}"
            )

    css_path = fonts_dir / "fonts.css"
    _write(css_path, "\n".join(css_lines) + "\n")
    log.info("  fonts.css written with %d @font-face rules", len(css_lines) - 1)


# ---------------------------------------------------------------------------
# Simple JS/JSON files
# ---------------------------------------------------------------------------

def vendor_js_file(session: requests.Session, url: str, dest: Path) -> None:
    log.info("Vendoring %s …", dest.name)
    _write(dest, _get(session, url).content)


def vendor_usatlas(session: requests.Session) -> None:
    log.info("Vendoring us-atlas TopoJSON …")
    _write(DOCS_ASSETS / "data" / "states-10m.json", _get(session, USATLAS_URL).content)


# ---------------------------------------------------------------------------
# @peculiar/certificates-viewer — full Stencil dist (IIFE + all lazy chunks)
# ---------------------------------------------------------------------------

def vendor_peculiar(session: requests.Session) -> None:
    """
    Download @peculiar/certificates-viewer.

    The Stencil build uses lazy-loaded chunks (p-*.system.js) that the IIFE
    entry point (peculiar.js) fetches at runtime via SystemJS relative to its
    own script src. We must vendor every file in the dist/peculiar/ directory
    so the component works fully offline.
    """
    log.info("Vendoring @peculiar/certificates-viewer …")
    peculiar_dir = DOCS_ASSETS / "peculiar"

    # Resolve @latest → pinned version via unpkg meta endpoint
    probe = session.head(
        PECULIAR_BASE_UNPKG + PECULIAR_NOMODULE,
        allow_redirects=True,
        timeout=REQUEST_TIMEOUT,
    )
    # e.g. https://unpkg.com/@peculiar/certificates-viewer@4.9.1/dist/peculiar/peculiar.js
    pinned_base = probe.url.rsplit("/", 1)[0] + "/"
    log.info("  Resolved to: %s", pinned_base)

    # Get the full file listing via unpkg ?meta
    meta_url = pinned_base + "?meta"
    meta_resp = _get(session, meta_url)
    meta = meta_resp.json()
    files = meta.get("files", [])

    # Filter to .js and .css files (skip .map source maps)
    dist_files = [
        f for f in files
        if (f["path"].endswith(".js") or f["path"].endswith(".css"))
        and not f["path"].endswith(".map")
    ]
    log.info("  Found %d dist files to vendor", len(dist_files))

    total_bytes = 0
    for finfo in dist_files:
        # finfo["path"] is like "/dist/peculiar/p-hEr9Uo3G.system.js"
        filename = finfo["path"].rsplit("/", 1)[-1]
        url = pinned_base + filename
        try:
            content = _get(session, url).content
            _write(peculiar_dir / filename, content)
            total_bytes += len(content)
        except Exception as exc:
            log.warning("  ✗  %s: %s", filename, exc)

    # Also grab the ESM entry point and index
    for extra in ["peculiar.esm.js", "index.esm.js"]:
        try:
            content = _get(session, pinned_base + extra).content
            _write(peculiar_dir / extra, content)
            total_bytes += len(content)
        except Exception:
            pass

    log.info(
        "  Vendored %d files, %d KB total",
        len(dist_files), total_bytes // 1024,
    )


# ---------------------------------------------------------------------------
# Expected file manifest (for --check)
# ---------------------------------------------------------------------------

EXPECTED_FILES = [
    DOCS_ASSETS / "fonts" / "fonts.css",
    DOCS_ASSETS / "js" / "d3.min.js",
    DOCS_ASSETS / "js" / "topojson-client.min.js",
    DOCS_ASSETS / "data" / "states-10m.json",
    DOCS_ASSETS / "peculiar" / "peculiar.js",
    DOCS_ASSETS / "peculiar" / "peculiar.css",
]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Vendor external assets for the mDL dashboard")
    parser.add_argument("--check", action="store_true", help="Verify all expected files exist")
    parser.add_argument("--list", action="store_true", help="Print expected files and exit")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list:
        for f in EXPECTED_FILES:
            print(f)
        return 0

    if args.check:
        missing = [f for f in EXPECTED_FILES if not f.exists()]
        if missing:
            for f in missing:
                log.error("Missing: %s", f)
            return 1
        log.info("All %d expected vendor files present.", len(EXPECTED_FILES))
        return 0

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT_PIPELINE

    errors: list[str] = []

    for label, fn in [
        ("Google Fonts", lambda: vendor_google_fonts(session)),
        ("D3", lambda: vendor_js_file(session, D3_URL, DOCS_ASSETS / "js" / "d3.min.js")),
        ("topojson-client", lambda: vendor_js_file(session, TOPOJSON_URL, DOCS_ASSETS / "js" / "topojson-client.min.js")),
        ("us-atlas", lambda: vendor_usatlas(session)),
        ("@peculiar/certificates-viewer", lambda: vendor_peculiar(session)),
    ]:
        try:
            fn()
        except Exception as exc:
            log.error("%s vendoring failed: %s", label, exc)
            errors.append(label)

    if errors:
        log.error("Vendoring failed for: %s", ", ".join(errors))
        return 1

    log.info("Vendoring complete. Run python pipeline.py to build docs/index.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
