#!/usr/bin/env python3
"""
mDL State of the Nation — Data Pipeline
Peculiar Ventures

Fetches data from TSA, AAMVA VICAL, and state DMV/DOT sites,
computes all stats, and embeds the result as DASHBOARD_DATA
directly into src/index.html → docs/index.html.

Usage:
    python pipeline.py            # build docs/index.html
    python pipeline.py --dry-run  # print JSON only, no file write
    python pipeline.py --no-web   # skip slow web-discovery step
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PIPELINE_VERSION = "1.1.0"
TEMPLATE_PATH = Path("src/index.html")
OUTPUT_PATH = Path("docs/index.html")

TSA_URL = "https://www.tsa.gov/digital-id/participating-states"
TSA_WAIVER_URL = "https://www.tsa.gov/realid/realid-mobile-drivers-license-mdls"
VICAL_BASE_URL = "https://vical.dts.aamva.org/"
GOOGLE_IACA_URL = (
    "https://developers.google.com/wallet/identity/verify/supported-issuers-iaca-certs"
)

# Minimum known-good set used when TSA pages are blocked or only partially
# rendered. Refresh when the live waiver list changes:
# https://www.tsa.gov/realid/realid-mobile-drivers-license-mdls
TSA_FALLBACK_STATES: set[str] = {
    "AK", "AZ", "AR", "CA", "CO", "GA", "HI", "IL", "IA", "KY",
    "LA", "MD", "MT", "NM", "NY", "ND", "OH", "OK", "PR", "UT",
    "VA", "WV",
}
TSA_FALLBACK_AS_OF = "2026-09-25"

REQUEST_TIMEOUT = 20
USER_AGENT = (
    "Mozilla/5.0 (compatible; mDL-Dashboard-Pipeline/1.1; "
    "+https://mdl.peculiarventures.com)"
)

# 2020 US Census state populations
STATE_POPULATIONS: dict[str, int] = {
    "AL": 5024279, "AK": 733391, "AZ": 7151502, "AR": 3011524,
    "CA": 39538223, "CO": 5773714, "CT": 3605944, "DE": 989948,
    "DC": 689545, "FL": 21538187, "GA": 10711908, "HI": 1455271,
    "ID": 1839106, "IL": 12812508, "IN": 6785528, "IA": 3190369,
    "KS": 2937880, "KY": 4505836, "LA": 4657757, "ME": 1362359,
    "MD": 6177224, "MA": 7029917, "MI": 10077331, "MN": 5706494,
    "MS": 2961279, "MO": 6154913, "MT": 1084225, "NE": 1961504,
    "NV": 3104614, "NH": 1377529, "NJ": 9288994, "NM": 2117522,
    "NY": 20201249, "NC": 10439388, "ND": 779094, "OH": 11799448,
    "OK": 3959353, "OR": 4237256, "PA": 13002700, "RI": 1097379,
    "SC": 5118425, "SD": 886667, "TN": 6910840, "TX": 29145505,
    "UT": 3271616, "VT": 643077, "VA": 8631393, "WA": 7705281,
    "WV": 1793716, "WI": 5893718, "WY": 576851, "PR": 3285874,
}
US_TOTAL_POP = 331449281  # 50 states + DC

ABBR_TO_STATE: dict[str, str] = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas",
    "CA": "California", "CO": "Colorado", "CT": "Connecticut",
    "DE": "Delaware", "DC": "District of Columbia", "FL": "Florida",
    "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois",
    "IN": "Indiana", "IA": "Iowa", "KS": "Kansas", "KY": "Kentucky",
    "LA": "Louisiana", "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts",
    "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri",
    "MT": "Montana", "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire",
    "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York",
    "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio",
    "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island",
    "SC": "South Carolina", "SD": "South Dakota", "TN": "Tennessee",
    "TX": "Texas", "UT": "Utah", "VT": "Vermont", "VA": "Virginia",
    "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin",
    "WY": "Wyoming", "PR": "Puerto Rico",
}
STATE_TO_ABBR = {v: k for k, v in ABBR_TO_STATE.items()}

# Known state mDL root certificate URLs for web discovery.
# Format: (state_abbr, url, description, format)
# Formats: "cer" = DER or PEM, "zip" = zip archive containing .cer/.pem files, "pem" = PEM
# These are updated manually as states publish their PKI.
KNOWN_STATE_CERT_URLS: list[tuple[str, str, str, str]] = [
    ("CA", "https://trust.dmv.ca.gov/certificates/ca-dmv-iaca-root-ca-crt.cer", "CA DMV mDL Root", "cer"),
    ("GA", "https://dds.georgia.gov/document/document/ga-mdl-rootzip/download", "GA DDS mDL Root", "zip"),
    ("HI", "https://hidot.hawaii.gov/highways/files/2024/08/2024_HI_IACA_Root.zip", "HI DOT mDL Root", "zip"),
    ("NM", "https://www.mvd.newmexico.gov/wp-content/uploads/2025/10/New-Mexico-IACA-Certificate.zip", "NM MVD IACA Root", "zip"),
    ("OH", "https://bmvonline.dps.ohio.gov/bmvonline/home/Downloads/ohio_mdl_iaca_root_2024.zip", "OH BMV IACA Root", "zip"),
    ("OK", "https://www.oklahoma.gov/content/dam/service-oklahoma/Documents/digital-id/SOK%20BOOST%20Mobile%20Credential%20Root%20IACA%207_1_26.zip", "OK Service Oklahoma IACA Root", "zip"),
    ("PR", "https://docs.pr.gov/files/ID_movil-mDL/Certificado_IACA/PRDTOPProdCA.pem", "PR DTOP mDL Root", "pem"),
]

# Google Wallet rows that are not a downloadable IACA file.
VICAL_HOSTS = ("vical.dts.aamva.org",)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mdl-pipeline")


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


# ---------------------------------------------------------------------------
# Certificate utilities
# ---------------------------------------------------------------------------

def _parse_cert(der: bytes) -> x509.Certificate | None:
    """Parse DER or PEM bytes into an x509.Certificate."""
    try:
        if der.strip().startswith(b"-----"):
            return x509.load_pem_x509_certificate(der)
        return x509.load_der_x509_certificate(der)
    except Exception:
        return None


_ADCS_OIDS = {"1.3.6.1.4.1.311.21.10", "1.3.6.1.4.1.58017.1"}
_ENTRUST_OID = "1.2.840.113533.7.65.0"


def _detect_ca_tags(cert: x509.Certificate) -> list[str]:
    """Detect CA software from certificate extensions (ADCS, Entrust, EJBCA)."""
    tags: list[str] = []
    try:
        for ext in cert.extensions:
            oid_str = ext.oid.dotted_string
            if oid_str in _ADCS_OIDS and "ADCS" not in tags:
                tags.append("ADCS")
            if oid_str == _ENTRUST_OID and "Entrust" not in tags:
                tags.append("Entrust")
    except Exception:
        pass

    # EJBCA: "ejbca" substring in any CRL Distribution Point URI
    try:
        crl_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for dp in crl_ext.value:
            for name in (dp.full_name or []):
                if hasattr(name, "value") and "ejbca" in name.value.lower():
                    if "EJBCA" not in tags:
                        tags.append("EJBCA")
    except Exception:
        pass

    return tags


def _cert_to_record(cert: x509.Certificate, state: str) -> dict:
    """Convert a cryptography Certificate into a dashboard root record."""
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        algorithm = "RSA"
        key_detail = str(pub.key_size)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        algorithm = "ECDSA"
        key_detail = pub.curve.name  # e.g. secp256r1
    else:
        algorithm = type(pub).__name__
        key_detail = ""

    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        cn = cert.subject.rfc4514_string()

    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der).hexdigest()
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_tags = _detect_ca_tags(cert)

    return {
        "fingerprint_sha256": fingerprint,
        "subject_cn": cn,
        "subject_full": cert.subject.rfc4514_string(),
        "not_before": (
            getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        ).isoformat(),
        "not_after": (
            getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        ).isoformat(),
        "algorithm": algorithm,
        "key_detail": key_detail,
        "tags": ca_tags,
        "state": state,
        "_pem": pem,
    }


# ---------------------------------------------------------------------------
# TSA scraper
# ---------------------------------------------------------------------------

def _states_from_html(html: str) -> set[str]:
    """Extract state names from discrete listing elements.

    Deliberately avoid scanning arbitrary page prose. Abbreviation matching
    made "Digital ID" look like Idaho, while substring matching made an
    address such as "Washington, DC" look like Washington state.
    """
    found: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")
    for item in soup.find_all(["li", "td", "th", "h2", "h3", "h4", "p", "a"]):
        text = " ".join(item.get_text(" ", strip=True).split())
        text = text.strip(" \t\r\n:;,.–—-")
        if text in STATE_TO_ABBR:
            found.add(STATE_TO_ABBR[text])
    return found


def fetch_tsa_states(session: requests.Session) -> set[str]:
    """Scrape TSA participating-states and REAL ID waiver pages."""
    log.info("Fetching TSA participating states …")
    found: set[str] = set()
    for label, url in (("participating-states", TSA_URL), ("realid-waiver", TSA_WAIVER_URL)):
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
        except Exception as exc:
            log.warning("TSA %s fetch failed: %s", label, exc)
            continue
        page_states = _states_from_html(resp.text)
        log.info("  TSA %s: %d jurisdictions", label, len(page_states))
        found |= page_states
    missing_fallback = TSA_FALLBACK_STATES - found
    if missing_fallback:
        log.warning(
            "TSA scrape omitted %d known jurisdictions; supplementing from "
            "fallback list as of %s",
            len(missing_fallback),
            TSA_FALLBACK_AS_OF,
        )
        found |= TSA_FALLBACK_STATES
    log.info("TSA: found %d participating states", len(found))
    return found


# ---------------------------------------------------------------------------
# AAMVA VICAL parser (COSE/CBOR format, new endpoint since 2024)
# ---------------------------------------------------------------------------

def fetch_vical(session: requests.Session) -> tuple[dict, list[tuple[str, x509.Certificate]]]:
    """
    Download and parse the AAMVA VICAL.
    The VICAL endpoint serves an HTML page listing versioned downloads.
    Each download is a COSE_Sign1 wrapping a CBOR VICAL payload.
    Returns (meta_dict, [(state_abbr, Certificate), ...]).
    """
    log.info("Fetching AAMVA VICAL …")
    meta: dict[str, Any] = {}
    certs: list[tuple[str, x509.Certificate]] = []

    try:
        # Step 1: Discover the current VICAL download URL from the homepage
        resp = session.get(VICAL_BASE_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        match = re.search(r'/vical/vc/vc-[^\'"]+', resp.text)
        if not match:
            log.warning("VICAL: could not find download link on homepage")
            return meta, certs

        vical_url = "https://vical.dts.aamva.org" + match.group(0)
        log.info("  VICAL download URL: %s", vical_url)

        # Step 2: Download the COSE blob
        data_resp = session.get(vical_url, timeout=REQUEST_TIMEOUT)
        data_resp.raise_for_status()
        raw = data_resp.content
        log.info("  Downloaded %d bytes", len(raw))

        # Step 3: Parse COSE_Sign1 → CBOR payload → certificates
        meta, certs = _parse_vical_cose(raw)
        log.info("VICAL: parsed %d certificates", len(certs))

    except Exception as exc:
        log.warning("VICAL fetch/parse failed: %s", exc)
        if log.isEnabledFor(logging.DEBUG):
            traceback.print_exc()

    return meta, certs


def _parse_vical_cose(raw: bytes) -> tuple[dict, list[tuple[str, x509.Certificate]]]:
    """
    Parse a COSE_Sign1 VICAL blob.
    Structure: [protected, unprotected, payload, signature]
    Payload is CBOR map with keys: version, vicalProvider, date,
    vicalIssueID, nextUpdate, certificateInfos.
    Each certificateInfo contains a 'certificate' key with DER bytes.
    """
    import cbor2

    cose = cbor2.loads(raw)
    if not isinstance(cose, list) or len(cose) != 4:
        raise ValueError(f"Expected COSE_Sign1 array of 4, got {type(cose).__name__} len={len(cose) if isinstance(cose, list) else '?'}")

    _protected, _unprotected, payload_bytes, _signature = cose
    vical = cbor2.loads(payload_bytes)

    meta: dict[str, Any] = {}
    certs: list[tuple[str, x509.Certificate]] = []

    # Extract metadata
    if "vicalProvider" in vical:
        meta["vical_provider"] = str(vical["vicalProvider"])
    if "date" in vical:
        dt = vical["date"]
        meta["date"] = dt.isoformat() if hasattr(dt, "isoformat") else str(dt)
    if "nextUpdate" in vical:
        dt = vical["nextUpdate"]
        meta["next_update"] = dt.isoformat() if hasattr(dt, "isoformat") else str(dt)
    if "vicalIssueID" in vical:
        meta["vical_issue_id"] = int(vical["vicalIssueID"])
    if "version" in vical:
        meta["version"] = str(vical["version"])

    # Extract certificates from certificateInfos
    cert_infos = vical.get("certificateInfos", [])
    for info in cert_infos:
        cert_der = info.get("certificate")
        if not cert_der or not isinstance(cert_der, bytes):
            continue
        try:
            cert = x509.load_der_x509_certificate(cert_der)
            # Use stateOrProvinceName from the VICAL metadata if available
            state_field = info.get("stateOrProvinceName", "")
            state = _resolve_state_abbr(state_field, cert)
            doc_types = info.get("docType", [])
            certs.append((state, cert))
            log.debug("  %s: %s (%s)", state,
                       cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                       if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                       else cert.subject.rfc4514_string(),
                       doc_types)
        except Exception as exc:
            log.debug("  Skipping cert entry: %s", exc)

    return meta, certs


def _resolve_state_abbr(state_field: str, cert: x509.Certificate) -> str:
    """
    Resolve a state abbreviation from the VICAL stateOrProvinceName field
    (e.g. 'US-MD', 'AK') or fall back to certificate subject inspection.
    """
    if state_field:
        # Handle 'US-XX' format
        if state_field.startswith("US-") and len(state_field) == 5:
            abbr = state_field[3:]
            if abbr in ABBR_TO_STATE:
                return abbr
        # Direct abbreviation
        if state_field.upper() in ABBR_TO_STATE:
            return state_field.upper()

    return _infer_state_from_cert(cert)


def _infer_state_from_cert(cert: x509.Certificate) -> str:
    """
    Best-effort state abbreviation from a certificate's subject.
    Checks ST (stateOrProvinceName), OU, O, and CN fields.
    """
    try:
        attrs = cert.subject
        for oid in [
            x509.NameOID.STATE_OR_PROVINCE_NAME,
            x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
            x509.NameOID.ORGANIZATION_NAME,
            x509.NameOID.COMMON_NAME,
        ]:
            vals = attrs.get_attributes_for_oid(oid)
            if vals:
                text = vals[0].value
                # Handle US-XX format
                if text.startswith("US-") and len(text) == 5:
                    abbr = text[3:]
                    if abbr in ABBR_TO_STATE:
                        return abbr
                # Direct abbreviation match
                if text.upper() in ABBR_TO_STATE:
                    return text.upper()
                # Full state name match
                if text in STATE_TO_ABBR:
                    return STATE_TO_ABBR[text]
                # Substring scan
                for name, abbr in STATE_TO_ABBR.items():
                    if name.lower() in text.lower() or abbr in text.split():
                        return abbr
    except Exception:
        pass
    return "XX"  # Unknown


# ---------------------------------------------------------------------------
# Web root discovery
# ---------------------------------------------------------------------------

def _guess_cert_format(url: str) -> str | None:
    path = url.split("?", 1)[0].lower()
    if path.endswith(".zip"):
        return "zip"
    if path.endswith((".cer", ".crt", ".der", ".pem")):
        return "cer"
    return None


def _is_vical_url(url: str) -> bool:
    return any(host in url for host in VICAL_HOSTS)


def _fetch_cert_url(
    session: requests.Session,
    abbr: str,
    url: str,
    label: str,
    fmt: str,
) -> list[tuple[str, x509.Certificate, str]]:
    import io
    import zipfile

    results: list[tuple[str, x509.Certificate, str]] = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            log.debug("  %s: HTTP %s (%s)", abbr, resp.status_code, url)
            return results
        if fmt == "zip" or resp.content[:2] == b"PK":
            try:
                zf = zipfile.ZipFile(io.BytesIO(resp.content))
                for name in zf.namelist():
                    if re.search(r"\.(cer|der|crt|pem)$", name, re.IGNORECASE):
                        cert = _parse_cert(zf.read(name))
                        if cert:
                            results.append((abbr, cert, label))
                            log.info("  ✓  %s: root in zip (%s → %s)", abbr, label, name)
            except zipfile.BadZipFile:
                log.debug("  %s: not a valid zip (%s)", abbr, url)
            return results
        cert = _parse_cert(resp.content)
        if cert:
            results.append((abbr, cert, label))
            log.info("  ✓  %s: root found (%s)", abbr, label)
        else:
            log.debug("  %s: not parseable as certificate", abbr)
    except Exception as exc:
        log.debug("  %s: fetch error — %s", abbr, exc)
    return results


def parse_google_iaca_table(session: requests.Session) -> dict[str, Any]:
    """
    Ingest Google Wallet's production IACA table.

    Returns metadata plus downloadable US-state file URLs. Rows that
    redirect to AAMVA VICAL are recorded but not re-fetched.
    Non-US issuers (ID Pass, Aadhaar, etc.) are listed separately and
    are not treated as US mDL programs.
    """
    log.info("Ingesting Google Wallet IACA table …")
    meta: dict[str, Any] = {
        "source": GOOGLE_IACA_URL,
        "listed_states": [],
        "file_states": [],
        "vical_states": [],
        "page_states": [],
        "non_us": [],
        "file_urls": [],
    }
    try:
        resp = session.get(GOOGLE_IACA_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except Exception as exc:
        log.warning("Google IACA table fetch failed: %s", exc)
        return meta

    soup = BeautifulSoup(resp.text, "html.parser")
    seen_states: set[str] = set()
    for row in soup.find_all("tr"):
        cells = row.find_all(["td", "th"])
        if len(cells) < 3:
            continue
        jurisdiction = cells[0].get_text(" ", strip=True)
        cred_type = cells[1].get_text(" ", strip=True)
        if jurisdiction in {"Country / US State", "Country"}:
            continue
        link = cells[2].find("a")
        href = (link.get("href") or "").strip() if link else ""
        if href.startswith("/"):
            href = "https://developers.google.com" + href

        abbr = STATE_TO_ABBR.get(jurisdiction)
        if not abbr:
            if jurisdiction and jurisdiction not in {"Country / US State", "Country"}:
                meta["non_us"].append({
                    "name": jurisdiction,
                    "credential_type": cred_type,
                    "href": href,
                })
            continue
        if cred_type and cred_type.lower() not in {"mdl", "credential type"}:
            # e.g. Google's own "ID Pass" row under United States
            meta["non_us"].append({
                "name": jurisdiction,
                "credential_type": cred_type,
                "href": href,
            })
            continue

        if abbr not in seen_states:
            meta["listed_states"].append(abbr)
            seen_states.add(abbr)

        if not href:
            continue
        if _is_vical_url(href):
            if abbr not in meta["vical_states"]:
                meta["vical_states"].append(abbr)
            continue
        fmt = _guess_cert_format(href)
        if fmt:
            meta["file_urls"].append((abbr, href, f"Google Wallet IACA ({abbr})", fmt))
            if abbr not in meta["file_states"]:
                meta["file_states"].append(abbr)
        else:
            if abbr not in meta["page_states"]:
                meta["page_states"].append(abbr)

    log.info(
        "Google IACA: %d US mDL rows (%d file, %d VICAL, %d page-only), %d non-US",
        len(meta["listed_states"]),
        len(meta["file_states"]),
        len(meta["vical_states"]),
        len(meta["page_states"]),
        len(meta["non_us"]),
    )
    return meta


def discover_web_roots(
    session: requests.Session,
    extra_urls: list[tuple[str, str, str, str]] | None = None,
) -> list[tuple[str, x509.Certificate, str]]:
    """Fetch IACA files from the hardcoded catalog plus Google-discovered URLs."""
    log.info("Discovering web roots …")
    results: list[tuple[str, x509.Certificate, str]] = []
    seen: set[str] = set()
    catalog = list(KNOWN_STATE_CERT_URLS) + list(extra_urls or [])
    for abbr, url, label, fmt in catalog:
        if url in seen:
            continue
        seen.add(url)
        results.extend(_fetch_cert_url(session, abbr, url, label, fmt))
    log.info("Web discovery: found %d roots from %d URLs", len(results), len(seen))
    return results


# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------

def build_dashboard_data(
    tsa_states: set[str],
    vical_meta: dict,
    vical_certs: list[tuple[str, x509.Certificate]],
    web_certs: list[tuple[str, x509.Certificate, str]],
    google_meta: dict | None = None,
    google_certs: list[tuple[str, x509.Certificate, str]] | None = None,
) -> dict:
    """
    Merge all sources into the DASHBOARD_DATA schema expected by index.html.
    """
    log.info("Building dashboard data …")

    # --- Deduplicate certificates by SHA-256 fingerprint --------------------
    # Track: fingerprint -> (record_dict, sources)
    all_fingerprints: dict[str, dict] = {}
    # Track per-state collected certs
    state_certs: dict[str, dict[str, dict]] = {}  # abbr -> {fp: record}

    def _add_cert(abbr: str, cert: x509.Certificate, source: str) -> None:
        record = _cert_to_record(cert, abbr)
        fp = record["fingerprint_sha256"]
        if abbr not in state_certs:
            state_certs[abbr] = {}
        if fp not in state_certs[abbr]:
            state_certs[abbr][fp] = record
            state_certs[abbr][fp]["_sources"] = []
        if source not in state_certs[abbr][fp]["_sources"]:
            state_certs[abbr][fp]["_sources"].append(source)
        all_fingerprints[fp] = state_certs[abbr][fp]

    for abbr, cert in vical_certs:
        if abbr != "XX":
            _add_cert(abbr, cert, "AAMVA")

    for abbr, cert, label in web_certs:
        _add_cert(abbr, cert, "Web")

    for abbr, cert, label in (google_certs or []):
        _add_cert(abbr, cert, "Google")

    google_meta = google_meta or {}
    google_listed = set(google_meta.get("listed_states") or [])

    # --- Determine all mDL states (TSA union VICAL union web union Google) --
    mdl_states: set[str] = set(tsa_states) | google_listed
    for abbr in state_certs:
        if abbr != "XX":
            mdl_states.add(abbr)

    # --- Determine states with at least one root ----------------------------
    states_with_root: set[str] = {
        abbr for abbr, certs in state_certs.items()
        if abbr != "XX" and len(certs) > 0
    }

    # --- Build authorities list ---------------------------------------------
    authorities: list[dict] = []
    for abbr in sorted(mdl_states):
        state_name = ABBR_TO_STATE.get(abbr, abbr)
        roots_map = state_certs.get(abbr, {})

        sources: list[str] = []
        if abbr in tsa_states:
            sources.append("TSA")
        if any("AAMVA" in r.get("_sources", []) for r in roots_map.values()):
            sources.append("AAMVA")
        if any("Web" in r.get("_sources", []) for r in roots_map.values()):
            sources.append("Web")
        if abbr in google_listed or any(
            "Google" in r.get("_sources", []) for r in roots_map.values()
        ):
            sources.append("Google")

        # Build clean root records (drop private fields)
        roots = []
        pem_entries = []
        for record in roots_map.values():
            pem = record.pop("_pem", None)
            rec_sources = record.pop("_sources", [])
            # Expose primary source on the record for the dashboard UI
            record["source"] = rec_sources[0] if rec_sources else "Unknown"
            roots.append(record)
            if pem:
                pem_entries.append({
                    "state": abbr,
                    "subject_cn": record["subject_cn"],
                    "pem": pem,
                })

        authorities.append({
            "name": state_name,
            "abbr": abbr,
            "sources": sources,
            "eligible_ids": [f"{abbr} DL", f"{abbr} ID"],
            "roots": roots,
            "_pem_entries": pem_entries,
        })

    # --- Flat PEM bundle ----------------------------------------------------
    pem_bundle: list[dict] = []
    for auth in authorities:
        pem_bundle.extend(auth.pop("_pem_entries", []))

    # --- Map states ---------------------------------------------------------
    map_states: dict[str, str] = {}
    for abbr in mdl_states:
        if abbr in states_with_root:
            map_states[abbr] = "mdl_with_root"
        else:
            map_states[abbr] = "mdl_no_root"

    # --- Stats --------------------------------------------------------------
    pop_with_mdl = sum(
        STATE_POPULATIONS.get(abbr, 0)
        for abbr in mdl_states
        if abbr in STATE_POPULATIONS
    )
    pop_coverage_pct = round(pop_with_mdl / US_TOTAL_POP * 100, 1)

    total_roots = sum(len(a["roots"]) for a in authorities)
    programs_with_root = sum(1 for a in authorities if len(a["roots"]) > 0)
    root_coverage_pct = (
        round(programs_with_root / len(mdl_states) * 100, 1) if mdl_states else 0
    )

    # Count distinct states in VICAL
    vical_state_set = {abbr for abbr, _ in vical_certs if abbr != "XX"}
    web_state_set = {abbr for abbr, _, _ in web_certs}
    google_file_states = set(google_meta.get("file_states") or [])
    google_cert_states = {abbr for abbr, _, _ in (google_certs or [])}

    # Serializable copy of Google metadata (drop the raw URL tuples).
    google_public = {
        "source": google_meta.get("source", GOOGLE_IACA_URL),
        "listed_states": google_meta.get("listed_states") or [],
        "file_states": google_meta.get("file_states") or [],
        "vical_states": google_meta.get("vical_states") or [],
        "page_states": google_meta.get("page_states") or [],
        "non_us_count": len(google_meta.get("non_us") or []),
    }

    stats = {
        "tsa_recognized": len(tsa_states),
        "vical_authorities": len(vical_state_set),
        "web_discovered": len(web_state_set),
        "google_listed": len(google_listed),
        "google_files": len(google_file_states | google_cert_states),
        "total_roots": total_roots,
        "root_coverage_pct": root_coverage_pct,
        "population_coverage_pct": pop_coverage_pct,
    }

    return {
        "_generated": datetime.now(tz=timezone.utc).isoformat(),
        "_pipeline_version": PIPELINE_VERSION,
        "stats": stats,
        "vical_meta": vical_meta,
        "google_meta": google_public,
        "map_states": map_states,
        "authorities": authorities,
        "_pem_bundle": pem_bundle,
    }


# ---------------------------------------------------------------------------
# HTML injection
# ---------------------------------------------------------------------------

INJECTION_MARKER = "<!-- {{DASHBOARD_DATA}} -->"
SCRIPT_OPEN_RE = re.compile(r"(<script>)\s*\n//\s*──\s*Configuration", re.MULTILINE)


def embed_into_html(template_html: str, data: dict) -> str:
    """
    Inject DASHBOARD_DATA as an inline <script> block into the template HTML.
    Tries three strategies in order:
      1. Replace the INJECTION_MARKER comment.
      2. Insert before the first `<script>// ── Configuration` block.
      3. Insert just before </body>.
    """
    json_str = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    script_block = f'<script id="inline-data">window.DASHBOARD_DATA = {json_str};</script>\n'

    if INJECTION_MARKER in template_html:
        return template_html.replace(INJECTION_MARKER, script_block)

    match = SCRIPT_OPEN_RE.search(template_html)
    if match:
        pos = match.start()
        return template_html[:pos] + script_block + "\n" + template_html[pos:]

    # Fallback: before </body>
    return template_html.replace("</body>", script_block + "</body>")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="mDL dashboard pipeline")
    parser.add_argument("--dry-run", action="store_true", help="Print JSON, no file write")
    parser.add_argument("--no-web", action="store_true", help="Skip web root discovery")
    parser.add_argument("--debug", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    session = _session()

    # --- Fetch all sources --------------------------------------------------
    tsa_states = fetch_tsa_states(session)
    vical_meta, vical_certs = fetch_vical(session)

    google_meta: dict[str, Any] = {}
    google_certs: list[tuple[str, x509.Certificate, str]] = []
    web_certs: list[tuple[str, x509.Certificate, str]] = []
    if not args.no_web:
        google_meta = parse_google_iaca_table(session)
        web_certs = discover_web_roots(session)
        # Fetch Google-advertised files separately so they keep a Google source tag.
        known_urls = {url for _, url, _, _ in KNOWN_STATE_CERT_URLS}
        extra = [
            row for row in google_meta.get("file_urls") or []
            if row[1] not in known_urls
        ]
        for abbr, url, label, fmt in extra:
            google_certs.extend(_fetch_cert_url(session, abbr, url, label, fmt))

    # --- Build data ---------------------------------------------------------
    data = build_dashboard_data(
        tsa_states,
        vical_meta,
        vical_certs,
        web_certs,
        google_meta=google_meta,
        google_certs=google_certs,
    )

    log.info(
        "Built dashboard data: %d states, %d total roots",
        len(data["authorities"]),
        data["stats"]["total_roots"],
    )

    if args.dry_run:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    # --- Load template ------------------------------------------------------
    if not TEMPLATE_PATH.exists():
        log.error("Template not found: %s", TEMPLATE_PATH)
        return 1

    template_html = TEMPLATE_PATH.read_text(encoding="utf-8")
    output_html = embed_into_html(template_html, data)

    # --- Write output -------------------------------------------------------
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(output_html, encoding="utf-8")
    log.info("Wrote %s (%d bytes)", OUTPUT_PATH, len(output_html))

    return 0


if __name__ == "__main__":
    sys.exit(main())
