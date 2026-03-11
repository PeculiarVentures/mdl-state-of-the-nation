# mDL State of the Nation

Interactive dashboard tracking mobile Driver's License (mDL) deployment across US jurisdictions — root certificate discovery, AAMVA VICAL verification, and population coverage.

**Live:** [mdl.peculiarventures.com](https://mdl.peculiarventures.com)

## Data Sources

| Source | What | How |
|--------|------|-----|
| **TSA** | Participating states | Scrape tsa.gov digital ID page |
| **AAMVA VICAL** | Root certificates per state | Download COSE/CBOR VICAL, parse X.509 certs |
| **Web Discovery** | State-published IACA roots | Fetch from CA, GA, HI, PR DMV/DOT sites |

## Architecture

```
src/index.html          ← Dashboard template (HTML/CSS/JS)
pipeline.py             ← Data pipeline: TSA + VICAL + web discovery → embedded JSON
vendor.py               ← Asset vendoring: fonts, D3, topojson, Peculiar viewer, us-atlas
docs/                   ← Compiled output served by GitHub Pages
  index.html            ← Self-contained dashboard with embedded data
  assets/               ← Vendored JS, CSS, fonts, map data, cert viewer
.github/workflows/
  build.yml             ← CI: vendor → pipeline → commit → deploy → purge cache
```

## Pipeline

The pipeline runs on every push to `main` via GitHub Actions:

1. **`vendor.py`** downloads all external assets (D3, topojson, us-atlas TopoJSON, Google Fonts via Fontsource, @peculiar/certificates-viewer with all Stencil chunks) into `docs/assets/`. Cached by content hash.

2. **`pipeline.py`** fetches live data from TSA, AAMVA VICAL (COSE/CBOR format), and state DMV/DOT sites. Parses X.509 certificates, computes stats, and injects `DASHBOARD_DATA` into `src/index.html` → `docs/index.html`.

3. The compiled `docs/` directory is committed and served by GitHub Pages. Cloudflare cache is purged if secrets are configured.

## Local Development

```bash
pip install -r requirements.txt
python vendor.py          # download assets (once)
python pipeline.py        # build docs/index.html with live data
cd docs && python -m http.server 8000
```

## Dependencies

- Python 3.12+
- `requests`, `beautifulsoup4`, `lxml`, `cryptography`, `asn1crypto`, `cbor2`

## Certificate Viewer

Uses [@peculiar/certificates-viewer](https://github.com/nicktaras/nicktaras.github.io), the Stencil-based X.509 certificate viewer from Peculiar Ventures. All 42+ Stencil lazy-load chunks are vendored for zero third-party runtime requests.

---

*Peculiar Ventures — Companion to [mDL Meets the WebPKI Ecosystem](https://unmitigatedrisk.com)*
*WebPKI data at the [WebPKI Observatory](https://webpki.systematicreasoning.com)*
