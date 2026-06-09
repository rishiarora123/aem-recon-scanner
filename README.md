# AEM Recon Scanner

A focused, automated reconnaissance and vulnerability scanner for **Adobe Experience Manager (AEM)** and **Next.js** deployments. Given a root domain (or a pre-built host list), it discovers subdomains, confirms live ones, fingerprints tech stack, maps CVEs, and probes for dispatcher bypass vulnerabilities — all from a single browser-based UI.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Pipeline Overview

```
Domain
  │
  ▼
Phase 1 ─ Subdomain Enumeration
          C99.nl (API/scraper) · subfinder · crt.sh · SecurityTrails · OTX
  │
  ▼
Phase 2 ─ Alive Check
          Parallel httpx probing — HTTP status + response time
  │
  ▼
Phase 3 ─ Tech Detection
          AEM fingerprinting (6 methods, score-based)
          Next.js detection (8+ methods) + CVE mapping
  │
  ▼
Phase 4 ─ AEM Bypass Scan
          13 bypass techniques × 58 sensitive endpoints
```

### Extra capabilities

| Feature | Details |
|---|---|
| **Next.js CVE mapping** | Detected version cross-referenced against 6 CVEs with direct Nuclei template links |
| **Internet auto-pause** | Scan pauses on connectivity loss, auto-resumes from exact batch when restored |
| **Resume after restart** | Server restart? Click ▶ Resume — continues from last saved cursor |
| **Streaming downloads** | Subdomain/alive lists stream line-by-line; no browser-freezing 800 MB responses |
| **Standalone Next.js checker** | Check any URL for Next.js + version + CVEs without running a full scan |
| **Real-time WebSocket feed** | Every discovery, error and phase transition streams to the browser instantly |

---

## Quick Start

### Prerequisites

```bash
# Python 3.10+
pip install -r requirements.txt

# Optional but highly recommended
brew install subfinder          # macOS, or:
# go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx for fast alive checking:
# https://github.com/projectdiscovery/httpx/releases
```

### Run

```bash
python3 server.py
# Open http://localhost:8000
```

---

## Configuration

### C99.nl API Key (recommended — up to 100K subdomains per domain)

```bash
export C99_API_KEY=your_key_here   # $5 one-time at https://api.c99.nl
```

Without an API key the scanner falls back to HTML scraping with automatic proxy rotation.

### Proxy rotation for C99 scraping

```bash
export C99_PROXIES=http://1.2.3.4:8080,socks5://5.6.7.8:1080
```

If no proxies are set and an abuse block is detected, the scanner auto-fetches fresh free proxies.

---

## Subdomain Sources

| Source | Method | Coverage |
|---|---|---|
| **C99.nl** | Official JSON API or HTML scraper | Largest — up to 100K per domain |
| **subfinder** | Passive DNS aggregator CLI | Covers 40+ passive DNS providers |
| **crt.sh** | Certificate Transparency logs | Good wildcard cert coverage |
| **SecurityTrails** | Public API | Historical subdomain data |
| **AlienVault OTX** | Threat intelligence API | Old/forgotten subdomains |

---

## AEM Detection (Phase 3)

Score-based fingerprinting — 6 independent methods:

| Method | Signal | Score |
|---|---|---|
| A | HTML — `/etc.clientlibs/`, `jcr:` attrs, `cq-` CSS classes, `/content/dam/` paths | +5 each |
| B | HTTP headers — `x-dispatcher`, `x-vhost`, `x-aem-request-id` | +4 each |
| C | Path probing — `/libs/granite/`, `/crx/de/`, `/bin/querybuilder.json` | +3 each |
| D | Body signatures — `jcr:primaryType`, `sling:resourceType`, `granite.ui.` | +5 each |
| E | JS objects — `CQ.WCM`, `Granite.*`, `Sling.servlet` | +3 each |
| F | Sample content — `/content/we-retail/`, `/content/geometrixx/` | +5 each |

**Confidence:** score ≥ 10 → `confirmed` · score ≥ 5 → `suspected` · helix-rum-js only → `edge_delivery`

---

## Next.js Detection (Phase 3)

| Method | Signal |
|---|---|
| M0 | `X-Powered-By: Next.js` / `x-nextjs-cache` / `x-nextjs-prerender` headers |
| M1 | `__NEXT_DATA__` JSON tag (Pages Router) — extracts `buildId` |
| M2 | `<meta name="generator" content="Next.js X.Y.Z">` |
| M2b | `<meta name="next-head-count">` (App Router indicator) |
| M3 | `<div id="__next">` and `data-next-page` attributes |
| M4 | `/_next/static/` asset paths in HTML + build ID extraction |
| M5 | `/_next/image` endpoint response signature |
| M6 | `_buildManifest.js` via known build ID |
| M7 | Fetch all `/_next/static/chunks/*.js` in priority order, extract version regex |
| M8 | Extract React version from `framework-*.js` → infer Next.js range (hardened build fallback) |

### Hardened build handling

Enterprise builds (Microsoft, large Vercel customers) strip all version strings from JS bundles.
When no exact version is found, the scanner:

1. Extracts the React version from `framework-*.js` using React-specific patterns
2. Maps React major → Next.js range: `React 19.x → Next.js ~15.x`
3. Shows an amber `~15.x ≈` badge — clearly distinct from an exact cyan `v14.2.3` badge

---

## Next.js CVE Database

Detected versions are automatically cross-referenced. Exact versions get definitive matches; inferred ranges get "possibly affected" flags.

| CVE | Severity | CVSS | Title | Affected versions | Nuclei |
|---|---|---|---|---|---|
| [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) | **CRITICAL** | 9.1 | Middleware Auth Bypass | < 12.3.5 · 13.x < 13.5.9 · 14.x < 14.2.25 · 15.x < 15.2.3 | [template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-29927.yaml) |
| [CVE-2024-56332](https://nvd.nist.gov/vuln/detail/CVE-2024-56332) | **HIGH** | 8.1 | SSRF via Image Optimization | < 15.1.0 | [template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-56332.yaml) |
| [CVE-2024-34351](https://nvd.nist.gov/vuln/detail/CVE-2024-34351) | **HIGH** | 7.5 | SSRF via Host Header (Server Actions) | 14.0.0 – 14.1.0 | [template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-34351.yaml) |
| [CVE-2024-46982](https://nvd.nist.gov/vuln/detail/CVE-2024-46982) | **HIGH** | 7.5 | Cache Poisoning via Host Header | < 13.5.7 · 14.x < 14.2.10 | [template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-46982.yaml) |
| [CVE-2025-32421](https://nvd.nist.gov/vuln/detail/CVE-2025-32421) | MEDIUM | 5.3 | ReDoS via Path Parameter | < 14.2.26 · 15.x < 15.1.7 | [template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32421.yaml) |
| [CVE-2025-32280](https://nvd.nist.gov/vuln/detail/CVE-2025-32280) | MEDIUM | 5.9 | DoS — Infinite Loop in App Router | < 14.2.30 · 15.x < 15.2.4 | [template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32280.yaml) |

### Run Nuclei against findings

```bash
# Verify with Nuclei templates (install: https://github.com/projectdiscovery/nuclei)
nuclei -u https://target.example.com \
  -t http/cves/2025/CVE-2025-29927.yaml \
  -t http/cves/2024/CVE-2024-46982.yaml \
  -t http/cves/2024/CVE-2024-34351.yaml \
  -t http/cves/2024/CVE-2024-56332.yaml \
  -t http/cves/2025/CVE-2025-32421.yaml \
  -t http/cves/2025/CVE-2025-32280.yaml

# Or run all Next.js CVE templates at once
nuclei -u https://target.example.com -tags nextjs,cve
```

---

## AEM Bypass Scan (Phase 4)

### 13 Dispatcher bypass techniques

| # | Tag | Path pattern |
|---|---|---|
| 1 | `nocanon` | `/graphql/execute.json/..%2f../{endpoint}` |
| 2 | `nocanon-upper` | `/graphql/execute.json/..%2F../{endpoint}` |
| 3 | `nocanon-2slash` | `//graphql/execute.json/..%2f../{endpoint}` |
| 4 | `nocanon-2slash-up` | `//graphql/execute.json/..%2F../{endpoint}` |
| 5 | `path-param` | `/{endpoint};a.css` |
| 6 | `hybrid` | `/{endpoint};x=graphql/execute.json` |
| 7 | `dynmedia` | `/adobe/dynamicmedia/deliver/..;/..;/..;/{endpoint}` |
| 8 | `nocanon-3dot` | `/graphql/execute.json/..%2f..%2f..%2f{endpoint}` |
| 9 | `double-slash` | `//{endpoint}` |
| 10 | `encoded-slash` | `/%2f{endpoint}` |
| 11 | `semi-traverse` | `/content/..;/{endpoint}` |
| 12 | `suffix-bypass` | `/{endpoint}.css/a.html` |
| 13 | `ext-json` | `/{endpoint-root}.ext.json` |

### 58 sensitive AEM endpoints

QueryBuilder · CRX/PackMgr · CRXDE Lite · OSGi Console · JMX · OSGi ConfigMgr · Product Info · Health Check · Content JSON · DAM JSON · User Admin · Granite Login · CSRF Token Leak · Trust Store · Replication Agents · Cloud Services · Domain Manager · ACS Audit Log · and more.

---

## Resume After Restart

Every Phase 2 batch and Phase 3 host is checkpointed to `scans_db.json`. On restart:

1. Dashboard shows interrupted scans with an **▶ Resume** button
2. Resume logic automatically picks the right phase:
   - Has `aem_hosts` → continue from **Phase 4**
   - Has `alive_hosts` → continue from **Phase 3**
   - Has `subdomains` or `phase2_cursor > 0` → continue from **Phase 2**
   - Otherwise → restart from **Phase 1**

---

## Internet Auto-Pause

Background monitor probes `8.8.8.8:53`, `1.1.1.1:53`, `8.8.4.4:53` every 10 s (online) / 30 s (offline).

When connectivity drops mid-scan:
- Scan status → `paused`, WebSocket sends `internet_pause` event
- UI shows pulsing amber **PAUSED** badge
- Scan thread blocks at the current probe

When connectivity restores:
- Scan automatically resumes from exactly where it paused
- WebSocket sends `internet_resume` with downtime duration

---

## API Reference

### Scan lifecycle

```
POST   /api/scan                          Start scan
GET    /api/scan/{id}/status              Status poll
GET    /api/scan/{id}/results             Full results (counts for large arrays)
POST   /api/scan/{id}/cancel             Cancel
POST   /api/scan/{id}/resume             Resume interrupted scan
DELETE /api/scan/{id}                     Delete
```

### Downloads (streaming)

```
GET /api/scan/{id}/download/subdomains    Line-by-line subdomain list
GET /api/scan/{id}/download/alive         Line-by-line alive hosts
GET /api/scan/{id}/download/vulnerabilities  Vulnerability JSON
```

### Utilities

```
POST /api/detect-nextjs                   Standalone Next.js detection
GET  /api/internet                        Connectivity status
GET  /api/scans                           List all scans
POST /api/upload-hosts                    Upload host list (skip Phase 1)
```

### WebSocket events

| `type` | Key fields | Meaning |
|---|---|---|
| `subdomain_found` | `subdomain` | New subdomain |
| `alive_host` | `host`, `status_code`, `response_time_ms` | Live host confirmed |
| `aem_detected` | `host`, `confidence`, `score`, `reasons` | AEM result |
| `nextjs_detected` | `host`, `version`, `router`, `cves[]` | Next.js + CVEs |
| `vuln_found` | `host`, `endpoint`, `bypass`, `status_code` | Bypass hit |
| `internet_pause` | `message`, `context` | Connectivity lost |
| `internet_resume` | `message`, `waited_seconds` | Connectivity restored |
| `phase` | `phase`, `name`, `status`, `count` | Phase lifecycle |

---

## Output Structure

```
scan.subdomains          []str   All discovered subdomains
scan.alive_hosts         []str   Confirmed live hosts
scan.aem_hosts           {host → {confidence, score, reasons[]}}
scan.nextjs_hosts        {host → {version, version_inferred, react_version, router, cves[], ...}}
scan.vulnerabilities     [{host, endpoint, bypass, status_code, body_snippet, ...}]
scan.vulnerability_summary  {total, by_host, by_endpoint}
```

---

## Legal

This tool is for **authorised security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorised scanning may violate computer crime laws in your jurisdiction.

---

## License

MIT — see [LICENSE](LICENSE)
