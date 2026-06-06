# AEM RECON — Dispatcher Bypass Scanner

A professional, real-time web-based scanner for discovering Adobe Experience Manager (AEM) instances and testing Dispatcher bypass vulnerabilities across target domains.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

### 4-Phase Scanning Pipeline

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Subdomain Enumeration** | Discovers subdomains using `subfinder` + passive OSINT sources |
| 2 | **Alive Host Check** | Filters live hosts with ProjectDiscovery `httpx` |
| 3 | **AEM Detection** | Multi-signal fingerprinting (response headers, body patterns, status-code differentials) with false-positive filtering |
| 4 | **Dispatcher Bypass Scan** | Tests 9 bypass techniques across 46 sensitive AEM endpoints |

### 9 Bypass Techniques

| # | Tag | Method |
|---|-----|--------|
| 1 | `nocanon` | Path traversal via `%2f` encoding |
| 2 | `nocanon-upper` | Path traversal via `%2F` uppercase encoding |
| 3 | `nocanon-2slash` | Double-slash prefix with `%2f` traversal |
| 4 | `nocanon-2slash-up` | Double-slash prefix with `%2F` traversal |
| 5 | `path-param` | Semicolon path parameter injection (`;a.css`) |
| 6 | `hybrid` | Semicolon + GraphQL execute path |
| 7 | `dynmedia` | Dynamic Media deliver path traversal |
| 8 | `nocanon-3dot` | Triple-dot encoded traversal |
| 9 | `ext-json` | `.ext.json` selector bypass |

### 46 Sensitive Endpoints Tested

Includes CRX/DE, OSGi Console, Package Manager, QueryBuilder, JMX, DAM, User Admin, CSRF Token, Replication Agents, and more.

### Professional Dashboard

- **SOC-style operations dashboard** — view all scans at a glance
- **Real-time status** — Running (pulse animation) / Complete / Error badges
- **Stats cards** — Total scans, Running, Completed, AEM hosts found, Vulnerabilities
- **Click any scan row** to load full results in the scanner view
- **Auto-refresh** every 5 seconds

### Per-Phase Controls

- **Download TXT** — Export the shortlisted hosts from any phase as a `.txt` file
- **Upload TXT** — Import your own host list into any phase
- **Continue from any phase** — Skip earlier phases by uploading hosts and clicking Continue

### Real-Time WebSocket Feed

- Live event stream as the scan progresses
- Auto-scrolling log with timestamps
- Phase progress cards with completion badges

---

## Screenshots

```
┌────────────────────────────────────────────────────────────────┐
│  AEM RECON — Dispatcher Bypass Scanner                        │
│                                                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ Subs: 42 │ │ Alive:18 │ │ AEM: 3   │ │ Vulns: 1 │         │
│  │ COMPLETE │ │ COMPLETE │ │ COMPLETE │ │ COMPLETE │         │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
│                                                                │
│  LIVE FEED                    AEM HOSTS │ VULNS │ ALL HOSTS   │
│  21:14:01 › Subfinder: 42    ┌─────────────────────┐          │
│  21:14:23 › Alive: 18       │ example.com          │          │
│  21:15:01 › AEM confirmed:3 │ CONFIRMED Score: 26  │          │
│  21:16:37 › Scan complete   │ [tags] [tags] [tags] │          │
│                              └─────────────────────┘          │
└────────────────────────────────────────────────────────────────┘
```

---

## Setup

### Prerequisites

- **Python 3.10+**
- **Go** (for installing subfinder and httpx)
- **subfinder** — subdomain enumeration
- **httpx** (ProjectDiscovery) — alive host checking

### 1. Install Go Tools

```bash
# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install httpx (ProjectDiscovery)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Make sure `~/go/bin` is in your `PATH`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### 2. Clone the Repository

```bash
git clone https://github.com/rishiarora123/aem-recon-scanner.git
cd aem-recon-scanner
```

### 3. Install Python Dependencies

```bash
pip3 install fastapi uvicorn requests pydantic
```

Or with a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn requests pydantic
```

### 4. Run the Scanner

```bash
python3 server.py
```

The server starts at **http://localhost:8000**.

### Environment Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8000` | Server port |
| `HOST` | `0.0.0.0` | Bind address |

```bash
PORT=9090 python3 server.py
```

---

## Usage

### From the Dashboard

1. Open **http://localhost:8000** in your browser
2. Click **NEW SCAN** to switch to the scanner view
3. Enter a domain (e.g., `microsoft.com`) or paste a list of URLs
4. Click **LAUNCH SCAN**
5. Watch the 4-phase pipeline run in real-time
6. Click **◄ DASHBOARD** to see all scans

### Continue from Any Phase

You can skip earlier phases by uploading a pre-made host list:

1. Hover over any phase card → click the **upload** icon
2. Upload a `.txt` file (one host per line)
3. Click **CONTINUE** to start scanning from that phase

### Download Phase Results

- Hover over any phase card → click the **download** icon
- A `.txt` file with all hosts from that phase will download

### Export Results

- Click **EXPORT JSON** to download full scan results as JSON

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start a new scan |
| `GET` | `/api/scan/{id}/status` | Get scan status |
| `GET` | `/api/scan/{id}/results` | Get full scan results |
| `GET` | `/api/scans` | List all scans (dashboard) |
| `WS` | `/ws/{id}` | Real-time WebSocket updates |

### Start a Scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "threads": 20, "timeout": 10}'
```

### Continue from Phase 3 (AEM Detection)

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "start_phase": 3,
    "uploaded_hosts": ["host1.example.com", "host2.example.com"]
  }'
```

### Scan Request Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | string | — | Target domain for subdomain enumeration |
| `url` | string | — | Single URL to scan directly |
| `urls` | list | — | List of URLs to scan directly |
| `threads` | int | `20` | Concurrent threads |
| `per_host_concurrency` | int | `3` | Concurrent requests per host |
| `timeout` | int | `10` | Request timeout in seconds |
| `bypass_mode` | string | `"full"` | Bypass scan mode |
| `start_phase` | int | `1` | Phase to start from (1-4) |
| `uploaded_hosts` | list | — | Pre-populated hosts for the start phase |

---

## Project Structure

```
aem-scanner-web/
├── server.py              # FastAPI backend (scanner engine + API + WebSocket)
├── templates/
│   └── index.html         # Frontend (single-page app, vanilla JS)
├── dns-wordlist.txt       # DNS brute-force wordlist for subdomain enum
└── README.md
```

---

## How It Works

```
                    ┌─────────────────────┐
                    │   Enter Domain /    │
                    │   Upload Host List  │
                    └─────────┬───────────┘
                              │
              ┌───────────────▼───────────────┐
     Phase 1  │   Subdomain Enumeration       │
              │   (subfinder + passive OSINT)  │
              └───────────────┬───────────────┘
                              │ subdomains
              ┌───────────────▼───────────────┐
     Phase 2  │   Alive Host Check            │
              │   (httpx probe)               │
              └───────────────┬───────────────┘
                              │ alive hosts
              ┌───────────────▼───────────────┐
     Phase 3  │   AEM Detection               │
              │   Multi-signal fingerprint:   │
              │   • Response headers          │
              │   • Body pattern matching     │
              │   • Status-code differential  │
              │   • False-positive filtering  │
              └───────────────┬───────────────┘
                              │ confirmed AEM hosts
              ┌───────────────▼───────────────┐
     Phase 4  │   Dispatcher Bypass Scan      │
              │   9 techniques × 46 endpoints │
              │   Body-signature validation   │
              └───────────────┬───────────────┘
                              │
                    ┌─────────▼───────────┐
                    │   Results + Export   │
                    │   Dashboard View    │
                    └─────────────────────┘
```

### AEM Detection (Phase 3)

The scanner uses a multi-signal approach to accurately identify AEM instances:

- **Control probe** — Requests a random non-existent path to establish the server's default behavior
- **AEM-specific paths** — Tests `/libs/granite/core/content/login.html`, `/crx/de`, `/system/console`, etc.
- **Differential analysis** — Compares AEM path responses against the control probe
- **Catch-all filtering** — Detects servers that return the same status code for everything (common false positive source)
- **Scoring system** — Assigns confidence scores; hosts scoring above threshold are marked CONFIRMED

### Dispatcher Bypass (Phase 4)

For each confirmed AEM host, the scanner:

1. Tests all 46 sensitive endpoints through 9 bypass techniques (414 requests per host)
2. Validates responses against AEM body signatures to confirm genuine access
3. Reports only verified bypasses with technique tag, endpoint, status code, and matched signature

---

## Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper written authorization before scanning any targets. Unauthorized scanning is illegal and unethical. The authors are not responsible for any misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
