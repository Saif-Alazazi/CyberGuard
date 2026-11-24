"""Layer 3: known-bad lookups and plain DNS.

Live per-link: OpenPhish (current feed), URLhaus, ThreatFox (abuse.ch), Cloudflare 1.1.1.2 filtering DNS.
Bulk domain lists, refreshed every 6 h: Phishing.Database (active phishing domains) and Phishing Army.
A listed domain never overrides the official / popular / shared-hosting protections.
"""
import asyncio
import time

import httpx

from app import config
from app.data import data, split_host

_OPENPHISH = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
_state = {"urls": set(), "hosts": set(), "loaded": 0.0}
_lock = asyncio.Lock()
BULK_LISTS = {
    "Phishing.Database": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "Phishing Army": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
}
_bulk = {"sets": {}, "loaded": 0.0, "sizes": {}}
_bulk_lock = asyncio.Lock()


async def load_bulk() -> dict:
    """Download the bulk domain lists (every 6 h). Kept as frozensets: ~540k domains, roughly 60 MB of RAM."""
    async with _bulk_lock:
        if time.time() - _bulk["loaded"] > 6 * 3600:
            async with httpx.AsyncClient(timeout=60, verify=config.SSL_CTX, follow_redirects=True) as c:
                for name, url in BULK_LISTS.items():
                    try:
                        r = await c.get(url)
                        r.raise_for_status()
                        s = frozenset(l.strip().lower() for l in r.text.splitlines() if l.strip() and not l.startswith("#"))
                        _bulk["sets"][name] = s
                        _bulk["sizes"][name] = len(s)
                    except httpx.HTTPError:
                        pass  # keep the previous copy; retried at the next refresh
            _bulk["loaded"] = time.time() if _bulk["sets"] else time.time() - 5 * 3600
    return _bulk["sets"]


def _bulk_candidates(host: str) -> list[str]:
    """Host and its parent domains, stopping before anything official, popular or a shared-hosting apex."""
    d = data()
    reg = split_host(host)[3]
    if d.official_brand(reg) or d.tranco_rank(reg) or d.global_official(reg):
        return []
    out, parts = [], host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if d.hosting_suffix(cand) == cand or d.is_shortener(cand):
            break
        out.append(cand)
        if cand == reg:
            break
    return out


async def _openphish() -> tuple[set, set]:
    async with _lock:
        if time.time() - _state["loaded"] > 3600:
            try:
                async with httpx.AsyncClient(timeout=15, verify=config.SSL_CTX) as c:
                    text = (await c.get(_OPENPHISH)).text
                urls = {l.strip().rstrip("/") for l in text.splitlines() if l.startswith("http")}
                hosts = {u.split("/")[2].lower() for u in urls if u.count("/") >= 2}
                d = data()
                hosts = {h for h in hosts if not d.hosting_suffix(h) and not d.tranco_rank(h)}
                _state.update(urls=urls, hosts=hosts, loaded=time.time())
            except httpx.HTTPError:
                _state["loaded"] = time.time() - 3000  # retry in 10 minutes
    return _state["urls"], _state["hosts"]


async def doh(c: httpx.AsyncClient, endpoint: str, name: str, rtype: str = "A") -> dict:
    r = await c.get(endpoint, params={"name": name, "type": rtype}, headers={"accept": "application/dns-json"})
    return r.json()


async def dns_records(c: httpx.AsyncClient, host: str, registrable: str) -> dict:
    """Unfiltered resolution through Cloudflare DoH (1.1.1.1): A records + NS of the registrable domain."""
    a, ns = await asyncio.gather(doh(c, "https://cloudflare-dns.com/dns-query", host),
                                 doh(c, "https://cloudflare-dns.com/dns-query", registrable, "NS"), return_exceptions=True)
    out = {"a": [], "ns": [], "nxdomain": False, "error": None}
    if isinstance(a, dict):
        out["nxdomain"] = a.get("Status") == 3
        out["a"] = [x["data"] for x in a.get("Answer", []) if x.get("type") == 1][:8]
    else:
        out["error"] = type(a).__name__
    if isinstance(ns, dict):
        out["ns"] = sorted({x["data"].rstrip(".").lower() for x in ns.get("Answer", []) if x.get("type") == 2})[:6]
    return out


async def lookup(url: str, host: str, registrable: str, check_host: bool) -> dict:
    """Return {'hits': [...], 'dns': {...}, 'skipped': [...]}. check_host=False for shared/popular hosts."""
    hits, skipped = [], []
    async with httpx.AsyncClient(timeout=4, verify=config.SSL_CTX) as c:
        tasks = {"dns": dns_records(c, host, registrable)}
        if config.FEEDS_ENABLED:
            tasks["cf_filter"] = doh(c, "https://security.cloudflare-dns.com/dns-query", host)
            tasks["openphish"] = _openphish()
            tasks["bulk"] = load_bulk()
            if config.URLHAUS_AUTH_KEY:
                hdr = {"Auth-Key": config.URLHAUS_AUTH_KEY}
                if check_host:
                    tasks["threatfox"] = c.post("https://threatfox-api.abuse.ch/api/v1/", headers=hdr,
                                                json={"query": "search_ioc", "search_term": host, "exact_match": True})
                tasks["urlhaus_url"] = c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers=hdr)
                if check_host:
                    tasks["urlhaus_host"] = c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host}, headers=hdr)
        results = dict(zip(tasks, await asyncio.gather(*tasks.values(), return_exceptions=True)))
    dns = results["dns"] if isinstance(results["dns"], dict) else {"a": [], "ns": [], "nxdomain": False, "error": "dns failed"}
    if not config.FEEDS_ENABLED:
        skipped.append("threat feeds disabled for this run")
        return {"hits": hits, "dns": dns, "skipped": skipped}
    for name, res in results.items():
        if isinstance(res, Exception):
            skipped.append(f"{name}: {type(res).__name__}")
    op = results.get("openphish")
    if isinstance(op, tuple):
        urls, hosts = op
        if url.rstrip("/") in urls:
            hits.append({"source": "OpenPhish", "match": "exact URL"})
        elif check_host and host in hosts:
            hits.append({"source": "OpenPhish", "match": "host"})
    bulk = results.get("bulk")
    if isinstance(bulk, dict):
        cands = _bulk_candidates(host)
        for name, s in bulk.items():
            m = next((c for c in cands if c in s), None)
            if m:
                hits.append({"source": name, "match": "domain" if m == host else f"parent domain {m}"})
    tf = results.get("threatfox")
    if isinstance(tf, httpx.Response) and tf.status_code == 200:
        j = tf.json()
        if j.get("query_status") == "ok" and isinstance(j.get("data"), list) and j["data"]:
            hits.append({"source": "ThreatFox", "match": f"host ({j['data'][0].get('threat_type', 'malicious')})"})
    for key, label in (("urlhaus_url", "URL"), ("urlhaus_host", "host")):
        r = results.get(key)
        if isinstance(r, httpx.Response) and r.status_code == 200:
            j = r.json()
            if j.get("query_status") == "ok" and (key == "urlhaus_url" or int(j.get("url_count") or 0) > 0):
                hits.append({"source": "URLhaus", "match": label, "ref": j.get("urlhaus_reference")})
    if check_host and dns.get("a"):
        cf = results.get("cf_filter")
        if isinstance(cf, dict) and any(x.get("data") == "0.0.0.0" for x in cf.get("Answer", [])):
            hits.append({"source": "Cloudflare 1.1.1.2", "match": "blocked by malware/phishing filter"})
    return {"hits": hits, "dns": dns, "skipped": skipped}
