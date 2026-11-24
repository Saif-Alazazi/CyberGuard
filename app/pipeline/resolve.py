"""Layer 1: unroll redirects hop by hop (3xx, meta refresh, trivial JS location) with SSRF checks on every hop."""
import re
import time
from urllib.parse import urljoin, urlsplit

import httpx

from app.config import MAX_HOPS
from app.data import data
from app.pipeline.netsafe import UnsafeURL, client, normalize, safe_get

_META = re.compile(rb"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]*content=[\"']?\s*\d+\s*;\s*url=([^\"'>\s]+)", re.I)
_JS = re.compile(rb"(?:window\.|document\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*[\"']([^\"']+)[\"']", re.I)


async def unroll(url: str, deep: bool) -> dict:
    """Follow the chain. In fast mode only HTTP redirects are followed (bodies are read only for
    shortener hops); deep mode also reads the final body for meta/JS redirects."""
    d = data()
    hops: list[dict] = []
    current = url
    final_body = b""
    final_ct = ""
    error = None
    async with client() as c:
        for _ in range(MAX_HOPS + 1):
            host = urlsplit(current).hostname or ""
            is_short = d.is_shortener(host)
            t0 = time.monotonic()
            try:
                r = await safe_get(c, current, read_body=deep or is_short, max_bytes=300_000 if not deep else 1_000_000)
            except UnsafeURL as exc:
                hops.append({"url": current, "status": None, "error": f"blocked: {exc}", "shortener": is_short})
                error = "ssrf_blocked"
                break
            except (httpx.HTTPError, OSError) as exc:
                hops.append({"url": current, "status": None, "error": type(exc).__name__, "shortener": is_short,
                             "ms": int((time.monotonic() - t0) * 1000)})
                error = "unreachable"
                break
            ms = int((time.monotonic() - t0) * 1000)
            if r.get("error") == "NXDOMAIN":
                hops.append({"url": r["url"], "status": None, "error": "NXDOMAIN", "shortener": is_short, "ms": ms})
                error = "nxdomain"
                break
            hop = {"url": r["url"], "status": r["status"], "ip": r["ip"], "shortener": is_short, "ms": ms}
            hops.append(hop)
            nxt = None
            if 300 <= r["status"] < 400 and r["headers"].get("location"):
                nxt = urljoin(r["url"], r["headers"]["location"])
            elif r["body"] and "html" in r["content_type"] and len(r["body"]) < 300_000:
                m = _META.search(r["body"][:20000]) or (_JS.search(r["body"][:6000]) if len(r["body"]) < 6000 else None)
                if m:
                    nxt = urljoin(r["url"], m.group(1).decode("utf-8", "replace"))
                    hop["via"] = "meta/js"
            if not nxt:
                final_body, final_ct = r["body"], r["content_type"]
                break
            try:
                normalize(nxt)
            except UnsafeURL as exc:
                hops.append({"url": nxt, "status": None, "error": f"blocked: {exc}", "shortener": False})
                error = "ssrf_blocked"
                break
            if any(h["url"] == nxt for h in hops):
                error = "redirect_loop"
                break
            current = nxt
        else:
            error = "too_many_hops"
    final = hops[-1]["url"] if hops else url
    return {"hops": hops, "final_url": final, "error": error, "body": final_body, "content_type": final_ct}
