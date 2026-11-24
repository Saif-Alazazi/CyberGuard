"""Build data/favicon_hashes.json: mmh3 hashes of the official favicons of UAE brands.

A page that serves one of these icons from a non-official domain triggers FAVICON_CLONE.
Run: python -m scripts.build_favicon_hashes   (needs internet)
"""
import asyncio
import json
import re
from urllib.parse import urljoin

import httpx

from app.config import DATA_DIR
from app.data import data
from app.pipeline.netsafe import client, safe_get
from app.pipeline.page import favicon_hash

ICON = re.compile(rb"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)
HREF = re.compile(rb"href=[\"']([^\"']+)", re.I)


async def brand_icon(domain: str) -> tuple[str, int | None]:
    url = f"https://www.{domain}/" if domain.count(".") == 1 else f"https://{domain}/"
    icons: list[str] = []
    try:
        async with client() as c:
            for _ in range(4):  # follow a few redirects to reach the real homepage
                r = await safe_get(c, url, read_body=True, max_bytes=400_000)
                loc = r.get("headers", {}).get("location")
                if r.get("status") in (301, 302, 303, 307, 308) and loc:
                    url = urljoin(url, loc)
                    continue
                break
        for tag in ICON.findall(r.get("body") or b""):
            m = HREF.search(tag)
            if m:
                icons.append(m.group(1).decode("utf-8", "replace"))
    except (httpx.HTTPError, OSError, ValueError):
        pass
    return url, await favicon_hash(url, icons)


async def main() -> None:
    hashes: dict[str, str] = {}
    brands = list(data().brands.values())
    results = await asyncio.gather(*(brand_icon(b["domains"][0]) for b in brands))
    for b, (url, h) in zip(brands, results):
        print(f"{b['id']:16} {url:45} {h}")
        if h is not None:
            hashes[str(h)] = b["id"]
    (DATA_DIR / "favicon_hashes.json").write_text(json.dumps(
        {"_about": "mmh3 (Shodan-style, base64 body) hashes of official UAE brand favicons, collected by "
                   "scripts/build_favicon_hashes.py", "hashes": hashes}, indent=1), encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(main())
