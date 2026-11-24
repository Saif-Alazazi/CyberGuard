"""Run the watchers, auto-scan every hit in fast mode and record it as an early warning.

python -m watchers.run_all [--serp] [--export]
--serp    also run the SerpApi search/ads/Maps probe (uses ~12 of the 250 free monthly searches)
--export  write data/early_warnings_seed.json + data/seed_scans.jsonl so a fresh deployment starts with them
"""
import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone

from app import store
from app.config import DATA_DIR
from app.pipeline.run import scan_url
from watchers import nrd_ct, serp

log = logging.getLogger("watchers")
SWEEP_STATUS: dict = {"last_run_utc": None, "early_warnings": None, "error": None}


async def _scan_hits(hits: list[dict], limit: int = 40) -> list[dict]:
    sem = asyncio.Semaphore(8)
    seen = set()

    async def one(h):
        async with sem:
            target = h.get("url") or f"http://{h['domain']}/"
            if h["domain"].startswith("phone:"):
                return {**h, "score": None, "tier": "review", "blocklisted": False, "scan_id": None}
            r = await scan_url(target, "fast", source=h["source"])
            return {**h, "score": r["score"], "tier": r["tier"], "blocklisted": bool(r.get("feeds")), "scan_id": r["id"]}

    todo = []
    for h in hits:
        if h["domain"] not in seen:
            seen.add(h["domain"])
            todo.append(h)
    return await asyncio.gather(*(one(h) for h in todo[:limit]))


async def run_watchers_async(with_serp: bool = False) -> list[dict]:
    hits: list[dict] = []
    sources = [("nrd", nrd_ct.whoisds), ("ct", nrd_ct.crtsh)] + ([("search_maps", serp.probe)] if with_serp else [])
    serp_stats: dict = {}
    for name, fn in sources:
        stats: dict = serp_stats if name == "search_maps" else {}
        try:
            found = await asyncio.to_thread(fn, stats=stats)  # blocking HTTP clients run off the event loop
            hits += found
        except Exception as exc:  # one watcher failing must not stop the others
            stats["error"] = type(exc).__name__
            log.warning("%s failed: %s", name, exc)
        store.set_coverage(name, stats)
    scanned = await _scan_hits(hits)
    # Search results that merely mention a brand (blogs, guides) are kept only if the scan or phone check flags them.
    scanned = [w for w in scanned if w["source"] in ("nrd", "ct") or w.get("phones") or (w["score"] or 0) >= 25]
    if with_serp:
        serp_stats["suspicious"] = sum(1 for w in scanned if w["source"] not in ("nrd", "ct"))
        store.set_coverage("search_maps", serp_stats)
    for w in scanned:
        store.add_warning(w)
    return scanned


def run_watchers(with_serp: bool = False) -> list[dict]:
    return asyncio.run(run_watchers_async(with_serp))


async def watch_forever(first_delay: float = 90, every_hours: float = 24) -> None:
    """Server background loop: new-domain + certificate sweep shortly after start-up, then once a day.
    SerpApi is left out (250 searches a month); it runs on demand via /api/watchers/run?serp=true."""
    await asyncio.sleep(first_delay)
    while True:
        try:
            found = await run_watchers_async(with_serp=False)
            SWEEP_STATUS.update(early_warnings=len(found), error=None)
        except Exception as exc:
            SWEEP_STATUS.update(error=type(exc).__name__)
        SWEEP_STATUS["last_run_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        await asyncio.sleep(every_hours * 3600)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serp", action="store_true")
    ap.add_argument("--export", action="store_true")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # request URLs would otherwise print the SerpApi key
    store.init()
    scanned = run_watchers(args.serp)
    for w in scanned:
        print(f"{w['source']:10} {str(w['score']):>4} {w['tier']:12} {'BLOCKLISTED' if w['blocklisted'] else 'not listed':12} "
              f"{w['domain']:40} {w['detail'][:90]}")
    if args.export:
        (DATA_DIR / "early_warnings_seed.json").write_text(
            json.dumps([{k: w.get(k) for k in ("domain", "source", "first_seen", "detail", "score", "tier", "blocklisted", "scan_id")}
                        for w in scanned], ensure_ascii=False, indent=1), encoding="utf-8")
        (DATA_DIR / "coverage_seed.json").write_text(json.dumps(store.coverage(), indent=1), encoding="utf-8")
        # merge into the seed (it also holds campaign scans for the graph); newest scan per registrable domain wins
        seed_path = DATA_DIR / "seed_scans.jsonl"
        seeds = {}
        if seed_path.exists():
            for line in seed_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    s = json.loads(line)
                    seeds[s.get("registrable") or s["id"]] = s
        for w in scanned:
            if w.get("scan_id"):
                s = store.get_scan(w["scan_id"])
                seeds[s.get("registrable") or s["id"]] = s
        seed_path.write_text("".join(json.dumps(s, ensure_ascii=False, default=str) + "\n" for s in seeds.values()),
                             encoding="utf-8")


if __name__ == "__main__":
    main()
