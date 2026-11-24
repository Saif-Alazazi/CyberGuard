"""Run the watchers, auto-scan every hit in fast mode and record it as an early warning.

python -m watchers.run_all [--serp] [--export]
--serp    also run the SerpApi search/ads/Maps probe (uses ~12 of the 250 free monthly searches)
--export  write data/early_warnings_seed.json + data/seed_scans.jsonl so a fresh deployment starts with them
"""
import argparse
import asyncio
import json
import logging

from app import store
from app.config import DATA_DIR
from app.pipeline.run import scan_url
from watchers import nrd_ct, serp

log = logging.getLogger("watchers")


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


def run_watchers(with_serp: bool = False) -> list[dict]:
    hits: list[dict] = []
    for name, fn in (("WhoisDS", nrd_ct.whoisds), ("crt.sh", nrd_ct.crtsh)):
        try:
            found = fn()
            log.info("%s: %d hits", name, len(found))
            hits += found
        except Exception as exc:  # one watcher failing must not stop the others
            log.warning("%s failed: %s", name, exc)
    if with_serp:
        try:
            hits += serp.probe()
        except Exception as exc:
            log.warning("SerpApi failed: %s", exc)
    scanned = asyncio.run(_scan_hits(hits))
    for w in scanned:
        store.add_warning(w)
    return scanned


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serp", action="store_true")
    ap.add_argument("--export", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    store.init()
    scanned = run_watchers(args.serp)
    for w in scanned:
        print(f"{w['source']:10} {str(w['score']):>4} {w['tier']:12} {'BLOCKLISTED' if w['blocklisted'] else 'not listed':12} "
              f"{w['domain']:40} {w['detail'][:90]}")
    if args.export:
        (DATA_DIR / "early_warnings_seed.json").write_text(
            json.dumps([{k: w.get(k) for k in ("domain", "source", "first_seen", "detail", "score", "tier", "blocklisted", "scan_id")}
                        for w in scanned], ensure_ascii=False, indent=1), encoding="utf-8")
        with (DATA_DIR / "seed_scans.jsonl").open("w", encoding="utf-8") as fh:
            for w in scanned:
                if w.get("scan_id"):
                    fh.write(json.dumps(store.get_scan(w["scan_id"]), ensure_ascii=False, default=str) + "\n")


if __name__ == "__main__":
    main()
