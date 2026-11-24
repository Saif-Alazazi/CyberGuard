"""Bulk scan a file of URLs (one per line, or a CSV with a 'url' column).

python cli.py urls.txt --mode fast --out results.csv
"""
import argparse
import asyncio
import csv
import sys

from app import store
from app.pipeline.run import scan_url


async def _run(urls: list[str], mode: str, concurrency: int) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)

    async def one(u: str) -> dict:
        async with sem:
            r = await scan_url(u, mode, source="cli")
            print(f"{r['score']:>3} {r['tier']:<13} {u}", file=sys.stderr)
            return r

    return await asyncio.gather(*(one(u) for u in urls))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file")
    ap.add_argument("--mode", choices=["fast", "deep"], default="fast")
    ap.add_argument("--out", default="results.csv")
    ap.add_argument("--concurrency", type=int, default=20)
    args = ap.parse_args()
    with open(args.file, encoding="utf-8-sig") as fh:
        text = fh.read()
    rows = list(csv.DictReader(text.splitlines())) if text.lower().startswith("url") else None
    urls = [r["url"].strip() for r in rows] if rows else [l.strip() for l in text.splitlines()]
    urls = [u for u in urls if u and not u.startswith("#")]
    store.init()
    results = asyncio.run(_run(urls, args.mode, args.concurrency))
    with open(args.out, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label", "score", "tier", "final_url", "impersonated_brand", "reasons_en", "reasons_ar", "case_id"])
        for r in results:
            w.writerow([r["input_url"], r["label"], r["score"], r["tier"], r.get("final_url", ""),
                        (r.get("impersonated") or {}).get("name_en", ""), " | ".join(x["en"] for x in r.get("top_reasons", [])),
                        " | ".join(x["ar"] for x in r.get("top_reasons", [])), r["id"]])
    print(f"wrote {len(results)} rows to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
