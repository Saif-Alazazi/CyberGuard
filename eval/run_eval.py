"""Evaluate CyberGuard fast mode on eval/validation.csv.

python eval/run_eval.py [--no-feeds] [--limit N] [--threshold T]

Headline = fraud slices {openphish, smishing_ioc} vs legit slices {uae_official, uae_business, tranco}.
uae_synthetic (team-written patterns) is reported on its own and never mixed into headline numbers.
Run once with feeds and once with --no-feeds: OpenPhish URLs also appear in the OpenPhish feed, so the
no-feeds run is the honest measure of what the detection layers catch on their own.
"""
import argparse
import asyncio
import csv
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["CYBERGUARD_DB"] = str(ROOT / "eval" / "cache" / "eval.db")

HEADLINE_FRAUD = {"openphish", "smishing_ioc"}
HEADLINE_LEGIT = {"uae_official", "uae_business", "tranco", "legit_hosting"}


def metrics(rows: list[dict], threshold: int) -> dict:
    tp = sum(1 for r in rows if r["label"] == "fraud" and r["score"] >= threshold and r["tier"] != "official")
    fn = sum(1 for r in rows if r["label"] == "fraud") - tp
    fp = sum(1 for r in rows if r["label"] == "legit" and r["score"] >= threshold and r["tier"] != "official")
    tn = sum(1 for r in rows if r["label"] == "legit") - fp
    p = tp / (tp + fp) if tp + fp else 0.0
    rcl = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rcl / (p + rcl) if p + rcl else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": rcl, "f1": f1, "fpr": fpr}


async def run(rows: list[dict], concurrency: int) -> list[dict]:
    from app import store
    from app.pipeline.run import scan_url
    store.init()
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def one(r):
        nonlocal done
        async with sem:
            try:
                res = await scan_url(r["url"], "fast", source="eval")
                out = {**r, "score": res["score"], "tier": res["tier"],
                       "codes": " ".join(f"{x['code']}:{x['weight']}" for x in res["reasons"]),
                       "skipped": "; ".join(res.get("skipped", []))[:200], "ms": res.get("elapsed_ms", 0)}
            except Exception as exc:  # recorded, counted as not detected
                out = {**r, "score": 0, "tier": "error", "codes": "", "skipped": repr(exc)[:200], "ms": 0}
            done += 1
            if done % 100 == 0:
                print(f"  {done}/{len(rows)}", file=sys.stderr)
            return out

    return await asyncio.gather(*(one(r) for r in rows))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-feeds", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="sample N fraud URLs from openphish (0 = all)")
    ap.add_argument("--holdout", action="store_true", help="use the OpenPhish URLs NOT in the --limit sample (never used for tuning)")
    ap.add_argument("--threshold", type=int, default=None)
    ap.add_argument("--concurrency", type=int, default=30)
    args = ap.parse_args()
    if args.no_feeds:
        os.environ["CYBERGUARD_DISABLE_FEEDS"] = "1"
    from app import config
    rows = list(csv.DictReader((ROOT / "eval" / "validation.csv").open(encoding="utf-8")))
    if args.limit:
        random.seed(7)
        op = [r for r in rows if r["slice"] == "openphish"]
        keep = set(id(r) for r in random.sample(op, min(args.limit, len(op))))
        if args.holdout:
            rows = [r for r in rows if r["slice"] == "openphish" and id(r) not in keep]
        else:
            rows = [r for r in rows if r["slice"] != "openphish" or id(r) in keep]
    t0 = time.time()
    results = asyncio.run(run(rows, args.concurrency))
    tag = ("nofeeds" if args.no_feeds else "feeds") + ("_holdout" if args.holdout else "")
    out = ROOT / "eval" / "cache" / f"scores_{tag}.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    head = [r for r in results if r["slice"] in HEADLINE_FRAUD | HEADLINE_LEGIT]
    uae_legit = [r for r in results if r["slice"] in ("uae_official", "uae_business")]
    chosen = args.threshold or config.THRESHOLD
    legit = [r for r in head if r["label"] == "legit"]
    # Calibration aid: lowest threshold keeping FPR <= 1% on UAE legit links and on all legit links
    calibrated = next((t for t in range(5, 100, 5) if metrics(uae_legit, t)["fpr"] <= 0.01 and metrics(legit, t)["fpr"] <= 0.01), None)
    title = "threat feeds OFF" if args.no_feeds else "threat feeds ON"
    if args.holdout:
        title += ", HELD-OUT OpenPhish URLs never used for tuning"
    print(f"\n## CyberGuard fast-mode evaluation ({title})")
    print(f"validation set: {len(results)} URLs, run time {time.time() - t0:.0f}s, threshold {chosen}; "
          f"lowest threshold with FPR <= 1% on this set: {calibrated}\n")
    print("| Set | N | Precision | Recall | F1 | FPR | TP | FP | FN | TN |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    groups = [("Headline (OpenPhish + smishing IOCs vs all legit)", head),
              ("UAE legit only (official + UAE business)", uae_legit)]
    for s in ["openphish", "smishing_ioc", "uae_synthetic", "uae_official", "uae_business", "tranco", "legit_hosting"]:
        groups.append((f"slice: {s}", [r for r in results if r["slice"] == s]))
    for name, rs in groups:
        if not rs:
            continue
        m = metrics(rs, chosen)
        print(f"| {name} | {m['n']} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3%} | "
              f"{m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |")
    print("\nThreshold sweep (headline):")
    print("| Threshold | Precision | Recall | F1 | FPR all legit | FPR UAE legit |")
    print("|---|---|---|---|---|---|")
    for t in range(20, 80, 5):
        m = metrics(head, t)
        print(f"| {t} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.2%} | {metrics(uae_legit, t)['fpr']:.2%} |")
    ms = sorted(r["ms"] for r in results if r["ms"])
    if ms:
        print(f"\nlatency per URL: median {ms[len(ms) // 2]} ms, p95 {ms[int(len(ms) * 0.95)]} ms")
    fps = [r for r in head if r["label"] == "legit" and r["score"] >= chosen and r["tier"] != "official"]
    if fps:
        print("\nFalse positives:")
        for r in fps[:20]:
            print(f"- {r['score']} {r['url'][:90]} {r['codes']}")


if __name__ == "__main__":
    main()
