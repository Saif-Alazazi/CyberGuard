"""Orchestrates the funnel: extract -> unroll -> allowlist -> lexical -> feeds + domain intel -> (deep: page + LLM) -> score."""
import asyncio
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app import config, store
from app.data import data
from app.pipeline import allowlist, domain_intel, extract, feeds, lexical, resolve
from app.pipeline.netsafe import UnsafeURL, normalize
from app.pipeline.score import finalize, reason

STRONG_LEXICAL = {"BRAND_IN_HOST", "SUFFIX_TRICK", "USERINFO_TRICK", "FREE_HOST_BRAND", "MIXED_SCRIPT"}


def new_case_id() -> str:
    return "CG-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + secrets.token_hex(3).upper()


async def _timed(coro, seconds: float, label: str, skipped: list):
    try:
        return await asyncio.wait_for(coro, seconds)
    except asyncio.TimeoutError:
        skipped.append(f"{label}: timed out")
    except Exception as exc:  # a failed layer is skipped visibly, never treated as "safe"
        skipped.append(f"{label}: {type(exc).__name__}")
    return None


async def scan_url(url: str, mode: str = "fast", message: dict | None = None, source: str = "user") -> dict:
    t0 = time.monotonic()
    d = data()
    deep = mode == "deep"
    case_id = new_case_id()
    skipped: list[str] = []
    reasons: list[dict] = []
    result = {"id": case_id, "input_url": url, "mode": mode, "source": source,
              "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "version": config.VERSION}
    try:
        normalize(url)
    except UnsafeURL as exc:
        result.update({"error": str(exc), **finalize([], False, False), "skipped": [], "hops": [], "final_url": url})
        result["label"] = "invalid"
        return result

    # Layer 1 - unroll
    chain = await _timed(resolve.unroll(url, deep), 12 if deep else config.FAST_BUDGET, "redirect unroll", skipped)
    if chain is None:
        chain = {"hops": [], "final_url": normalize(url)[0], "error": "timeout", "body": b"", "content_type": ""}
    hops = chain["hops"]
    final_url = chain["final_url"]
    final_host = (urlsplit(final_url).hostname or "").lower()
    if chain["error"] == "ssrf_blocked":
        skipped.append("a redirect pointed to an internal address and was blocked (SSRF guard)")
    if any(h.get("shortener") for h in hops) or d.is_shortener(urlsplit(url).hostname or ""):
        reasons.append(reason("SHORTENER", ", ".join(sorted({urlsplit(h["url"]).hostname for h in hops if h.get("shortener")}))
                              or urlsplit(url).hostname))
    if len(hops) > 4:
        reasons.append(reason("MANY_HOPS", str(len(hops) - 1)))

    # Layer 2 - allowlist on the final URL
    gate = allowlist.check(final_url)
    official = gate["official_brand"]
    if official:
        b = d.brand(official)
        reasons.append(reason("ALLOW_OFFICIAL", f"{b['name_en']} ({gate['registrable']})"))
    if gate["query_phone"]:
        reasons.append(reason("QUERY_PHONE", gate["query_phone"]))
    if gate["tranco_rank"] and not official:
        reasons.append(reason("POPULAR", str(gate["tranco_rank"])))
    if gate["gov_ae_unlisted"]:
        reasons.append(reason("GOV_AE_UNLISTED", gate["registrable"]))
    trusted_final = bool(official or gate["global_brand"] or gate["tranco_rank"])

    # Layer 4 - lexical on every hop host that is not itself trusted
    lex_hits: list[dict] = []
    seen_hosts = set()
    for u in [url] + [h["url"] for h in hops]:
        h = (urlsplit(u if "://" in u else "http://" + u).hostname or "").lower()
        key = (h, "@" in urlsplit(u).netloc)
        if not h or key in seen_hosts:
            continue
        seen_hosts.add(key)
        g = allowlist.check(u)
        if (g["official_brand"] or g["global_brand"] or g["tranco_rank"]) and "@" not in urlsplit(u).netloc:
            continue
        lex_hits += lexical.analyse(u, h)
    brands_claimed = []
    for s in lex_hits:
        if s["code"] in ("BRAND_IN_HOST", "FREE_HOST_BRAND"):
            w = 35 if s.get("scope") == "uae" else 30
            if s["code"] == "FREE_HOST_BRAND":
                w -= 5
            b = d.brand(s["brand"])
            how = ("" if s.get("how", "exact") == "exact" else f" ({s['how']})") + (f" - {s['hosting']}" if s.get("hosting") else "")
            reasons.append(reason(s["code"], b["name_en"] + how, w, b.get("name_ar", b["name_en"]) + how))
            brands_claimed.append(s["brand"])
        else:
            reasons.append(reason(s["code"], s["detail"], s.get("weight")))
    strong_lex = any(s["code"] in STRONG_LEXICAL for s in lex_hits)
    if official and strong_lex:
        reasons.append(reason("CLOAK", "a look-alike link redirects to the real official site (typical scanner evasion)"))

    # Message-level signals
    if message:
        if message["lure_hits"]:
            reasons.append(reason("LURE_TEXT", ", ".join(dict.fromkeys(h["phrase"] for h in message["lure_hits"]))[:120],
                                  10 + min(10, 2 * sum(h["weight"] for h in message["lure_hits"][1:]))))
        uae_claims = [c for c in message["claimed_brands"] if c in d.brands]
        if uae_claims and message["sender_flags"]:
            reasons.append(reason("SENDER_ANOMALY", "; ".join(message["sender_flags"])))
        if uae_claims and not official and not gate["tranco_rank"]:
            reasons.append(reason("TEXT_BRAND_MISMATCH", ", ".join(d.brands[c]["name_en"] for c in uae_claims[:2]),
                                  detail_ar="، ".join(d.brands[c]["name_ar"] for c in uae_claims[:2])))
            brands_claimed += uae_claims

    # Layers 3 + 5 - feeds and domain intel, concurrently
    reg = gate["registrable"]
    first_ip = next((h.get("ip") for h in reversed(hops) if h.get("ip")), None)
    shared = bool(gate["hosting"] or gate["shortener"] or trusted_final)
    want_intel = (deep or not trusted_final) and not gate["hosting"] and not gate["shortener"]
    feed_res, intel = await asyncio.gather(
        _timed(feeds.lookup(final_url, final_host, reg, check_host=not shared), 6, "threat feeds", skipped),
        _timed(domain_intel.lookup(reg, first_ip), 7, "RDAP/WHOIS + IPinfo", skipped) if want_intel else asyncio.sleep(0),
    )
    known_bad = False
    dns = {}
    if feed_res:
        skipped += feed_res["skipped"]
        dns = feed_res["dns"]
        if feed_res["hits"]:
            known_bad = True
            reasons.append(reason("KNOWN_BAD", "; ".join(f"{h['source']} ({h['match']})" for h in feed_res["hits"])))
        if dns.get("nxdomain") and not trusted_final:
            reasons.append(reason("NO_DNS"))
    if intel:
        skipped += intel["skipped"]
        age = intel["age_days"]
        if age is not None and not trusted_final:
            if age < 7:
                reasons.append(reason("NEW_DOMAIN", str(age), 25))
            elif age < 30:
                reasons.append(reason("NEW_DOMAIN", str(age)))
            elif age < 180:
                reasons.append(reason("RECENT_DOMAIN", str(age)))
        ipi = intel.get("ip") or {}
        if ipi.get("kit_hosting") and not trusted_final:
            reasons.append(reason("KIT_HOSTING", f"{ipi['kit_hosting']} {ipi.get('asn')}"))
    elif want_intel and not trusted_final:
        skipped.append("domain age unknown")

    page = None
    llm = None
    if deep and not chain["error"]:
        from app.pipeline import page as page_mod
        page = await _timed(page_mod.inspect(final_url, chain["body"], chain["content_type"], official, gate, brands_claimed, intel),
                            45, "page capture", skipped)
        if page:
            skipped += page.get("skipped", [])
            reasons += page["reasons"]
    elif deep:
        skipped.append(f"page capture: site not reachable ({chain['error']})")

    scored = finalize(reasons, bool(official) and not strong_lex, known_bad and not official)
    if deep and 25 <= scored["score"] <= 74 and page:
        from app.pipeline import llm as llm_mod
        llm = await _timed(llm_mod.brand_check(final_url, page, gate), 25, "AI brand check", skipped)
        if llm and llm.get("reasons"):
            reasons += llm["reasons"]
            scored = finalize(reasons, bool(official) and not strong_lex, known_bad and not official)
    elif deep and not config.GEMINI_API_KEY:
        skipped.append("AI brand check: no API key configured")

    infra = store.infra_links(reg, first_ip, dns.get("ns", []), page)
    if infra and not official:
        reasons.append(reason("INFRA_LINK", infra))
        scored = finalize(reasons, bool(official) and not strong_lex, known_bad and not official)

    result.update(scored)
    impersonated = next((b for b in brands_claimed if d.brand(b)), None)
    if (page or {}).get("page_brand") and not impersonated:
        impersonated = page["page_brand"]
    if llm and llm.get("brand_id") and not impersonated and d.brand(llm["brand_id"]):
        impersonated = llm["brand_id"]
    ib = d.brand(impersonated) if impersonated else None
    result.update({
        "final_url": final_url, "final_host": final_host, "registrable": reg, "hops": hops,
        "chain_error": chain["error"], "allowlist": gate, "dns": dns,
        "intel": {k: v for k, v in (intel or {}).items() if k != "skipped"},
        "feeds": (feed_res or {}).get("hits", []), "page": {k: v for k, v in (page or {}).items() if k not in ("reasons", "skipped", "screenshot")},
        "llm": {k: v for k, v in (llm or {}).items() if k != "reasons"} or None,
        "impersonated": {"id": impersonated, "name_en": ib["name_en"], "name_ar": ib.get("name_ar", ""),
                         "official_domains": ib.get("domains", [])} if ib and result["tier"] != "official" else None,
        "message": message, "skipped": list(dict.fromkeys(skipped)),
        "elapsed_ms": int((time.monotonic() - t0) * 1000),
    })
    store.save_scan(result, (page or {}).get("screenshot"))
    return result


async def scan_input(text: str, mode: str = "fast", sender: str = "") -> dict:
    """Entry point for /api/scan: a single URL or a pasted message with one or more links."""
    single = extract.looks_like_single_url(text)
    urls = [text.strip()] if single else extract.extract_urls(text)
    message = None if single else extract.analyse_message(text, sender)
    if single and sender:
        message = extract.analyse_message("", sender)
    if message:
        d = data()
        message["claimed_names"] = [{"id": c, "en": d.brand(c)["name_en"], "ar": d.brand(c).get("name_ar", d.brand(c)["name_en"])}
                                    for c in message["claimed_brands"] if d.brand(c)]
    results = await asyncio.gather(*(scan_url(u, mode, message) for u in urls[:5]))
    return {"input_type": "url" if single else "message", "urls_found": urls, "message": message, "results": list(results)}
