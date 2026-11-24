"""Search-engine, ads and Google Maps probe (SerpApi): fake UAE government / bank pages and fake helplines.

The free SerpApi plan allows 250 searches a month, so one run uses a fixed pack of 12 bilingual queries.
"""
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
import phonenumbers

from app import config
from app.data import data, normalize_text, split_host

WEB_QUERIES = [("pay RTA traffic fine dubai", "en"), ("dubai police fine payment online", "en"),
               ("salik recharge online", "en"), ("darb toll payment abu dhabi", "en"),
               ("consumer protection uae complaint", "en"), ("سداد مخالفات شرطة دبي", "ar"),
               ("حماية المستهلك الإمارات تقديم شكوى", "ar"), ("تحديث بيانات الهوية الإماراتية", "ar"),
               ("emirates post customer care number", "en")]
MAPS_QUERIES = [("Emirates Post customer service", "en"), ("RTA customer happiness centre", "en"),
                ("ADCB customer service centre abu dhabi", "en")]


def _brands_in(text: str) -> list[str]:
    norm = normalize_text(text)
    return list(dict.fromkeys(bid for name, bid in data().name_patterns if name in norm))


def _phones(text: str) -> list[str]:
    return [phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164)
            for m in phonenumbers.PhoneNumberMatcher(text, "AE")]


def _official_phone(e164: str) -> bool:
    digits = re.sub(r"\D", "", e164)
    digits = digits[3:] if digits.startswith("971") else digits
    return any(digits.lstrip("0") == n.lstrip("0") for n in data().helplines)


def _check(title: str, snippet: str, link: str, phone: str, source: str, query: str, now: str) -> dict | None:
    d = data()
    host = (urlsplit(link).hostname or "").lower() if link else ""
    reg = split_host(host)[3] if host else ""
    claims = _brands_in(f"{title} {snippet}")
    if not claims:
        return None
    off_domain = reg and not d.official_brand(reg) and not d.tranco_rank(reg)
    phones = list(dict.fromkeys(p for p in ([phone] if phone else []) + _phones(snippet) if p))
    # a listing that links to the brand's official site is treated as genuine (branch numbers vary)
    bad_phones = [] if (reg and d.official_brand(reg)) else [p for p in phones if not _official_phone(p)]
    if not off_domain and not bad_phones:
        return None
    names = ", ".join(d.brands[c]["name_en"] for c in claims[:2])
    detail = f"'{title[:80]}' claims {names}"
    if off_domain:
        detail += f" on non-official domain {reg}"
    if bad_phones:
        detail += f"; phone {', '.join(bad_phones[:2])} is not in the official helpline registry (analyst review)"
    return {"domain": reg or f"phone:{bad_phones[0]}", "source": source, "first_seen": now, "url": link,
            "detail": f"{detail} (query: {query})", "phones": bad_phones}


def probe() -> list[dict]:
    if not config.SERPAPI_KEY:
        return []
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    hits: list[dict] = []
    with httpx.Client(timeout=40) as c:
        for q, hl in WEB_QUERIES:
            j = c.get("https://serpapi.com/search.json", params={"engine": "google", "q": q, "gl": "ae", "hl": hl,
                                                                   "google_domain": "google.ae", "api_key": config.SERPAPI_KEY}).json()
            for kind, items in (("search_ad", j.get("ads", [])), ("search", j.get("organic_results", [])[:10])):
                for it in items:
                    h = _check(it.get("title", ""), it.get("snippet", "") or it.get("description", ""), it.get("link", ""),
                               it.get("phone", ""), kind, q, now)
                    if h:
                        hits.append(h)
        for q, hl in MAPS_QUERIES:
            j = c.get("https://serpapi.com/search.json", params={"engine": "google_maps", "q": q, "hl": hl,
                                                                   "ll": "@24.4539,54.3773,10z", "type": "search",
                                                                   "api_key": config.SERPAPI_KEY}).json()
            for it in j.get("local_results", [])[:15]:
                h = _check(it.get("title", ""), f"{it.get('type', '')} {it.get('address', '')}", it.get("website", ""),
                           it.get("phone", ""), "maps", q, now)
                if h:
                    hits.append(h)
    return hits
