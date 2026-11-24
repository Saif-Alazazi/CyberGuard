"""Layer 6 (deep mode): Cloudflare URL Scanner screenshot + page checks.

Checks: credential / OTP / card / Emirates ID fields, Telegram exfiltration, favicon hash vs official brand
icons, phone numbers vs the official helpline registry, brand names in page text, cloaking hints.
"""
import asyncio
import base64
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx
import mmh3
import phonenumbers

from app import config
from app.data import data, normalize_text, split_host
from app.pipeline.netsafe import UnsafeURL, client, safe_get
from app.pipeline.score import reason

CF_BASE = "https://api.cloudflare.com/client/v4/accounts/{acc}/urlscanner/v2"
OTP_RE = re.compile(r"otp|one.?time|verification.?code|sms.?code|passcode|pin\b|رمز.?التحقق|رمز", re.I)
CARD_RE = re.compile(r"card.?num|cc.?num|cardnumber|cvv|cvc|csc|expir|exp.?date|cc-exp|رقم.?البطاقة", re.I)
EID_RE = re.compile(r"emirates.?id|\beid\b|784-|national.?id|الهوية", re.I)
CAPTCHA_RE = re.compile(r"cf-turnstile|g-recaptcha|hcaptcha|challenge-platform", re.I)


class Inspector(HTMLParser):
    """HTML walker adapted from FraudLand fingerprints/html.py: forms, inputs, scripts, icons, title, visible text."""

    def __init__(self) -> None:
        super().__init__()
        self.forms, self.inputs, self.scripts, self.icons, self.text, self.title = [], [], [], [], [], []
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in ("script", "style", "noscript"):
            self._skip += 1
            if tag == "script" and a.get("src"):
                self.scripts.append(a["src"])
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get").lower()})
        elif tag in ("input", "select", "textarea"):
            self.inputs.append({k: a.get(k, "") for k in ("type", "name", "id", "placeholder", "autocomplete", "aria-label")})
        elif tag == "link" and "icon" in a.get("rel", "").lower() and a.get("href"):
            self.icons.append(a["href"])
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data_):
        t = " ".join(data_.split())
        if not t:
            return
        if self._in_title:
            self.title.append(t)
        elif not self._skip:
            self.text.append(t)


def _decode(body: bytes, content_type: str) -> str:
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I) or re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", body[:4000], re.I)
    enc = m.group(1) if m else "utf-8"
    enc = enc.decode() if isinstance(enc, bytes) else enc
    try:
        return body.decode(enc, "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


def _digits(n: str) -> str:
    d = re.sub(r"\D", "", n)
    for p in ("00971", "971"):
        if d.startswith(p):
            d = d[len(p):]
    return d.lstrip("0")


async def cloudflare_scan(url: str) -> dict:
    """Submit to Cloudflare URL Scanner (unlisted), poll for the result, fetch mobile screenshot + DOM."""
    if not (config.CLOUDFLARE_ACCOUNT_ID and config.CLOUDFLARE_API_TOKEN):
        return {"error": "not configured"}
    base = CF_BASE.format(acc=config.CLOUDFLARE_ACCOUNT_ID)
    hdr = {"Authorization": f"Bearer {config.CLOUDFLARE_API_TOKEN}"}
    async with httpx.AsyncClient(timeout=15, headers=hdr) as c:
        r = await c.post(f"{base}/scan", json={"url": url, "visibility": "Unlisted", "screenshotsResolutions": ["mobile"],
                                               "customagent": config.USER_AGENT})
        if r.status_code >= 400:
            return {"error": f"submit HTTP {r.status_code}: {r.text[:120]}"}
        uuid = r.json().get("uuid") or (r.json().get("result") or {}).get("uuid")
        result = None
        for _ in range(20):
            await asyncio.sleep(2.5)
            rr = await c.get(f"{base}/result/{uuid}")
            if rr.status_code == 200:
                result = rr.json()
                break
        if not result:
            return {"error": "scan did not finish in time", "uuid": uuid}
        shot, dom = await asyncio.gather(c.get(f"{base}/screenshots/{uuid}.png", params={"resolution": "mobile"}),
                                         c.get(f"{base}/dom/{uuid}"), return_exceptions=True)
    verdict = ((result.get("verdicts") or {}).get("overall") or {})
    page = result.get("page") or {}
    return {"uuid": uuid, "report_url": f"https://radar.cloudflare.com/scan/{uuid}",
            "screenshot": shot.content if isinstance(shot, httpx.Response) and shot.status_code == 200 else None,
            "dom": dom.text if isinstance(dom, httpx.Response) and dom.status_code == 200 else "",
            "malicious": bool(verdict.get("malicious")), "categories": verdict.get("categories") or [],
            "page_url": page.get("url"), "page_ip": page.get("ip"), "page_asn": page.get("asn"),
            "page_country": page.get("country"), "title": page.get("title")}


async def favicon_hash(page_url: str, icons: list[str]) -> int | None:
    href = urljoin(page_url, icons[0]) if icons else urljoin(page_url, "/favicon.ico")
    async with client() as c:
        try:
            r = await safe_get(c, href, read_body=True, max_bytes=200_000)
        except (UnsafeURL, httpx.HTTPError, OSError):
            return None
    if r.get("status") != 200 or not r.get("body"):
        return None
    return mmh3.hash(base64.encodebytes(r["body"]))


async def inspect(final_url: str, body: bytes, content_type: str, official: str | None, gate: dict,
                  brands_claimed: list[str], intel: dict | None) -> dict:
    d = data()
    skipped: list[str] = []
    cf = await asyncio.gather(cloudflare_scan(final_url), return_exceptions=True)
    cf = cf[0] if not isinstance(cf[0], Exception) else {"error": type(cf[0]).__name__}
    if cf.get("error"):
        skipped.append(f"Cloudflare screenshot: {cf['error']}")
    html = _decode(body, content_type) if body and "html" in (content_type or "html") else ""
    source = "direct fetch (mobile user agent)"
    if len(html) < 300 and cf.get("dom"):
        html, source = cf["dom"], "Cloudflare URL Scanner DOM"
    p = Inspector()
    try:
        p.feed(html[:1_500_000])
    except Exception:
        skipped.append("HTML parse error")
    text = " ".join(p.text)[:20000]
    title = " ".join(p.title)[:300] or (cf.get("title") or "")
    norm = normalize_text(title + " " + text)

    fields = set()
    for i in p.inputs:
        blob = " ".join(i.values())
        if i.get("type", "").lower() == "password":
            fields.add("password")
        if OTP_RE.search(blob):
            fields.add("OTP / verification code")
        if CARD_RE.search(blob) or "cc-" in i.get("autocomplete", ""):
            fields.add("card number / CVV")
        if EID_RE.search(blob):
            fields.add("Emirates ID")
    host = (urlsplit(final_url).hostname or "").lower()
    post_targets = []
    for f in p.forms:
        if f["action"].startswith("http"):
            t = urlsplit(f["action"]).hostname or ""
            if t and split_host(t)[3] != split_host(host)[3]:
                post_targets.append(t)
    tg = re.findall(r"api\.telegram\.org/bot[0-9]{6,}", html)

    page_brand = None
    for name, bid in d.name_patterns:
        if re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", norm):
            page_brand = bid
            break
    if not page_brand:
        for b in brands_claimed:
            page_brand = b
            break

    phones = []
    for m in phonenumbers.PhoneNumberMatcher(text[:8000], "AE"):
        phones.append(phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164))
    official_numbers = {_digits(n) for n in d.helplines}
    unofficial = [n for n in dict.fromkeys(phones) if _digits(n) not in official_numbers]

    fav = await favicon_hash(final_url, p.icons)
    fav_brand = d.favicons.get(str(fav)) if fav is not None else None

    reasons = []
    if not official:
        if fields:
            reasons.append(reason("CRED_FORM", ", ".join(sorted(fields))))
        if tg:
            reasons.append(reason("TG_EXFIL", tg[0][:40] + "..."))
        if fav_brand and fav_brand != official:
            fb = d.brand(fav_brand)
            reasons.append(reason("FAVICON_CLONE", fb["name_en"], detail_ar=fb.get("name_ar", fb["name_en"])))
            page_brand = page_brand or fav_brand
        if page_brand:
            b = d.brand(page_brand)
            if gate["registrable"] not in b.get("domains", []):
                name_ar = b.get("name_ar", b["name_en"])
                reasons.append(reason("PAGE_BRAND", b["name_en"], detail_ar=name_ar))
                if fields:
                    reasons.append(reason("BRAND_MISMATCH_CRP", b["name_en"], detail_ar=name_ar))
                if unofficial:
                    reasons.append(reason("FAKE_HELPLINE", ", ".join(unofficial[:3])))
        if cf.get("malicious"):
            reasons.append(reason("CF_SCANNER_MALICIOUS", ", ".join(cf.get("categories") or []) or "malicious"))
        young = (intel or {}).get("age_days") is not None and intel["age_days"] < 30
        if (len(text) < 80 and not p.inputs or CAPTCHA_RE.search(html)) and (brands_claimed or young):
            reasons.append(reason("CLOAK", "CAPTCHA wall or near-empty page on a brand-keyword or days-old domain"))
    return {"reasons": reasons, "skipped": skipped, "screenshot": cf.get("screenshot"), "source": source,
            "title": title, "text_excerpt": text[:600], "sensitive_fields": sorted(fields), "post_targets": post_targets,
            "telegram_exfil": bool(tg), "favicon_mmh3": fav, "favicon_brand": fav_brand, "phones": list(dict.fromkeys(phones)),
            "unofficial_phones": unofficial, "page_brand": page_brand, "forms": len(p.forms), "inputs": len(p.inputs),
            "cloudflare": {k: v for k, v in cf.items() if k not in ("screenshot", "dom")}}
