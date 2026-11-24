"""Layer 4: lexical and lookalike signals on a hostname (English + Arabic, Unicode confusables, punycode)."""
import math
import re
import unicodedata
from collections import Counter
from urllib.parse import unquote, urlsplit

from rapidfuzz.distance import Levenshtein

from app.data import data, normalize_text, split_host

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a"})
_TRICK_LABELS = {"com", "gov", "gov-ae", "govae", "ae-gov"}
_LOGIN_WORDS = ("login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "auth", "wallet",
                "payment", "billing", "unlock", "confirm", "recover", "suspend", "validate", "webscr", "kyc")


def _script(ch: str) -> str:
    name = unicodedata.name(ch, "")
    for s in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "ARMENIAN", "HEBREW", "CJK", "HANGUL", "THAI"):
        if name.startswith(s) or f" {s} " in name:
            return s
    return "OTHER"


def unicode_host(host: str) -> str:
    try:
        return ".".join(l.encode("ascii").decode("idna") if l.startswith("xn--") else l for l in host.split("."))
    except UnicodeError:
        return host


def skeleton(text: str) -> str:
    conf = data().confusables
    return "".join(conf.get(ch, ch) for ch in unicodedata.normalize("NFKC", text.lower()))


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


CODE_HOSTS = {"github.io", "gitlab.io"}
PLATFORM_OWNER = {"blogspot.com": "google", "appspot.com": "google", "web.app": "google", "firebaseapp.com": "google",
                  "sites.google.com": "google", "azurewebsites.net": "microsoft", "sharepoint.com": "microsoft",
                  "amplifyapp.com": "amazon", "cloudfront.net": "amazon", "s3.amazonaws.com": "amazon"}
TENANT_LURES = ("support", "service", "help", "secure", "verify", "wallet", "mail", "claim", "bonus", "reward", "gift",
                "prize", "promo", "billing", "invoice", "refund", "auth", "login", "signin", "account", "update", "connect",
                "recovery", "unlock", "airdrop", "hadiah", "resmi")


def auto_generated(label: str) -> bool:
    """Machine-generated tenant names typical of phishing kits on free hosting (e.g. k1xmn-tu9-izyg-iovhz-27-10-2026-aa)."""
    flat = re.sub(r"[^a-z0-9]", "", label)
    if len(flat) < 8:
        return False
    digits = sum(c.isdigit() for c in re.sub(r"(19|20)\d\d", "", flat))
    chunks = [c for c in re.split(r"[-_.]", label) if c]
    junk = [c for c in chunks if (re.search(r"\d", c) and re.search(r"[a-z]", c)) or (len(c) >= 4 and not re.search(r"[aeiouy]", c))]
    return digits >= 4 or len(junk) >= 2 or (len(flat) >= 16 and _entropy(flat) > 3.9)


def brand_hits(text: str, loose: bool = False) -> list[dict]:
    """Find UAE/global brand tokens (exact, confusable skeleton, leetspeak or 1-2 edit typos) in a host-like string."""
    d = data()
    lure_words = set(d.lures["url_lure_words"]) | {"uae", "ae", "dubai", "abudhabi", "gov", "online", "my", "e"}
    skel = skeleton(text)
    words = [w for w in re.split(r"[^a-z0-9؀-ۿ]+", skel) if w]
    joined = "".join(words)
    leet_words = [w.translate(_LEET) for w in words]
    hits: dict[str, dict] = {}

    def add(bid: str, scope: str, how: str, token: str) -> None:
        if bid not in hits or hits[bid]["how"] != "exact":
            hits[bid] = {"brand": bid, "scope": scope, "how": how, "token": token}

    def affix_ok(rest: str) -> bool:
        return rest in lure_words or rest.isdigit()

    def word_match(tok: str, ws: list[str]) -> bool:
        if (len(tok) >= 8 or (loose and len(tok) >= 5)) and tok in "".join(ws):
            return True
        pairs = ws + [a + b for a, b in zip(ws, ws[1:])]
        for w in pairs:
            if w == tok or (w.startswith(tok) and affix_ok(w[len(tok):])) or (w.endswith(tok) and affix_ok(w[: -len(tok)])):
                return True
        return False

    for tok, bid, scope in d.tokens:
        if word_match(tok, words):
            add(bid, scope, "exact", tok)
        elif word_match(tok, leet_words):
            add(bid, scope, "leetspeak/confusable", tok)
    # typosquats of distinctive tokens (e.g. dubaipoit, emiratsnbd, uaepas)
    for tok, bid, scope in d.tokens:
        if len(tok) < 6 or hits:
            continue
        limit = 2 if len(tok) >= 9 else 1
        for w in leet_words:
            if len(w) < 5 or abs(len(w) - len(tok)) > limit or w[0] != tok[0]:
                continue
            dist = Levenshtein.distance(w, tok)
            if 0 < dist <= limit:
                add(bid, scope, f"typosquat ({w}~{tok})", tok)
                break
    # Arabic brand names inside an IDN label
    for name, bid in d.name_patterns:
        if re.search(r"[؀-ۿ]", name) and name.replace(" ", "") in normalize_text(text).replace(" ", ""):
            add(bid, "uae", "arabic name", name)
    return list(hits.values())


def analyse(url: str, host: str) -> list[dict]:
    """Return signals as {code, detail, brand?} for one hop's URL."""
    d = data()
    sigs: list[dict] = []
    sub, dom, suffix, reg = split_host(host)
    uhost = unicode_host(host)
    tld = suffix.split(".")[-1] if suffix else ""

    raw_netloc = urlsplit(url).netloc
    if "@" in raw_netloc:
        userinfo = unquote(raw_netloc.rsplit("@", 1)[0])
        sigs.append({"code": "USERINFO_TRICK", "detail": f"text before '@' ({userinfo[:60]}) hides the real host {host}"})
        for h in brand_hits(userinfo):
            sigs.append({"code": "BRAND_IN_HOST", "detail": f"{h['brand']} named before '@'", "brand": h["brand"], "scope": h["scope"]})

    if "xn--" in host:
        scripts = {_script(ch) for ch in uhost.replace(".", "").replace("-", "") if not ch.isdigit()}
        sigs.append({"code": "PUNYCODE", "detail": f"internationalised domain shown as {uhost}"})
        if len(scripts - {"OTHER"}) > 1:
            sigs.append({"code": "MIXED_SCRIPT", "detail": f"mixes scripts {sorted(scripts - {'OTHER'})}"})
    if skeleton(uhost) != uhost.lower() and "xn--" in host:
        sigs.append({"code": "CONFUSABLE", "detail": f"look-alike characters: {uhost} reads as {skeleton(uhost)}"})

    hosting = d.hosting_suffix(host)
    scope_text = host[: -len(hosting) - 1] if hosting else (uhost[: -len(suffix) - 1] if suffix else uhost)
    tenant = scope_text.split(".")[-1] if hosting and scope_text else ""
    for h in brand_hits(scope_text, loose=bool(hosting)):
        if d.brand(h["brand"]) and reg in d.brand(h["brand"]).get("domains", []):
            continue
        if hosting in CODE_HOSTS and tenant == h["token"]:
            continue  # e.g. google.github.io is the organisation's own GitHub Pages site
        if PLATFORM_OWNER.get(hosting) == h["brand"] and not any(w in tenant for w in TENANT_LURES):
            continue  # brand's own platform (googleprojectzero.blogspot.com); still flagged with lure words
        code = "FREE_HOST_BRAND" if hosting else "BRAND_IN_HOST"
        sigs.append({"code": code, "detail": f"{h['token']} ({h['how']})" + (f" on {hosting}" if hosting else ""),
                     "brand": h["brand"], "scope": h["scope"], "how": h["how"], "hosting": hosting})

    labels = (sub.split(".") if sub else []) + [dom]
    if any(l in _TRICK_LABELS for l in labels[:-1]) or re.match(r"^(com|gov|ae|gov-ae)-", dom):
        sigs.append({"code": "SUFFIX_TRICK", "detail": f"fake suffix pattern in {host}"})

    if tld in d.abused_tlds:
        short = len(dom) <= 6 or auto_generated(dom)
        sigs.append({"code": "ABUSED_TLD", "detail": f".{tld}" + (f", short/random name '{dom}'" if short else ""),
                     "weight": 20 if short else None})
    if hosting and not any(s["code"] == "FREE_HOST_BRAND" for s in sigs):
        sigs.append({"code": "FREE_HOSTING", "detail": hosting})
    if hosting:
        if auto_generated(tenant):
            sigs.append({"code": "RANDOM_TENANT", "detail": f"{tenant}.{hosting}"})
        lures = [w for w in TENANT_LURES if w in tenant]
        if lures:
            sigs.append({"code": "LURE_IN_HOST", "detail": ", ".join(lures[:3])})
        path = unquote(urlsplit(url).path).lower()
        for h in brand_hits(path):
            if not any(s.get("brand") == h["brand"] for s in sigs):
                sigs.append({"code": "FREE_HOST_BRAND", "detail": f"{h['token']} in page path on {hosting}", "brand": h["brand"],
                             "scope": h["scope"], "how": "brand name in the page path", "hosting": hosting})
                break

    low = unquote(url).lower()
    host_words = [w for w in (TENANT_LURES if tld in d.abused_tlds else _LOGIN_WORDS) if w in host]
    path_words = [w for w in _LOGIN_WORDS if w in urlsplit(low).path + "?" + urlsplit(low).query]
    if host_words:
        sigs.append({"code": "LURE_IN_HOST", "detail": ", ".join(host_words[:3])})
    if path_words:
        sigs.append({"code": "LURE_IN_PATH", "detail": ", ".join(path_words[:3])})
    frag = unquote(unquote(urlsplit(url).fragment)).lower()
    if re.search(r"[\w.+-]+@[\w-]+\.[\w.]+|^-?e-?mail-?$", frag):
        sigs.append({"code": "EMAIL_IN_URL", "detail": "victim e-mail address pre-filled in the link fragment"})
    if dom.count("-") >= 2 or len(sub.split(".")) >= 3:
        sigs.append({"code": "COMPLEX_HOST", "detail": host})
    core = re.sub(r"[^a-z]", "", dom)
    if not hosting and len(dom) >= 8 and (auto_generated(dom) or not re.search(r"[aeiou]", core)):
        sigs.append({"code": "RANDOM_LABEL", "detail": dom})
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        sigs.append({"code": "IP_HOST", "detail": host})
    gen = [g for g in d.generic_tokens if g in host]
    if gen and not any(s["code"] in ("BRAND_IN_HOST", "FREE_HOST_BRAND") for s in sigs) and (host_words or tld in d.abused_tlds or hosting):
        sigs.append({"code": "UAE_KEYWORD", "detail": ", ".join(gen[:3])})
    return sigs
