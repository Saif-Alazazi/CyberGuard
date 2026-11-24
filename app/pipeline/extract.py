"""Layer 0: pull URLs out of pasted SMS / WhatsApp / email text and score the message itself."""
import re
import unicodedata

import phonenumbers

from app.data import data, normalize_text

_DEFANG = [(re.compile(r"h[xX]{2}p(s?)", re.I), r"http\1"), (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
           (re.compile(r"\[:\]"), ":"), (re.compile(r"[。．｡]"), ".")]
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'،]+|(?<![@\w.-])(?:[\w؀-ۿ-]+\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]+|امارات)(?:/[^\s<>\"'،]*)?",
                  re.I)
_TRAIL = ".,;:!?)]}>'\"،؛"
_INTL_SENDER = re.compile(r"^\+?(63|1|44|62|84|86|234|92|91)\d{6,}$")


def defang(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    for pat, rep in _DEFANG:
        text = pat.sub(rep, text)
    return text


_AR_DIGITS = str.maketrans({c: str(i) for i, c in enumerate("٠١٢٣٤٥٦٧٨٩")})


def _as_url(match: str) -> str | None:
    u = match.rstrip(_TRAIL)
    host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split("@")[-1].split(":")[0]
    if "." not in host or host.replace(".", "").isdigit() and host.count(".") != 3:
        return None
    return u if u.lower().startswith("http") else "http://" + u


def extract_urls(text: str) -> list[str]:
    found = []
    for m in _URL.finditer(defang(text).translate(_AR_DIGITS)):
        u = _as_url(m.group(0))
        if u and u not in found:
            found.append(u)
    return found[:20]


def rewrite_urls(text: str, fn) -> str:
    """Replace every link in the (defanged) text with fn(url), keeping trailing punctuation."""
    def repl(m: re.Match) -> str:
        raw = m.group(0)
        u = _as_url(raw)
        if not u:
            return raw
        core = raw.rstrip(_TRAIL)
        return fn(u) + raw[len(core):]
    return _URL.sub(repl, defang(text).translate(_AR_DIGITS))


def looks_like_single_url(text: str) -> bool:
    t = text.strip()
    return bool(t) and not re.search(r"\s", t) and len(extract_urls(t)) == 1


def analyse_message(text: str, sender: str = "") -> dict:
    """Lure lexicon, brand claims and sender anomaly for a pasted message."""
    d = data()
    norm = normalize_text(text)
    hits = []
    for cat, langs in d.lures["categories"].items():
        for lang in ("en", "ar"):
            for phrase, weight in langs[lang]:
                p = normalize_text(phrase)
                if re.search(r"(?<!\w)" + re.escape(p) + r"(?!\w)", norm):
                    hits.append({"category": cat, "phrase": phrase, "lang": lang, "weight": weight})
    urgency = [u for lang in ("en", "ar") for u in d.lures["urgency"][lang] if normalize_text(u) in norm]
    claimed = []
    for name, bid in d.name_patterns:
        if re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", norm) and bid not in claimed:
            claimed.append(bid)
    for tok, bid, scope in d.tokens:
        if scope == "uae" and len(tok) >= 3 and re.search(r"(?<![a-z])" + re.escape(tok) + r"(?![a-z])", norm) and bid not in claimed:
            claimed.append(bid)
    phones = []
    for m in phonenumbers.PhoneNumberMatcher(text, "AE"):
        phones.append(phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164))
    sender_flags = []
    s = re.sub(r"[\s()-]", "", sender or "")
    if s:
        if "@" in s:
            sender_flags.append("email sender")
        elif _INTL_SENDER.match(s) and not s.startswith("+971") and not s.startswith("971"):
            sender_flags.append(f"international number {sender}")
        elif re.fullmatch(r"\+?\d{9,}", s) and not re.match(r"^\+?971", s):
            sender_flags.append(f"non-UAE number {sender}")
    return {"lure_hits": hits, "urgency": urgency, "claimed_brands": claimed, "phones": phones,
            "sender": sender, "sender_flags": sender_flags}
