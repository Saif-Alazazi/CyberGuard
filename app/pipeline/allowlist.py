"""Layer 2: verified-allowlist gate on the registrable domain (eTLD+1, Public Suffix List) of the FINAL URL."""
import re
from urllib.parse import unquote, urlsplit

from app.data import data, split_host

_PHONE_IN_QUERY = re.compile(r"(?:\+|00)?971[\s-]?\d{7,9}|\b0?5\d[\s-]?\d{3}[\s-]?\d{4}\b|\b(?:800|600)\d{4,7}\b")


def check(final_url: str) -> dict:
    d = data()
    host = (urlsplit(final_url).hostname or "").lower()
    _, _, suffix, reg = split_host(host)
    hosting = d.hosting_suffix(host)
    out = {"host": host, "registrable": reg, "suffix": suffix, "official_brand": None, "global_brand": None,
           "tranco_rank": None, "hosting": hosting, "shortener": d.is_shortener(host), "gov_ae_unlisted": False,
           "query_phone": None}
    if hosting or out["shortener"]:
        return out  # never allowlist shared hosting or shorteners, even if they are popular
    out["official_brand"] = d.official_brand(reg)
    out["global_brand"] = d.global_official(reg)
    out["tranco_rank"] = d.tranco_rank(reg)
    if suffix in ("gov.ae", "mil.ae") and not out["official_brand"]:
        out["gov_ae_unlisted"] = True
    query = unquote(urlsplit(final_url).query)
    m = _PHONE_IN_QUERY.search(query)
    if m and (out["official_brand"] or out["tranco_rank"]):
        out["query_phone"] = m.group(0)
    return out
