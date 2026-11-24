"""Early detection: newly registered domains (WhoisDS daily list) and Certificate Transparency (crt.sh)
filtered for UAE brand look-alikes, before any victim reports them."""
import base64
import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

import httpx

from app.data import data, split_host
from app.pipeline import lexical

MAX_CT_BYTES = 8_000_000
CT_TOKENS = ["dubaipolice", "adpolice", "uaepass", "tamm", "salik", "darb", "mawaqif", "rtafine", "rta-dubai",
             "emiratespost", "emiratesnbd", "adcb", "icp-gov", "parkin", "qmobility", "etisalat", "mashreq"]


def _is_uae_lookalike(domain: str) -> list[dict]:
    d = data()
    reg = split_host(domain)[3]
    if d.official_brand(reg) or d.tranco_rank(reg):
        return []
    return [h for h in lexical.brand_hits(domain.rsplit(".", 1)[0]) if h["scope"] == "uae"]


def _prefilter():
    """Cheap first pass: a domain is fully checked only if it contains the first 4 letters of a UAE brand token
    (keeps typos such as salilk or dubaipoit) or is an internationalised (xn--) name."""
    stems = {t[:4] for t, _, scope in data().tokens if scope == "uae" and len(t) >= 3}
    return lambda dom: "xn--" in dom or any(s in dom for s in stems)


def whoisds(days_back: int = 1, stats: dict | None = None) -> list[dict]:
    """Download yesterday's free WhoisDS NRD list and keep UAE brand look-alikes."""
    day = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%d")
    token = base64.b64encode(f"{day}.zip".encode()).decode()
    r = httpx.get(f"https://www.whoisds.com//whois-database/newly-registered-domains/{token}/nrd", timeout=60,
                  follow_redirects=True)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        names = z.read(z.namelist()[0]).decode("utf-8", "replace").split()
    hits = []
    worth_checking = _prefilter()
    for dom in names:
        dom = dom.strip().lower()
        b = _is_uae_lookalike(dom) if worth_checking(dom) else []
        if b:
            hits.append({"domain": dom, "source": "nrd", "first_seen": f"{day}T00:00:00+00:00",
                         "detail": f"registered {day}; looks like {', '.join(sorted({x['brand'] for x in b}))} "
                                   f"({len(names)} new domains screened)"})
    if stats is not None:
        stats.update(registration_day=day, domains_screened=len(names), lookalikes=len(hits))
    return hits


def crtsh(tokens: list[str] | None = None, max_age_days: int = 30, stats: dict | None = None) -> list[dict]:
    """Search CT logs for recent certificates naming UAE brand tokens outside official domains."""
    since = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    hits: dict[str, dict] = {}
    failures = 0
    with httpx.Client(timeout=40) as c:
        for tok in tokens or CT_TOKENS:
            if failures >= 2:
                break  # crt.sh is down: keep what was found instead of retrying every token
            rows = None
            for attempt in range(3):  # crt.sh often answers 502/503 under load
                try:
                    with c.stream("GET", "https://crt.sh/", params={"q": f"%{tok}%", "output": "json", "exclude": "expired"}) as r:
                        if r.status_code == 200:
                            body = b""
                            for chunk in r.iter_bytes():
                                body += chunk
                                if len(body) > MAX_CT_BYTES:  # keep memory bounded on a 512 MB host
                                    break
                            rows = json.loads(body) if len(body) <= MAX_CT_BYTES else []
                            break
                except (httpx.HTTPError, ValueError):
                    pass
                time.sleep(3 * (attempt + 1))
            failures = failures + 1 if rows is None else 0
            for row in rows or []:
                nb = datetime.fromisoformat(row.get("not_before", "1970-01-01T00:00:00")).replace(tzinfo=timezone.utc)
                if nb < since:
                    continue
                for name in str(row.get("name_value", "")).lower().split("\n"):
                    name = name.lstrip("*.").strip()
                    if not name or name in hits:
                        continue
                    if _is_uae_lookalike(name):
                        hits[name] = {"domain": name, "source": "ct", "first_seen": nb.isoformat(),
                                      "detail": f"TLS certificate issued {nb:%Y-%m-%d} by {row.get('issuer_name', '')[:60]}"}
    if stats is not None:
        stats.update(brand_queries=len(tokens or CT_TOKENS), unavailable=failures >= 2, lookalikes=len(hits))
    return list(hits.values())
