"""Layer 5: domain age, registrar, abuse contacts (RDAP; port-43 WHOIS for .ae) and IP/ASN (IPinfo Lite)."""
import asyncio
import re
from datetime import datetime, timezone

import httpx

from app import config

CLOUDFLARE_ASN = "AS13335"
KIT_ASNS = {"AS132203": "Tencent", "AS45102": "Alibaba"}


def _vcard(entity: dict, field: str) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item[0] == field:
            return item[3] if isinstance(item[3], str) else None
    return None


def _parse_rdap(j: dict) -> dict:
    out = {"created": None, "registrar": None, "abuse_email": None, "nameservers": [], "status": j.get("status", [])}
    for ev in j.get("events", []):
        if ev.get("eventAction") == "registration":
            out["created"] = ev.get("eventDate")
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            out["registrar"] = _vcard(ent, "fn")
            for sub in ent.get("entities", []):
                if "abuse" in sub.get("roles", []):
                    out["abuse_email"] = _vcard(sub, "email")
    out["nameservers"] = [n.get("ldhName", "").lower() for n in j.get("nameservers", [])][:6]
    return out


async def rdap(c: httpx.AsyncClient, registrable: str) -> dict:
    r = await c.get(f"https://rdap.org/domain/{registrable}", follow_redirects=True)
    if r.status_code == 404:
        return {"error": "not found in RDAP"}
    r.raise_for_status()
    return _parse_rdap(r.json())


async def whois_ae(registrable: str) -> dict:
    """.ae has no RDAP; aeDA port-43 WHOIS gives registrar and status (no creation date)."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection("whois.aeda.net.ae", 43), 4)
    writer.write((registrable + "\r\n").encode())
    await writer.drain()
    raw = (await asyncio.wait_for(reader.read(20000), 4)).decode("utf-8", "replace")
    writer.close()
    if "No Data Found" in raw:
        return {"error": "not registered"}
    reg = re.search(r"Registrar Name:\s*(.+)", raw)
    status = re.findall(r"Status:\s*(.+)", raw)
    return {"created": None, "registrar": reg.group(1).strip() if reg else None, "abuse_email": None,
            "nameservers": [n.strip().lower() for n in re.findall(r"Name Server:\s*(\S+)", raw)][:6],
            "status": status, "note": ".ae WHOIS does not publish a creation date"}


async def ipinfo(c: httpx.AsyncClient, ip: str) -> dict:
    r = await c.get(f"https://api.ipinfo.io/lite/{ip}", params={"token": config.IPINFO_TOKEN})
    r.raise_for_status()
    j = r.json()
    return {"ip": ip, "asn": j.get("asn"), "as_name": j.get("as_name"), "as_domain": j.get("as_domain"),
            "country": j.get("country_code")}


def age_days(created: str | None) -> int | None:
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, (datetime.now(timezone.utc) - dt).days)


async def lookup(registrable: str, ip: str | None) -> dict:
    out = {"whois": None, "ip": None, "age_days": None, "skipped": []}
    async with httpx.AsyncClient(timeout=5, verify=config.SSL_CTX) as c:
        tasks = {"whois": whois_ae(registrable) if registrable.endswith(".ae") else rdap(c, registrable)}
        if ip and config.IPINFO_TOKEN:
            tasks["ip"] = ipinfo(c, ip)
        res = dict(zip(tasks, await asyncio.gather(*tasks.values(), return_exceptions=True)))
    for k, v in res.items():
        if isinstance(v, Exception):
            out["skipped"].append(f"{'RDAP/WHOIS' if k == 'whois' else 'IPinfo'}: {type(v).__name__}")
        else:
            out[k] = v
    if out["whois"] and not out["whois"].get("error"):
        out["age_days"] = age_days(out["whois"].get("created"))
    if out["ip"]:
        out["ip"]["cloudflare_proxied"] = out["ip"].get("asn") == CLOUDFLARE_ASN
        out["ip"]["kit_hosting"] = KIT_ASNS.get(out["ip"].get("asn") or "")
    return out
