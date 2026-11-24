"""Layer 5: domain age, registrar, abuse contacts (RDAP; port-43 WHOIS for .ae), IP/ASN (IPinfo Lite) and the
TLS certificate the site presents (issuer, issue date, other domains on the same certificate, SHA-256)."""
import asyncio
import re
from datetime import datetime, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

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


async def tls_cert(host: str, ip: str) -> dict:
    """Read the certificate the server presents (every HTTPS site must show one). Connects only to `ip`, which
    the SSRF guard has already verified as public."""
    _, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443, ssl=config.NO_VERIFY_CTX, server_hostname=host), 5)
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issued = cert.not_valid_before_utc
    return {"issuer": org[0].value if org else None, "issued_utc": issued.isoformat(),
            "expires_utc": cert.not_valid_after_utc.isoformat(), "issued_days_ago": (datetime.now(timezone.utc) - issued).days,
            "san_count": len(sans), "sans": [s.lower() for s in sans[:30]], "self_signed": cert.issuer == cert.subject,
            "sha256": cert.fingerprint(hashes.SHA256()).hex()}


def age_days(created: str | None) -> int | None:
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, (datetime.now(timezone.utc) - dt).days)


async def lookup(registrable: str, ip: str | None, host: str | None = None, want_whois: bool = True) -> dict:
    out = {"whois": None, "ip": None, "tls": None, "age_days": None, "skipped": []}
    labels = {"whois": "RDAP/WHOIS", "ip": "IPinfo", "tls": "TLS certificate"}
    async with httpx.AsyncClient(timeout=5, verify=config.SSL_CTX) as c:
        tasks = {}
        if want_whois:
            tasks["whois"] = whois_ae(registrable) if registrable.endswith(".ae") else rdap(c, registrable)
        if ip and config.IPINFO_TOKEN:
            tasks["ip"] = ipinfo(c, ip)
        if ip and host:
            tasks["tls"] = tls_cert(host, ip)
        res = dict(zip(tasks, await asyncio.gather(*tasks.values(), return_exceptions=True)))
    for k, v in res.items():
        if isinstance(v, Exception):
            out["skipped"].append(f"{labels[k]}: {type(v).__name__}")
        else:
            out[k] = v
    if out["whois"] and not out["whois"].get("error"):
        out["age_days"] = age_days(out["whois"].get("created"))
    if out["ip"]:
        out["ip"]["cloudflare_proxied"] = out["ip"].get("asn") == CLOUDFLARE_ASN
        out["ip"]["kit_hosting"] = KIT_ASNS.get(out["ip"].get("asn") or "")
    return out
