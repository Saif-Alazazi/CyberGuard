"""SSRF guard for every outbound fetch of a user-supplied URL.

Adapted from the FraudLand prototype (domain/urls.py normalize + IP-pinned fetch): only http/https on
ports 80/443, no local hostnames, every resolved address must be public, and the peer address of the
actual TCP connection is re-checked before any body byte is read (defeats DNS rebinding).
"""
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.config import HOP_TIMEOUT, MAX_BODY, USER_AGENT


class UnsafeURL(ValueError):
    pass


def normalize(raw: str) -> tuple[str, str]:
    """Return (normalised URL without userinfo, ascii host). Raises UnsafeURL."""
    raw = raw.strip()
    if len(raw) > 4096 or any(ord(c) < 32 for c in raw):
        raise UnsafeURL("invalid URL")
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise UnsafeURL("unsupported URL scheme")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeURL("bad port") from exc
    if port not in (None, 80, 443):
        raise UnsafeURL("port not allowed")
    try:
        host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        host = parts.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".local", ".internal", ".localhost", ".lan", ".home.arpa")):
        raise UnsafeURL("local hostname")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        if not ip.is_global:
            raise UnsafeURL("non-public IP address")
    netloc = host + (f":{port}" if port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")), host


async def resolve_public(host: str) -> list[str]:
    """Resolve host; raise UnsafeURL if any address is not public. Returns [] on NXDOMAIN."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM), 4)
    except (socket.gaierror, asyncio.TimeoutError, UnicodeError):
        return []
    ips = list(dict.fromkeys(i[4][0] for i in infos))
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            raise UnsafeURL(f"{host} resolves to non-public address")
    return ips


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=HOP_TIMEOUT, follow_redirects=False, verify=False, trust_env=False,
                             headers={"User-Agent": USER_AGENT, "Accept-Language": "ar-AE,ar;q=0.9,en;q=0.8",
                                      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})


def _peer_ip(resp: httpx.Response) -> str | None:
    stream = resp.extensions.get("network_stream")
    try:
        addr = stream.get_extra_info("server_addr") if stream else None
    except Exception:
        addr = None
    return addr[0] if addr else None


async def safe_get(c: httpx.AsyncClient, url: str, read_body: bool, max_bytes: int = MAX_BODY) -> dict:
    """One hop, no redirects followed. Returns status, headers, peer ip and (optionally) the body."""
    url, host = normalize(url)
    ips = await resolve_public(host)
    if not ips:
        return {"url": url, "error": "NXDOMAIN"}
    async with c.stream("GET", url) as resp:
        peer = _peer_ip(resp)
        if peer and not ipaddress.ip_address(peer).is_global:
            raise UnsafeURL("connection to non-public address blocked")
        body = b""
        if read_body and resp.status_code < 300:
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    body = body[:max_bytes]
                    break
        return {"url": url, "status": resp.status_code, "headers": dict(resp.headers), "ip": peer or ips[0],
                "body": body, "content_type": resp.headers.get("content-type", "")}
