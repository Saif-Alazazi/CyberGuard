"""SQLite persistence: scans, screenshots, infrastructure entities (for the scam-network graph), early warnings."""
import json
import sqlite3
import threading
from contextlib import contextmanager

from app.config import DATA_DIR, DB_PATH

_lock = threading.Lock()
# Infrastructure shared by millions of unrelated sites is not evidence of a link.
COMMON_NS = ("cloudflare.com", "awsdns", "azure-dns", "googledomains.com", "google.com", "domaincontrol.com",
             "registrar-servers.com", "nsone.net", "akam.net", "ultradns", "dynect.net", "wixdns.net", "hostinger",
             "dns.com", "name.com", "namecheaphosting", "bluehost", "hostgator", "squarespacedns", "vercel-dns.com",
             "netlify", "shopify")
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, created TEXT, input_url TEXT, final_url TEXT, registrable TEXT,
  score INTEGER, tier TEXT, label TEXT, source TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS screenshots(id TEXT PRIMARY KEY, png BLOB);
CREATE TABLE IF NOT EXISTS entities(scan_id TEXT, registrable TEXT, kind TEXT, value TEXT);
CREATE INDEX IF NOT EXISTS ent_kv ON entities(kind, value);
CREATE TABLE IF NOT EXISTS early_warnings(domain TEXT PRIMARY KEY, source TEXT, first_seen TEXT, detail TEXT,
  score INTEGER, tier TEXT, blocklisted INTEGER, scan_id TEXT);
"""


@contextmanager
def conn():
    with _lock:
        c = sqlite3.connect(DB_PATH)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()


def init() -> None:
    with conn() as c:
        c.executescript(SCHEMA)
        empty = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
    scans = DATA_DIR / "seed_scans.jsonl"
    if empty and scans.exists():  # a fresh (ephemeral) deployment starts with the watchers' last findings
        for line in scans.read_text(encoding="utf-8").splitlines():
            if line.strip():
                save_scan(json.loads(line), None)
    seed = DATA_DIR / "early_warnings_seed.json"
    if seed.exists():
        for w in json.loads(seed.read_text(encoding="utf-8")):
            add_warning(w, replace=False)


def _entities(r: dict) -> list[tuple[str, str]]:
    ents = []
    for h in r.get("hops", []):
        if h.get("ip"):
            ents.append(("ip", h["ip"]))
    for ns in (r.get("dns") or {}).get("ns", []):
        if not any(c in ns for c in COMMON_NS):
            ents.append(("ns", ns))
    page = r.get("page") or {}
    if page.get("favicon_mmh3"):
        ents.append(("favicon", str(page["favicon_mmh3"])))
    for p in page.get("phones", []):
        ents.append(("phone", p))
    for t in page.get("post_targets", []):
        ents.append(("post_target", t))
    if r.get("final_host") and r.get("hops") and len(r["hops"]) > 1:
        ents.append(("redirect_target", r["registrable"]))
    for h in r.get("hops", [])[:-1]:
        ents.append(("redirect_from", h["url"].split("/")[2] if h["url"].count("/") >= 2 else h["url"]))
    ipi = (r.get("intel") or {}).get("ip") or {}
    if ipi.get("cloudflare_proxied") or (r.get("allowlist") or {}).get("hosting"):
        # Cloudflare anycast IPs and shared-hosting platforms (github.io, pages.dev...) serve millions of unrelated sites
        ents[:] = [e for e in ents if e[0] not in ("ip", "ns")]
    return list(dict.fromkeys(ents))


def node_key(r: dict) -> str | None:
    """Graph identity: the full host on shared hosting platforms (tenant sites are independent), else eTLD+1."""
    return r.get("final_host") if (r.get("allowlist") or {}).get("hosting") else r.get("registrable")


def save_scan(r: dict, screenshot: bytes | None) -> None:
    key = node_key(r)
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (r["id"], r["created_utc"], r["input_url"], r.get("final_url"), key, r["score"],
                   r["tier"], r["label"], r.get("source", "user"), json.dumps(r, default=str, ensure_ascii=False)))
        if screenshot:
            c.execute("INSERT OR REPLACE INTO screenshots VALUES(?,?)", (r["id"], screenshot))
        if key and r["tier"] != "official":
            c.executemany("INSERT INTO entities VALUES(?,?,?,?)", [(r["id"], key, k, v) for k, v in _entities(r)])


def get_scan(scan_id: str) -> dict | None:
    with conn() as c:
        row = c.execute("SELECT result FROM scans WHERE id=?", (scan_id,)).fetchone()
    return json.loads(row["result"]) if row else None


def get_screenshot(scan_id: str) -> bytes | None:
    with conn() as c:
        row = c.execute("SELECT png FROM screenshots WHERE id=?", (scan_id,)).fetchone()
    return row["png"] if row else None


def recent(limit: int = 50) -> list[dict]:
    with conn() as c:
        rows = c.execute("SELECT id, created, input_url, registrable, score, tier, label FROM scans "
                         "ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def infra_links(registrable: str, ip: str | None, ns: list[str], page: dict | None, shared_host: bool = False) -> str:
    """Return a description of shared infrastructure with a domain previously scored as fraud."""
    probes = [] if shared_host else [("ns", n) for n in ns if not any(c in n for c in COMMON_NS)]
    if ip and not shared_host:
        probes.append(("ip", ip))
    if page:
        if page.get("favicon_mmh3"):
            probes.append(("favicon", str(page["favicon_mmh3"])))
        probes += [("phone", p) for p in page.get("phones", [])]
        probes += [("post_target", t) for t in page.get("post_targets", [])]
    with conn() as c:
        for kind, value in probes:
            row = c.execute("SELECT e.registrable FROM entities e JOIN scans s ON s.id=e.scan_id WHERE e.kind=? AND e.value=? "
                            "AND e.registrable<>? AND s.label='fraud' LIMIT 1", (kind, value, registrable)).fetchone()
            if row:
                return f"{kind} {value} also used by {row['registrable']}"
    return ""


def graph_rows() -> tuple[list[dict], list[dict]]:
    with conn() as c:
        scans = [dict(r) for r in c.execute(
            "SELECT registrable, MAX(score) score, MAX(label) label, MAX(id) id FROM scans WHERE label='fraud' "
            "AND registrable IS NOT NULL GROUP BY registrable")]
        ents = [dict(r) for r in c.execute("SELECT DISTINCT registrable, kind, value FROM entities")]
    return scans, ents


def add_warning(w: dict, replace: bool = True) -> None:
    with conn() as c:
        c.execute(f"INSERT OR {'REPLACE' if replace else 'IGNORE'} INTO early_warnings VALUES(?,?,?,?,?,?,?,?)",
                  (w["domain"], w["source"], w["first_seen"], w.get("detail", ""), w.get("score"), w.get("tier"),
                   int(bool(w.get("blocklisted"))), w.get("scan_id")))


def warnings(limit: int = 100) -> list[dict]:
    with conn() as c:
        rows = c.execute("SELECT * FROM early_warnings ORDER BY first_seen DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
