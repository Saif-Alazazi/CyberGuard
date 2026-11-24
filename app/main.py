"""CyberGuard API + web UI."""
import asyncio
import csv
import hmac
import io
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import config, evidence, graph, safelinks, store
from app.pipeline.run import scan_input, scan_url

STATIC = config.ROOT / "app" / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    store.init()
    watcher = None
    if config.WATCHERS_ENABLED:
        from watchers.run_all import watch_forever
        watcher = asyncio.create_task(watch_forever())
    yield
    if watcher:
        watcher.cancel()


app = FastAPI(title="CyberGuard", version=config.VERSION, lifespan=lifespan,
              description="UAE scam-link detection: score, bilingual reasons, police evidence pack.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

# In-process rate limit and security headers (adapted from the FraudLand prototype API).
_rate_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)
LIMIT_PER_MIN = 40


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.url.path.startswith(("/api/scan", "/api/batch", "/api/protect", "/go")):
        ident = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0]
        now = time.monotonic()
        with _rate_lock:
            q = _hits[ident]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= LIMIT_PER_MIN:
                return JSONResponse({"detail": "Rate limit exceeded, try again in a minute."}, status_code=429,
                                    headers={"Retry-After": "60"})
            q.append(now)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
        "https://cdnjs.cloudflare.com; font-src https://fonts.gstatic.com; script-src 'self' https://cdnjs.cloudflare.com; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
    return resp


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    """Only enforced when CYBERGUARD_API_KEY is set (protects batch and watcher triggers on a public deployment)."""
    if config.API_KEY and not (x_api_key and hmac.compare_digest(config.API_KEY, x_api_key)):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


class ScanRequest(BaseModel):
    input: str = Field(min_length=3, max_length=5000, description="A URL, or a pasted SMS / WhatsApp / email text")
    mode: str = Field(default="fast", pattern="^(fast|deep)$")
    sender: str = Field(default="", max_length=120, description="Optional sender number / ID / email")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    from watchers.run_all import SWEEP_STATUS
    return {"status": "ok", "version": config.VERSION, "feeds_enabled": config.FEEDS_ENABLED, "watcher_sweep": SWEEP_STATUS,
            "ai_configured": bool(config.GEMINI_API_KEY),
            "screenshot_configured": bool(config.CLOUDFLARE_ACCOUNT_ID and config.CLOUDFLARE_API_TOKEN)}


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    out = await scan_input(req.input, req.mode, req.sender)
    if not out["results"]:
        raise HTTPException(status_code=422, detail="No URL found in the input.")
    return out


@app.post("/api/batch", dependencies=[Depends(require_key)])
async def api_batch(file: UploadFile = File(...), mode: str = Query("fast", pattern="^(fast|deep)$")):
    raw = (await file.read(2_000_000)).decode("utf-8-sig", "replace")
    rows = list(csv.reader(io.StringIO(raw)))
    if not rows:
        raise HTTPException(status_code=422, detail="Empty CSV")
    header = [h.strip().lower() for h in rows[0]]
    col = header.index("url") if "url" in header else 0
    body = rows[1:] if "url" in header else rows
    urls = [r[col].strip() for r in body if len(r) > col and r[col].strip()][:500]
    sem = asyncio.Semaphore(10)

    async def one(u):
        async with sem:
            try:
                return await scan_url(u, "deep" if mode == "deep" else "fast", source="batch")
            except Exception as exc:
                return {"input_url": u, "error": type(exc).__name__}

    results = await asyncio.gather(*(one(u) for u in urls))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["url", "label", "score", "tier", "final_url", "impersonated_brand", "top_reasons_en", "top_reasons_ar", "case_id"])
    for r in results:
        if "score" not in r:
            w.writerow([r["input_url"], "error", "", "", "", "", r.get("error", ""), "", ""])
            continue
        w.writerow([r["input_url"], r["label"], r["score"], r["tier"], r.get("final_url", ""),
                    (r.get("impersonated") or {}).get("name_en", ""), " | ".join(x["en"] for x in r["top_reasons"]),
                    " | ".join(x["ar"] for x in r["top_reasons"]), r["id"]])
    return Response(buf.getvalue().encode("utf-8-sig"), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=cyberguard_results.csv"})


class ProtectRequest(BaseModel):
    text: str = Field(min_length=3, max_length=5000, description="Message whose links should be rewritten as Safe Links")


@app.post("/api/protect")
def api_protect(req: ProtectRequest, request: Request):
    """Gateway side: rewrite every link in a message into a signed click-time-checked Safe Link."""
    out = safelinks.protect(req.text, str(request.base_url))
    if not out["links"]:
        raise HTTPException(status_code=422, detail="No URL found in the input.")
    return out


@app.get("/go")
async def go(request: Request, u: str = Query(min_length=4, max_length=4096), s: str = ""):
    """Click time: scan the link now. Signed + not flagged -> redirect; otherwise a bilingual warning page."""
    signed = safelinks.valid(u, s)
    r = await scan_url(u, "fast", source="safelink")
    if r.get("label") == "invalid":
        raise HTTPException(status_code=400, detail=r.get("error", "invalid link"))
    if signed and r["label"] != "fraud":
        return RedirectResponse(u, status_code=302)
    return HTMLResponse(safelinks.warning_page(r, signed, str(request.base_url)), headers={"Cache-Control": "no-store"})


@app.get("/api/evidence/{case_id}")
def api_evidence(case_id: str, format: str = Query("json", pattern="^(json|pdf|stix)$")):
    r = store.get_scan(case_id)
    if not r:
        raise HTTPException(status_code=404, detail="Unknown case ID")
    shot = store.get_screenshot(case_id)
    if format == "pdf":
        return Response(evidence.build_pdf(r, shot), media_type="application/pdf",
                        headers={"Content-Disposition": f"inline; filename={case_id}.pdf"})
    if format == "stix":
        return Response(evidence.build_stix(r), media_type="application/stix+json",
                        headers={"Content-Disposition": f"attachment; filename={case_id}.stix.json"})
    return Response(evidence.build_json(r, shot), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={case_id}.json"})


@app.get("/api/screenshot/{case_id}.png")
def api_screenshot(case_id: str):
    shot = store.get_screenshot(case_id)
    if not shot:
        raise HTTPException(status_code=404, detail="No screenshot for this case")
    return Response(shot, media_type="image/png")


@app.get("/api/graph")
def api_graph():
    return graph.to_json()


@app.get("/api/recent")
def api_recent():
    return store.recent()


@app.get("/api/early-warnings")
def api_warnings():
    return store.warnings()


@app.get("/api/coverage")
def api_coverage():
    """What each watcher checked on its last run (so 0 hits is visibly 'checked, nothing found')."""
    return store.coverage()


@app.post("/api/watchers/run", dependencies=[Depends(require_key)])
async def api_watchers(background: BackgroundTasks, serp: bool = False):
    from watchers.run_all import run_watchers_async
    background.add_task(run_watchers_async, serp)
    return {"status": "started", "note": "results appear in /api/early-warnings"}
