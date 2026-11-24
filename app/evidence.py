"""Layer 9: police evidence pack - JSON, PDF (English + Arabic) and STIX 2.1 bundle, with SHA-256 hashes and UTC + GST times."""
import hashlib
import io
import json
import uuid
from datetime import datetime, timedelta, timezone

import arabic_reshaper
from bidi.algorithm import get_display
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.config import DATA_DIR, VERSION

# IBM Plex Sans Arabic (OFL) carries both Arabic and Latin glyphs, so mixed lines render fully.
pdfmetrics.registerFont(TTFont("Naskh", str(DATA_DIR / "fonts" / "IBMPlexSansArabic-Regular.ttf")))
pdfmetrics.registerFont(TTFont("NaskhBold", str(DATA_DIR / "fonts" / "IBMPlexSansArabic-Bold.ttf")))
GST = timezone(timedelta(hours=4), "GST")
NS = uuid.UUID("6f1d3c2a-8b7e-4c1a-9d2f-0a5b7c9e1f30")
TIER_COLOR = {"official": "#1f8a4c", "not_verified": "#6b7280", "suspicious": "#c99a06", "likely_scam": "#d9622b",
              "high_risk": "#c0262d"}


def ar(text: str) -> str:
    return get_display(arabic_reshaper.reshape(text or ""))


def ar_block(text: str, style: ParagraphStyle, width: float) -> Paragraph:
    """Wrap Arabic in logical order first, then shape + reorder each line (ReportLab wraps visual text wrongly)."""
    lines, cur = [], []
    for word in (text or "").split():
        trial = " ".join(cur + [word])
        if cur and pdfmetrics.stringWidth(ar(trial), style.fontName, style.fontSize) > width:
            lines.append(" ".join(cur))
            cur = [word]
        else:
            cur.append(word)
    if cur:
        lines.append(" ".join(cur))
    safe = [ar(l).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for l in lines]
    return Paragraph("<br/>".join(safe), style)


def _times(iso: str) -> tuple[str, str]:
    t = datetime.fromisoformat(iso)
    return t.strftime("%Y-%m-%d %H:%M:%S UTC"), t.astimezone(GST).strftime("%Y-%m-%d %H:%M:%S GST (UTC+4)")


def suggested_action(r: dict) -> dict:
    intel = r.get("intel") or {}
    whois = intel.get("whois") or {}
    ipi = intel.get("ip") or {}
    abuse = whois.get("abuse_email")
    steps_en, steps_ar = [], []
    if r["tier"] in ("high_risk", "likely_scam", "suspicious"):
        steps_en.append("Report to Abu Dhabi Police Aman: call 800 2626, SMS 2828, or aman@adpolice.gov.ae (attach this pack).")
        steps_ar.append("الإبلاغ لخدمة أمان - شرطة أبوظبي: 8002626 أو رسالة نصية 2828 أو aman@adpolice.gov.ae مع إرفاق هذا الملف.")
        registrar = f" ({whois['registrar']})" if whois.get("registrar") else ""
        via = f" via {abuse}" if abuse else ""
        steps_en.append(f"Request suspension from the registrar{registrar}{via}; report the ORIGINAL link, not only the final redirect.")
        steps_ar.append("طلب تعليق النطاق من جهة التسجيل والإبلاغ عن الرابط الأصلي وليس فقط الوجهة النهائية.")
        if ipi.get("cloudflare_proxied"):
            steps_en.append("Site is behind Cloudflare: send the hosting report to abuse.cloudflare.com (WHOIS alone points to the wrong party).")
            steps_ar.append("الموقع خلف Cloudflare: أرسل البلاغ عبر abuse.cloudflare.com.")
        elif ipi.get("as_name"):
            steps_en.append(f"Notify the hosting network {ipi.get('as_name')} ({ipi.get('asn')}).")
            steps_ar.append(f"إخطار مزود الاستضافة {ipi.get('as_name')}.")
        steps_en.append("Share the STIX 2.1 indicator with CERT / blocklist partners (aeCERT, APWG eCX).")
        steps_ar.append("مشاركة مؤشر STIX 2.1 مع فرق الاستجابة وقوائم الحظر.")
    elif r["tier"] == "official":
        steps_en.append("Verified official domain. No takedown action.")
        steps_ar.append("نطاق رسمي موثّق. لا حاجة لإجراء إزالة.")
    else:
        steps_en.append("Not verified: do not enter personal or payment data; verify through the entity's official app or website.")
        steps_ar.append("غير موثّق: لا تُدخل بيانات شخصية أو مالية وتحقق عبر التطبيق أو الموقع الرسمي للجهة.")
    return {"en": steps_en, "ar": steps_ar, "legal_basis": "UAE Federal Decree-Law 34/2021: Art. 11 (fake website impersonating an entity), Art. 40 (electronic fraud). Legal wording to be validated by ADP."}


def build_json(r: dict, screenshot: bytes | None) -> bytes:
    utc, gst = _times(r["created_utc"])
    pack = {"case_id": r["id"], "generated_by": f"CyberGuard {VERSION}", "captured_utc": utc, "captured_gst": gst,
            "original_url": r["input_url"], "final_url": r.get("final_url"), "redirect_chain": r.get("hops", []),
            "verdict": {k: r.get(k) for k in ("score", "tier", "tier_en", "tier_ar", "label", "threshold")},
            "reasons": r.get("reasons", []), "impersonated_brand": r.get("impersonated"),
            "domain": {"registrable": r.get("registrable"), "whois": (r.get("intel") or {}).get("whois"),
                       "age_days": (r.get("intel") or {}).get("age_days"), "dns": r.get("dns")},
            "hosting": (r.get("intel") or {}).get("ip"), "threat_feeds": r.get("feeds"), "page": r.get("page"),
            "ai_brand_check": r.get("llm"), "message": r.get("message"), "layers_skipped": r.get("skipped", []),
            "suggested_action": suggested_action(r),
            "hashes": {"screenshot_sha256": hashlib.sha256(screenshot).hexdigest() if screenshot else None}}
    body = json.dumps(pack, ensure_ascii=False, indent=2, default=str).encode()
    pack["hashes"]["pack_sha256_before_this_field"] = hashlib.sha256(body).hexdigest()
    return json.dumps(pack, ensure_ascii=False, indent=2, default=str).encode()


def build_stix(r: dict) -> bytes:
    now = datetime.fromisoformat(r["created_utc"]).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ident = f"identity--{uuid.uuid5(NS, 'cyberguard')}"
    url = r["input_url"].replace("\\", "\\\\").replace("'", "\\'")
    objs = [{"type": "identity", "spec_version": "2.1", "id": ident, "created": now, "modified": now,
             "name": "CyberGuard (ScamShield AI Hackathon prototype)", "identity_class": "system"}]
    ind = {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(NS, r['id'])}", "created": now,
           "modified": now, "created_by_ref": ident, "name": f"{r['tier_en']}: {r['registrable']}",
           "description": "; ".join(x["en"] for x in r.get("top_reasons", [])),
           "indicator_types": ["malicious-activity"] if r["label"] == "fraud" else ["anomalous-activity"],
           "pattern": f"[url:value = '{url}']", "pattern_type": "stix", "valid_from": now,
           "confidence": int(r["score"]), "labels": [x["code"] for x in r.get("reasons", [])],
           "external_references": [{"source_name": "cyberguard", "external_id": r["id"]}]}
    objs.append(ind)
    sco = [{"type": "url", "spec_version": "2.1", "id": f"url--{uuid.uuid5(NS, r['input_url'])}", "value": r["input_url"]}]
    if r.get("final_url") and r["final_url"] != r["input_url"]:
        sco.append({"type": "url", "spec_version": "2.1", "id": f"url--{uuid.uuid5(NS, r['final_url'])}", "value": r["final_url"]})
    if r.get("registrable"):
        sco.append({"type": "domain-name", "spec_version": "2.1", "id": f"domain-name--{uuid.uuid5(NS, r['registrable'])}",
                    "value": r["registrable"]})
    for ip in {h.get("ip") for h in r.get("hops", []) if h.get("ip")}:
        sco.append({"type": "ipv6-addr" if ":" in ip else "ipv4-addr", "spec_version": "2.1",
                    "id": f"{'ipv6' if ':' in ip else 'ipv4'}-addr--{uuid.uuid5(NS, ip)}", "value": ip})
    objs += sco
    objs.append({"type": "observed-data", "spec_version": "2.1", "id": f"observed-data--{uuid.uuid5(NS, r['id'] + 'obs')}",
                 "created": now, "modified": now, "created_by_ref": ident, "first_observed": now, "last_observed": now,
                 "number_observed": 1, "object_refs": [o["id"] for o in sco]})
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid5(NS, r['id'] + 'bundle')}", "objects": objs}
    return json.dumps(bundle, indent=2, ensure_ascii=False).encode()


def build_pdf(r: dict, screenshot: bytes | None) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title=f"CyberGuard evidence {r['id']}", author="CyberGuard")
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontName="Helvetica", fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=10, textColor=colors.HexColor("#444444"))
    arab = ParagraphStyle("a", parent=body, fontName="Naskh", alignment=TA_RIGHT, fontSize=10, leading=15)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold", fontSize=16, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=11, spaceBefore=8, spaceAfter=3)

    def esc(s) -> str:
        return str(s if s is not None else "-").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def wrap(s) -> Paragraph:
        return Paragraph(esc(s), body)

    utc, gst = _times(r["created_utc"])
    intel = r.get("intel") or {}
    whois = intel.get("whois") or {}
    ipi = intel.get("ip") or {}
    color = colors.HexColor(TIER_COLOR.get(r["tier"], "#6b7280"))
    json_hash = hashlib.sha256(build_json(r, screenshot)).hexdigest()
    shot_hash = hashlib.sha256(screenshot).hexdigest() if screenshot else "no screenshot captured"
    el = [Paragraph("CyberGuard - Scam Link Evidence Report", h1),
          Paragraph(ar("تقرير أدلة رابط احتيالي - سايبر جارد"), ParagraphStyle("ah", parent=arab, fontName="NaskhBold", fontSize=13)),
          Paragraph(f"Case ID <b>{esc(r['id'])}</b> &nbsp;|&nbsp; Captured {esc(utc)} / {esc(gst)} &nbsp;|&nbsp; Mode: {esc(r['mode'])}", small),
          Spacer(1, 4)]
    verdict = Table([[Paragraph(f"<font color='white'><b>{r['score']}/100 &nbsp; {esc(r['tier_en'])}</b></font>",
                                ParagraphStyle("v", parent=body, fontSize=13, leading=16)),
                      Paragraph(f"<font color='white'>{esc(ar(r['tier_ar']))}</font>",
                                ParagraphStyle("va", parent=arab, fontName="NaskhBold", fontSize=13))]],
                    colWidths=[95 * mm, 83 * mm])
    verdict.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                 ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    el.append(verdict)
    imp = r.get("impersonated")
    rows = [["Original URL (as received)", wrap(r["input_url"])], ["Final URL", wrap(r.get("final_url"))],
            ["Registrable domain", wrap(r.get("registrable"))],
            ["Impersonated brand", wrap(f"{imp['name_en']} - official: {', '.join(imp['official_domains'])}" if imp else "-")],
            ["Binary label", wrap(f"{r['label']} (threshold {r['threshold']})")]]
    el += [Paragraph("Link", h2), _kv(rows)]

    el.append(Paragraph(f"Why / <font name='NaskhBold'>{ar('الأسباب')}</font>", h2))
    for x in r.get("reasons", [])[:10]:
        el.append(Paragraph(f"<b>[{esc(x['code'])} {x['weight']:+d}]</b> {esc(x['en'])}", body))
        el.append(ar_block(x["ar"], arab, 172 * mm))
    if r.get("skipped"):
        el.append(Paragraph("Layers skipped (not counted as safe): " + esc("; ".join(r["skipped"])), small))

    hops = r.get("hops", [])
    if hops:
        el.append(Paragraph("Redirect chain", h2))
        el.append(_kv([[f"Hop {i}", wrap(f"{h.get('status') or h.get('error')}  {h['url']}  {h.get('ip') or ''}"
                                         f"{'  [shortener]' if h.get('shortener') else ''}")] for i, h in enumerate(hops)]))

    el.append(Paragraph("Domain registration and hosting", h2))
    el.append(_kv([["Registrar", wrap(whois.get("registrar"))], ["Registrar abuse contact", wrap(whois.get("abuse_email"))],
                   ["Created", wrap(f"{whois.get('created') or 'unknown'} ({intel.get('age_days') if intel.get('age_days') is not None else '?'} days)")],
                   ["Nameservers", wrap(", ".join(whois.get("nameservers") or (r.get("dns") or {}).get("ns") or []))],
                   ["IP / ASN / hosting", wrap(f"{ipi.get('ip', '-')} / {ipi.get('asn', '-')} {ipi.get('as_name', '')} / {ipi.get('country', '')}"
                                               f"{' (Cloudflare proxy - real host hidden)' if ipi.get('cloudflare_proxied') else ''}")],
                   ["Threat feeds", wrap("; ".join(f"{f['source']} ({f['match']})" for f in r.get("feeds", [])) or "no listing found (not proof of safety)")]]))

    page = r.get("page") or {}
    if page:
        el.append(Paragraph("Page capture", h2))
        el.append(_kv([["Title", wrap(page.get("title"))], ["Sensitive fields", wrap(", ".join(page.get("sensitive_fields", [])) or "none found")],
                       ["Phone numbers on page", wrap(", ".join(page.get("phones", [])) or "-")],
                       ["Favicon mmh3", wrap(page.get("favicon_mmh3"))],
                       ["Cloudflare scan", wrap((page.get("cloudflare") or {}).get("report_url"))]]))
    if screenshot:
        img = ImageReader(io.BytesIO(screenshot))
        w, h = img.getSize()
        scale = min(70 * mm / w, 120 * mm / h)
        el += [Spacer(1, 4), Image(io.BytesIO(screenshot), width=w * scale, height=h * scale)]
    if r.get("llm"):
        el.append(Paragraph("AI brand check (advisory; code makes the decision)", h2))
        for e in r["llm"].get("evidence_en", []):
            el.append(Paragraph("- " + esc(e), body))

    act = suggested_action(r)
    el.append(Paragraph(f"Suggested action / <font name='NaskhBold'>{ar('الإجراء المقترح')}</font>", h2))
    for e, a in zip(act["en"], act["ar"]):
        el.append(Paragraph("- " + esc(e), body))
        el.append(ar_block(a, arab, 172 * mm))
    el.append(Paragraph(esc(act["legal_basis"]), small))
    el.append(Paragraph("Integrity", h2))
    el.append(_kv([["SHA-256 JSON evidence", wrap(json_hash)], ["SHA-256 screenshot", wrap(shot_hash)],
                   ["Tool", wrap(f"CyberGuard {VERSION}; automated pre-assessment, requires analyst confirmation before public action")]]))
    doc.build(el)
    return buf.getvalue()


def _kv(rows) -> Table:
    t = Table(rows, colWidths=[42 * mm, 136 * mm])
    t.setStyle(TableStyle([("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6"))]))
    return t
