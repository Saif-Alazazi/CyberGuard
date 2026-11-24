"""Safe Links: click-time protection for links delivered by SMS / WhatsApp / e-mail gateways.

A sender (telecom SMS gateway, bank notification system, messaging bot) rewrites every link through
/go?u=<url>&s=<signature>. When a person taps it, CyberGuard scans the link at that moment:
signed and not flagged -> redirect; flagged -> bilingual warning page with reasons and a pre-filled Aman report.
Only links signed with the server secret are ever redirected automatically, so the gateway cannot be used
as an open redirect to launder scam links.
"""
import hashlib
import hmac
import html
from urllib.parse import quote, urlencode

from app import config
from app.pipeline import extract

TIER_COLOR = {"official": "#1f8a4c", "not_verified": "#6b7280", "suspicious": "#b78900", "likely_scam": "#d9622b",
              "high_risk": "#c0262d"}


def sign(url: str) -> str:
    return hmac.new(config.LINK_SECRET.encode(), url.encode(), hashlib.sha256).hexdigest()[:24]


def valid(url: str, sig: str) -> bool:
    return bool(sig) and hmac.compare_digest(sign(url), sig)


def gateway_link(base: str, url: str) -> str:
    return f"{base.rstrip('/')}/go?{urlencode({'u': url, 's': sign(url)})}"


def protect(text: str, base: str) -> dict:
    """Rewrite every link in a message into a signed Safe Link."""
    links = []

    def swap(u: str) -> str:
        safe = gateway_link(base, u)
        links.append({"original": u, "safe_link": safe})
        return safe

    return {"protected_text": extract.rewrite_urls(text, swap), "links": links}


def warning_page(r: dict, signed: bool, base: str) -> str:
    """Self-contained bilingual interstitial (no scripts) shown instead of a flagged or unverifiable link."""
    e = html.escape
    color = TIER_COLOR.get(r.get("tier"), "#6b7280")
    imp = r.get("impersonated")
    reasons_en = "".join(f"<li>{e(x['en'])}</li>" for x in r.get("top_reasons", []))
    reasons_ar = "".join(f"<li>{e(x['ar'])}</li>" for x in r.get("top_reasons", []))
    flagged = r.get("label") == "fraud"
    head_en = "Warning: this link looks like a scam" if flagged else "Check before you continue"
    head_ar = "تحذير: هذا الرابط يبدو احتيالياً" if flagged else "تحقّق قبل المتابعة"
    official = ""
    if imp and imp.get("official_domains"):
        dom = imp["official_domains"][0]
        official = (f"<p class='off'>It pretends to be <b>{e(imp['name_en'])}</b>. Official site: "
                    f"<a href='https://{e(dom)}' rel='noopener'>{e(dom)}</a></p>"
                    f"<p class='off' dir='rtl'>ينتحل صفة <b>{e(imp.get('name_ar') or imp['name_en'])}</b>. الموقع الرسمي: "
                    f"<a href='https://{e(dom)}' rel='noopener'>{e(dom)}</a></p>")
    mail = "mailto:aman@adpolice.gov.ae?" + urlencode({
        "subject": f"Scam link report {r['id']}",
        "body": f"Suspicious link: {r['input_url']}\nCyberGuard case: {r['id']} (score {r['score']}/100, {r['tier_en']})\n"
                f"Evidence: {base.rstrip('/')}/api/evidence/{r['id']}?format=pdf\n"}, quote_via=quote)
    proceed = "" if flagged and r.get("score", 0) >= 75 else (
        f"<p class='small'><a href='{e(r['input_url'])}' rel='noopener noreferrer nofollow'>"
        f"{'Continue anyway (not recommended)' if flagged else 'Open the link anyway'}</a>"
        f"{'' if signed else ' - this link was not issued by a CyberGuard gateway'}</p>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>CyberGuard warning</title>
<style>
body{{margin:0;background:#f4f6f9;color:#0f1e2e;font:16px/1.5 system-ui,"Segoe UI",Tahoma,sans-serif}}
main{{max-width:640px;margin:0 auto;padding:24px 16px}}
.card{{background:#fff;border-radius:12px;border-top:8px solid {color};padding:22px;box-shadow:0 4px 18px rgba(0,0,0,.08)}}
h1{{font-size:1.35rem;margin:0 0 4px;color:{color}}} .ar{{direction:rtl;text-align:right}}
.score{{display:inline-block;background:{color};color:#fff;border-radius:8px;padding:4px 12px;font-weight:700;margin:8px 0}}
.url{{font-family:ui-monospace,Consolas,monospace;font-size:.85rem;word-break:break-all;background:#f4f6f9;padding:8px;border-radius:6px}}
ul{{padding-inline-start:20px}} .off{{background:#fff4e5;padding:8px 10px;border-radius:6px}}
.btns a{{display:inline-block;margin:6px 8px 0 0;padding:10px 16px;border-radius:8px;text-decoration:none;font-weight:600}}
.go{{background:#0b3d5c;color:#fff}} .rep{{background:#c0262d;color:#fff}} .ev{{background:#eef3f7;color:#0b3d5c}}
.small{{font-size:.85rem;color:#5b6b7c;margin-top:18px}}
@media (prefers-color-scheme: dark){{body{{background:#0b1622;color:#e7edf3}} .card{{background:#102033}}
.url{{background:#0b1622}} .off{{background:#3a2a12;color:#ffd9a3}} a{{color:#7cc4f5}} .ev{{background:#0b1622;color:#7cc4f5}}}}
</style></head><body><main><div class="card">
<h1>{head_en}</h1><h1 class="ar">{head_ar}</h1>
<span class="score">{r['score']}/100 · {e(r['tier_en'])} · {e(r['tier_ar'])}</span>
<div class="url">{e(r['input_url'])}</div>
{official}
<ul>{reasons_en}</ul><ul class="ar">{reasons_ar}</ul>
<div class="btns"><a class="go" href="/">Go back to safety · العودة بأمان</a>
<a class="rep" href="{e(mail)}">Report to Aman · إبلاغ أمان</a>
<a class="ev" href="/api/evidence/{e(r['id'])}?format=pdf" target="_blank" rel="noopener">Evidence · الأدلة</a></div>
{proceed}
<p class="small">Checked by CyberGuard at the moment you clicked (case {e(r['id'])}). Aman: 800 2626 · SMS 2828.</p>
</div></main></body></html>"""
