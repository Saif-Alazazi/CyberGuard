"""Layer 8: reason codes -> 0-100 score, tier and binary label. Every reason carries English and Arabic text."""
from app import config

# code: (weight, English, Arabic). {d} = detail string.
REASONS: dict[str, tuple[int, str, str]] = {
    "ALLOW_OFFICIAL": (0, "Final domain is a verified official domain of {d}.", "النطاق النهائي نطاق رسمي موثّق لـ {d}."),
    "KNOWN_BAD": (0, "Listed as malicious by threat intelligence: {d}.", "مُدرج كرابط ضار في مصادر استخبارات التهديدات: {d}."),
    "QUERY_PHONE": (30, "An official domain carries an injected phone number in the link ({d}); fake-helpline trick.", "رابط لنطاق رسمي يحمل رقم هاتف مُدرج ({d})، وهي حيلة أرقام خدمة عملاء مزيفة."),
    "BRAND_MISMATCH_CRP": (40, "Page presents itself as {d} but is not on its official domain and asks for credentials, payment or OTP.", "الصفحة تنتحل صفة {d} على نطاق غير رسمي وتطلب بيانات دخول أو دفع أو رمز تحقق."),
    "TG_EXFIL": (40, "Form data is sent to a Telegram bot ({d}), a phishing-kit exfiltration method.", "تُرسل بيانات النموذج إلى بوت تيليجرام ({d})، وهي طريقة تسريب تستخدمها أدوات التصيد."),
    "CF_SCANNER_MALICIOUS": (35, "Cloudflare URL Scanner verdict: malicious ({d}).", "حكم ماسح الروابط من Cloudflare: ضار ({d})."),
    "BRAND_IN_HOST": (35, "Domain imitates {d} but is not its official domain.", "النطاق ينتحل اسم {d} وليس نطاقه الرسمي."),
    "FAVICON_CLONE": (35, "Uses the official icon of {d} on a non-official domain.", "يستخدم الأيقونة الرسمية لـ {d} على نطاق غير رسمي."),
    "USERINFO_TRICK": (25, "Link hides its real destination after an '@' sign: {d}.", "الرابط يخفي وجهته الحقيقية بعد علامة '@': {d}."),
    "CRED_FORM": (25, "Page asks for sensitive data: {d}.", "الصفحة تطلب بيانات حساسة: {d}."),
    "FREE_HOST_BRAND": (25, "Brand name on a free hosting platform: {d}.", "اسم علامة تجارية على منصة استضافة مجانية: {d}."),
    "NEW_DOMAIN": (20, "Domain registered only {d} days ago.", "تم تسجيل النطاق قبل {d} يوماً فقط."),
    "RECENT_DOMAIN": (8, "Domain is young ({d} days old).", "النطاق حديث ({d} يوماً)."),
    "SUFFIX_TRICK": (20, "Fake official suffix inside the address ({d}).", "لاحقة رسمية مزيفة داخل العنوان ({d})."),
    "FAKE_HELPLINE": (20, "Phone number on the page is not an official helpline: {d}.", "رقم الهاتف في الصفحة ليس رقماً رسمياً: {d}."),
    "TEXT_BRAND_MISMATCH": (20, "Message claims to be from {d} but the link is not an official domain.", "الرسالة تدّعي أنها من {d} لكن الرابط ليس نطاقاً رسمياً."),
    "MIXED_SCRIPT": (20, "Domain mixes alphabets to look like another name ({d}).", "النطاق يمزج بين حروف لغات مختلفة ليشبه اسماً آخر ({d})."),
    "CERT_SIBLINGS": (15, "Its TLS certificate also covers other UAE look-alike domains ({d}), a sign of one scam operator.", "شهادة TLS الخاصة به تغطي أيضاً نطاقات مشابهة لجهات إماراتية ({d})، ما يدل على مشغّل احتيال واحد."),
    "BRAND_IN_PATH": (15, "Brand name hidden in the link path on an unrelated site ({d}), typical of hacked sites hosting phishing.", "اسم علامة تجارية مخفي في مسار الرابط على موقع غير ذي صلة ({d})، وهو نمط شائع في المواقع المخترقة."),
    "EMAIL_IN_URL": (15, "Link carries the recipient's e-mail address ({d}), a credential-phishing pattern.", "الرابط يحمل البريد الإلكتروني للمستلم ({d})، وهو نمط تصيد لبيانات الدخول."),
    "IP_HOST": (15, "Link points to a raw IP address ({d}).", "الرابط يشير إلى عنوان IP مباشر ({d})."),
    "PAGE_BRAND": (15, "Page text names {d} on a non-official domain.", "نص الصفحة يذكر {d} على نطاق غير رسمي."),
    "CLOAK": (15, "Possible cloaking: {d}.", "احتمال إخفاء المحتوى عن الفاحصين: {d}."),
    "INFRA_LINK": (15, "Shares infrastructure with a known scam domain ({d}).", "يشترك في البنية التحتية مع نطاق احتيالي معروف ({d})."),
    "CONFUSABLE": (10, "Uses look-alike characters: {d}.", "يستخدم حروفاً متشابهة شكلاً: {d}."),
    "PUNYCODE": (10, "Internationalised (punycode) domain: {d}.", "نطاق دولي مُرمّز (Punycode): {d}."),
    "ABUSED_TLD": (10, "Top-level domain often used in scams ({d}).", "امتداد نطاق شائع الاستخدام في الاحتيال ({d})."),
    "NO_DNS": (10, "Domain does not resolve (scam domains are often taken down within days).", "النطاق لا يعمل (غالباً ما تُغلق نطاقات الاحتيال خلال أيام)."),
    "LURE_TEXT": (10, "Message uses known UAE scam wording: {d}.", "الرسالة تستخدم عبارات احتيال معروفة في الإمارات: {d}."),
    "SENDER_ANOMALY": (10, "Claims to be official but sent from {d}.", "تدّعي أنها رسمية لكنها مرسلة من {d}."),
    "LURE_IN_HOST": (10, "Domain contains login/payment bait words ({d}).", "النطاق يحتوي على كلمات استدراج للدخول أو الدفع ({d})."),
    "FREE_HOSTING": (15, "Hosted on a free hosting platform ({d}).", "مستضاف على منصة استضافة مجانية ({d})."),
    "UAE_KEYWORD": (10, "UAE keyword used as bait in an untrusted domain ({d}).", "كلمة إماراتية مستخدمة كطُعم في نطاق غير موثوق ({d})."),
    "LURE_IN_PATH": (5, "Link path contains login/payment bait words ({d}).", "مسار الرابط يحتوي على كلمات استدراج ({d})."),
    "RANDOM_LABEL": (10, "Random-looking domain name ({d}).", "اسم نطاق عشوائي المظهر ({d})."),
    "RANDOM_TENANT": (15, "Machine-generated site name on free hosting ({d}), typical of phishing kits.", "اسم موقع مولّد آلياً على استضافة مجانية ({d})، وهو نمط شائع في أدوات التصيد."),
    "COMPLEX_HOST": (5, "Unusually long or hyphenated host ({d}).", "اسم مضيف طويل أو كثير الشرطات ({d})."),
    "KIT_HOSTING": (5, "Hosted on {d}, common for UAE-targeting phishing kits.", "مستضاف لدى {d}، وهي استضافة شائعة لأدوات التصيد التي تستهدف الإمارات."),
    "SHORTENER": (5, "Uses a link shortener ({d}).", "يستخدم خدمة اختصار روابط ({d})."),
    "MANY_HOPS": (5, "Long redirect chain ({d} hops).", "سلسلة إعادة توجيه طويلة ({d} قفزات)."),
    "POPULAR": (-15, "Domain is widely used (Tranco rank {d}).", "النطاق واسع الاستخدام (ترتيب Tranco {d})."),
    "GOV_AE_UNLISTED": (-10, "Under .gov.ae but not in our verified list ({d}); verify manually.", "ضمن .gov.ae لكنه غير مدرج في قائمتنا الموثقة ({d})؛ يُرجى التحقق."),
}

TIERS = [(75, "high_risk"), (50, "likely_scam"), (25, "suspicious"), (0, "not_verified")]
TIER_TEXT = {
    "official": ("Official domain", "نطاق رسمي"),
    "high_risk": ("High-risk scam", "احتيال عالي الخطورة"),
    "likely_scam": ("Likely scam", "احتيال مرجّح"),
    "suspicious": ("Suspicious", "مشبوه"),
    "not_verified": ("No record - not verified", "لا يوجد سجل - غير موثّق"),
}


def reason(code: str, detail: str = "", weight: int | None = None, detail_ar: str | None = None) -> dict:
    w, en, ar = REASONS[code]
    return {"code": code, "weight": w if weight is None else weight, "detail": detail,
            "en": en.format(d=detail), "ar": ar.format(d=detail if detail_ar is None else detail_ar)}


def finalize(reasons: list[dict], official: bool, known_bad: bool) -> dict:
    # Keep the strongest instance of each code
    best: dict[str, dict] = {}
    for r in reasons:
        if r["code"] not in best or r["weight"] > best[r["code"]]["weight"]:
            best[r["code"]] = r
    rs = sorted(best.values(), key=lambda r: -abs(r["weight"]))
    raw = sum(r["weight"] for r in rs)
    score = max(0, min(100, raw))
    has_phone_trick = "QUERY_PHONE" in best
    if official and not has_phone_trick:
        score = min(score, 10)
        tier = "official"
    else:
        if known_bad:
            score = max(score, 90)
        tier = next(t for lim, t in TIERS if score >= lim)
    label = "fraud" if (score >= config.THRESHOLD and tier != "official") else "legit"
    en, ar = TIER_TEXT[tier]
    first = {"official": "ALLOW_OFFICIAL"}.get(tier) or ("KNOWN_BAD" if known_bad else "")
    rs.sort(key=lambda r: (r["code"] != first, -abs(r["weight"])))
    top = [r for r in rs if r["weight"] > 0 or r["code"] in ("ALLOW_OFFICIAL", "KNOWN_BAD")][:3] or rs[:3]
    return {"score": score, "tier": tier, "tier_en": en, "tier_ar": ar, "label": label, "threshold": config.THRESHOLD,
            "reasons": rs, "top_reasons": top}
