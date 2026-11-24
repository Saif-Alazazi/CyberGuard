"""Offline unit tests for the deterministic layers (no network)."""
import asyncio

import pytest

from app.pipeline import allowlist, extract, lexical
from app.pipeline.netsafe import UnsafeURL, normalize, resolve_public
from app.pipeline.score import finalize, reason


def codes(url: str) -> set[str]:
    from urllib.parse import urlsplit
    return {s["code"] for s in lexical.analyse(url, urlsplit(url).hostname)}


def test_allowlist_uses_registrable_domain_not_substring():
    assert allowlist.check("https://smartservices.icp.gov.ae/login")["official_brand"] == "icp"
    assert allowlist.check("https://darb.qmobility.ae/")["official_brand"] == "qmobility"
    assert allowlist.check("https://dubaipolice.gov.ae.verify-fine.top/")["official_brand"] is None


def test_shorteners_and_free_hosting_are_never_allowlisted():
    assert allowlist.check("https://bit.ly/abc")["shortener"]
    g = allowlist.check("https://uaepass.web.app/login")
    assert g["hosting"] == "web.app" and g["official_brand"] is None and g["tranco_rank"] is None


def test_unlisted_gov_ae_is_flagged_for_verification():
    assert allowlist.check("https://www.unknown-entity.gov.ae/")["gov_ae_unlisted"]


def test_lookalikes_and_suffix_trick():
    assert {"BRAND_IN_HOST", "SUFFIX_TRICK", "ABUSED_TLD"} <= codes("https://rta.gov.ae-pay.top/fines")
    assert "BRAND_IN_HOST" in codes("http://dubaipoit.com/")
    assert "SUFFIX_TRICK" in codes("http://com-courtfees.xin/")
    assert "USERINFO_TRICK" in codes("https://www.salik.ae@salik-pay.top/")
    assert "FREE_HOST_BRAND" in codes("https://uaepass-verify.web.app/login")


def test_ordinary_words_are_not_brands():
    for host in ("parkingfrog.com", "softwarepostu.cl", "mvdmobility.com.uy", "portal-news.com"):
        assert not lexical.brand_hits(host.rsplit(".", 1)[0]), host


def test_confusable_and_punycode():
    host = "dubaipοlice.com".encode("idna").decode()  # Greek omicron
    c = codes(f"https://{host}/")
    assert {"PUNYCODE", "MIXED_SCRIPT", "BRAND_IN_HOST"} <= c


def test_extract_defanged_links_and_arabic_digits():
    text = "ادفع المخالفة ٥٠ درهم: hxxps://rta-fines[.]top/pay الآن"
    assert extract.extract_urls(text) == ["https://rta-fines.top/pay"]
    msg = extract.analyse_message("هيئة الطرق والمواصلات: لديك مخالفة مرورية غير مدفوعة", "+63 917 555 0142")
    assert "rta" in msg["claimed_brands"] and msg["lure_hits"] and msg["sender_flags"]


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://localhost:8000/",
                                 "http://10.0.0.5/", "ftp://example.com/", "http://example.com:8080/"])
def test_ssrf_guard_rejects_internal_targets(url):
    with pytest.raises(UnsafeURL):
        normalize(url)


def test_ssrf_guard_rejects_private_addresses_at_resolution():
    with pytest.raises(UnsafeURL):
        asyncio.run(resolve_public("192.168.1.10"))


def test_scoring_tiers_and_overrides():
    official = finalize([reason("ALLOW_OFFICIAL", "ADCB"), reason("LURE_IN_PATH", "login")], official=True, known_bad=False)
    assert official["tier"] == "official" and official["score"] <= 10 and official["label"] == "legit"
    bad = finalize([reason("KNOWN_BAD", "OpenPhish")], official=False, known_bad=True)
    assert bad["score"] >= 90 and bad["tier"] == "high_risk" and bad["label"] == "fraud"
    unknown = finalize([], official=False, known_bad=False)
    assert unknown["tier"] == "not_verified" and unknown["tier_en"].startswith("No record")
    phone = finalize([reason("ALLOW_OFFICIAL", "x"), reason("QUERY_PHONE", "800123456")], official=True, known_bad=False)
    assert phone["tier"] != "official"


def test_safe_links_are_signed_and_rewritten():
    from app import safelinks
    out = safelinks.protect("RTA: pay your fine at hxxps://rta-fines[.]top/pay now.", "https://cg.example/")
    assert len(out["links"]) == 1 and out["links"][0]["original"] == "https://rta-fines.top/pay"
    assert out["protected_text"].startswith("RTA: pay your fine at https://cg.example/go?u=") and out["protected_text"].endswith(" now.")
    assert safelinks.valid("https://rta-fines.top/pay", safelinks.sign("https://rta-fines.top/pay"))
    assert not safelinks.valid("https://evil.example/", safelinks.sign("https://rta-fines.top/pay"))
    assert not safelinks.valid("https://evil.example/", "")
