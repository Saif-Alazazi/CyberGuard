"""Build eval/validation.csv (url,label,slice,source).

fraud slices
  openphish      fresh URLs from the OpenPhish community feed (last 8 snapshots, ~4 days)
  smishing_ioc   Unit 42 smishing IOCs (Smishing Triad infrastructure) + UAE IOCs from Resecurity
  uae_synthetic  hand-written UAE lure patterns; reported separately, never in headline numbers
legit slices
  uae_official   real links crawled from official UAE bank/government sites (deep pages)
  uae_business   real links from legitimate UAE businesses that are NOT in the allowlist
  tranco         real deep links crawled from random Tranco top-10k sites
  legit_hosting  well-known organisations' sites on free hosting platforms (github.io, blogspot)

Run: python eval/build_validation.py   (needs internet; takes a few minutes)
"""
import asyncio
import csv
import json
import random
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
import tldextract

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "eval" / "cache"
OUT = ROOT / "eval" / "validation.csv"
EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
random.seed(42)

UAE_IOCS = [
    "http://dubaipoit.com/", "http://dubaipoliauey.top/", "http://sagy.site/", "http://vcnjh.icu/",
    "http://dub.xcber.icu/", "http://qad.uhbds.icu/",
]

UAE_SYNTHETIC = [
    "https://rta.gov.ae-pay.top/fines", "https://dubaipolice-fines.icu/pay", "https://uaepass-verify.online/login",
    "https://tamm-abudhabi.site/services/payment", "https://salik-toll.cc/balance", "https://darb-alert.top/secure",
    "https://adcb-secure-login.xyz/", "https://emiratesnbd.com-verify.info/otp", "https://emiratespost-redelivery.top/track",
    "https://icp-emiratesid-update.click/", "https://xn--dubaiplice-zbb.com/", "https://mawaqif-parking.vip/pay",
    "https://adpolice.gov.ae.traffic-fines.cfd/", "https://rtadubai-fine.buzz/pay", "https://uae-pass.web.app/login",
    "https://enbd-rewards.pages.dev/", "https://dewa-refund.store/", "https://etisalat-points.live/redeem",
    "https://mashreq-kyc.world/update", "https://fab-bank-secure.xin/", "https://parkin-fines.win/",
    "https://www.salik.ae@salik-pay.top/", "https://moi-uae.cyou/fine", "https://aramex-customs-fee.shop/",
    "https://dubaipollce.com/", "https://adcb.com.secure-auth.bond/", "https://tammabudhabi.netlify.app/",
    "https://qmobility-darb.sbs/", "https://consumer-protection-uae.online/complaint", "https://emirates-post.cfd/parcel",
]

UAE_OFFICIAL_SEEDS = [
    "https://www.adpolice.gov.ae", "https://www.dubaipolice.gov.ae", "https://www.moi.gov.ae", "https://u.ae/en",
    "https://www.tamm.abudhabi", "https://uaepass.ae", "https://icp.gov.ae", "https://www.tdra.gov.ae",
    "https://www.centralbank.ae", "https://www.rta.ae", "https://www.salik.ae", "https://www.parkin.ae",
    "https://www.qmobility.ae", "https://www.emiratespost.ae", "https://www.dewa.gov.ae", "https://www.sewa.gov.ae",
    "https://www.eand.ae", "https://www.du.ae", "https://www.bankfab.com", "https://www.adcb.com",
    "https://www.emiratesnbd.com", "https://www.mashreq.com", "https://www.dib.ae", "https://www.adib.ae",
    "https://www.cbd.ae", "https://www.rakbank.ae", "https://www.emiratesislamic.ae", "https://www.wio.io",
    "https://www.ajmanbank.ae", "https://www.sib.ae", "https://www.alhilalbank.ae", "https://www.nbf.ae",
    "https://www.hsbc.ae", "https://www.adcustoms.gov.ae", "https://www.abudhabi.gov.ae", "https://www.shjpolice.gov.ae",
    "https://www.etihadwe.ae", "https://www.taqadistribution.com", "https://www.mohre.gov.ae", "https://gdrfad.gov.ae",
    "https://www.payit.ae", "https://www.liv.me", "https://www.eandmoney.com", "https://www.aramex.com",
]
# Deep login / payment pages known from the entities' public sites, used when the crawl is blocked.
UAE_OFFICIAL_FIXED = [
    "https://www.rta.ae/wps/portal/rta/ae/home/fines-payment", "https://traffic.rta.ae/trfesrv/public_resources/ffu/fines-payment.do",
    "https://www.salik.ae/en/recharge", "https://customers.salik.ae/surepass/login", "https://darb.qmobility.ae/",
    "https://app.qmobility.ae/", "https://smartservices.icp.gov.ae/echannels/web/client/default.html#/login",
    "https://www.adpolice.gov.ae/en/services/traffic-fines", "https://es.adpolice.gov.ae/trafficservices/finespublic/inquiry.aspx",
    "https://www.dubaipolice.gov.ae/app/services/fine-payment/search", "https://www.tamm.abudhabi/en/aspects-of-life/trafficandtransportation",
    "https://www.tamm.abudhabi/en/login", "https://stage.tamm.abudhabi/en/", "https://id.uaepass.ae/idshub/login",
    "https://selfcare.uaepass.ae/", "https://online.adcb.com/", "https://www.adcb.com/en/personal/cards/credit-cards/",
    "https://online.emiratesnbd.com/", "https://www.emiratesnbd.com/en/fraud", "https://www.mashreq.com/en/uae/neo/",
    "https://digital.mashreq.com/", "https://www.bankfab.com/en-ae/personal/credit-cards", "https://www.adib.ae/en/pages/online-banking.aspx",
    "https://ebanking.dib.ae/", "https://www.dewa.gov.ae/en/consumer/billing/easy-pay", "https://www.du.ae/personal/quickpay",
    "https://www.eand.ae/en/quick-pay.html", "https://www.emiratespost.ae/track-and-trace", "https://www.parkin.ae/en/services/fines",
    "https://www.moi.gov.ae/en/eservices/traffic.fines.aspx", "https://u.ae/en/information-and-services/justice-safety-and-the-law",
    "https://www.centralbank.ae/en/our-operations/consumer-protection/", "https://www.rakbank.ae/en/personal/digital-banking",
    "https://www.cbd.ae/personal/digital-banking", "https://login.wio.io/", "https://mypay.payit.ae/",
]
LEGIT_HOSTING = ['https://google.github.io/styleguide/', 'https://microsoft.github.io/generative-ai-for-beginners/', 'https://facebook.github.io/react-native/', 'https://mozilla.github.io/pdf.js/', 'https://aws.github.io/copilot-cli/', 'https://kubernetes.github.io/ingress-nginx/', 'https://openai.github.io/openai-agents-python/', 'https://pytorch.github.io/', 'https://apple.github.io/swift-format/', 'https://twbs.github.io/', 'https://lodash.github.io/', 'https://sindresorhus.github.io/', 'https://d3.github.io/', 'https://jquery.github.io/', 'https://googleprojectzero.blogspot.com/', 'https://android-developers.blogspot.com/', 'https://googleonlinesecurity.blogspot.com/', 'https://chromium.github.io/', 'https://nvidia.github.io/', 'https://ibm.github.io/', 'https://adobe.github.io/', 'https://netflix.github.io/', 'https://spotify.github.io/', 'https://shopify.github.io/', 'https://uber.github.io/']
UAE_BUSINESS_SEEDS = [
    "https://www.noon.com/uae-en/", "https://uae.dubizzle.com", "https://www.bayut.com", "https://www.propertyfinder.ae",
    "https://www.talabat.com/uae", "https://www.careem.com", "https://www.emirates.com/ae/english/", "https://www.etihad.com/en-ae/",
    "https://www.flydubai.com/en/", "https://www.airarabia.com/en", "https://www.emaar.com", "https://www.aldar.com",
    "https://www.adnoc.ae", "https://www.enoc.com", "https://www.majidalfuttaim.com", "https://www.carrefouruae.com",
    "https://www.luluhypermarket.com/en-ae", "https://uae.sharafdg.com", "https://www.khaleejtimes.com", "https://gulfnews.com",
    "https://www.thenationalnews.com", "https://www.wam.ae/en", "https://www.uaeu.ac.ae/en/", "https://www.ku.ac.ae",
    "https://www.aus.edu", "https://mbzuai.ac.ae", "https://www.seha.ae", "https://www.dha.gov.ae/en",
    "https://www.adek.gov.ae", "https://www.visitdubai.com/en/", "https://visitabudhabi.ae/en", "https://www.yasisland.com",
    "https://www.louvreabudhabi.ae", "https://www.dubaidutyfree.com", "https://www.emiratesauction.com", "https://www.zawya.com/en",
    "https://www.ded.ae", "https://www.dubaichamber.com", "https://www.dubaiairports.ae", "https://www.adq.ae",
    "https://www.mubadala.com", "https://www.ptlmall.com", "https://www.yallacompare.com/uae", "https://www.policybazaar.ae",
    "https://www.ikea.com/ae/en/", "https://www.amazon.ae", "https://www.namshi.com/uae-en/", "https://www.virginmegastore.ae/en",
    "https://www.dubaiopera.com", "https://www.expocitydubai.com/en/",
]
SKIP_EXT = re.compile(r"\.(pdf|jpg|jpeg|png|gif|svg|zip|docx?|xlsx?|mp4|webp|ico|css|js)(\?|$)", re.I)


def etld1(host: str) -> str:
    return EXTRACT(host).registered_domain or host


async def crawl(client: httpx.AsyncClient, seed: str, per_site: int) -> list[str]:
    try:
        resp = await client.get(seed)
    except Exception:
        return []
    if resp.status_code >= 400 or "html" not in resp.headers.get("content-type", ""):
        return [str(resp.url)] if resp.status_code < 400 else []
    base = str(resp.url)
    site = etld1(urlsplit(base).hostname or "")
    links = set()
    for href in re.findall(r'href=["\']([^"\'#]+)', resp.text[:800_000]):
        u = urljoin(base, href.strip())
        parts = urlsplit(u)
        if parts.scheme not in ("http", "https") or not parts.hostname or SKIP_EXT.search(u):
            continue
        if etld1(parts.hostname) == site and len(parts.path) > 1:
            links.add(u)
    ranked = sorted(links, key=lambda x: (-("login" in x or "pay" in x or "account" in x or "card" in x), -len(x)))
    pick = ranked[: per_site * 3]
    random.shuffle(pick)
    return [base] + pick[:per_site]


async def crawl_all(seeds: list[str], per_site: int) -> list[str]:
    sem = asyncio.Semaphore(12)
    async with httpx.AsyncClient(timeout=12, follow_redirects=True, headers={"User-Agent": UA, "Accept-Language": "en-AE,ar;q=0.8"}) as client:
        async def one(s):
            async with sem:
                return await crawl(client, s, per_site)
        results = await asyncio.gather(*(one(s) for s in seeds))
    return [u for r in results for u in r]


def openphish_urls() -> list[str]:
    commits = httpx.get("https://api.github.com/repos/openphish/public_feed/commits",
                        params={"path": "feed.txt", "per_page": 8}, timeout=30).json()
    urls: list[str] = []
    for c in commits:
        raw = httpx.get(f"https://raw.githubusercontent.com/openphish/public_feed/{c['sha']}/feed.txt", timeout=30).text
        urls += [line.strip() for line in raw.splitlines() if line.strip().startswith("http")]
    return list(dict.fromkeys(urls))


def unit42_urls() -> list[str]:
    out = []
    for f in sorted(CACHE.glob("u42_*.txt")):
        for token in re.findall(r"[a-z0-9][a-z0-9.\-@/\[\]]*\[\.\][a-z]{2,}[^\s,]*", f.read_text(encoding="utf-8").lower()):
            if "unit42" in token or "paloalto" in token:
                continue
            out.append("http://" + token.replace("[.]", ".").replace("[", "").replace("]", ""))
    # the IOC notes also quote the legitimate brand domains being imitated (e.g. www.fedex.com): drop popular domains
    tranco = set((ROOT / "data" / "tranco_top10k.txt").read_text().split())
    return [u for u in dict.fromkeys(out) if etld1(urlsplit(u).hostname or "") not in tranco]


def main() -> None:
    rows: list[tuple[str, str, str, str]] = []
    op = openphish_urls()
    print("openphish", len(op))
    rows += [(u, "fraud", "openphish", "openphish.com community feed (GitHub mirror)") for u in op]
    u42 = unit42_urls()
    print("unit42", len(u42))
    rows += [(u, "fraud", "smishing_ioc", "Unit 42 smishing IOCs 2025") for u in u42]
    rows += [(u, "fraud", "smishing_ioc", "Resecurity Dubai Police Smishing Triad IOCs (Dec 2024)") for u in UAE_IOCS]
    rows += [(u, "fraud", "uae_synthetic", "team-written UAE lure pattern (synthetic)") for u in UAE_SYNTHETIC]

    official = asyncio.run(crawl_all(UAE_OFFICIAL_SEEDS, 5)) + UAE_OFFICIAL_FIXED
    print("uae_official", len(official))
    rows += [(u, "legit", "uae_official", "crawled from official site" if u not in UAE_OFFICIAL_FIXED else "known official deep page") for u in official]
    business = asyncio.run(crawl_all(UAE_BUSINESS_SEEDS, 2))
    print("uae_business", len(business))
    rows += [(u, "legit", "uae_business", "crawled from legitimate UAE business site") for u in business]

    hosting = set((ROOT / "data" / "free_hosting.txt").read_text().split()) | set((ROOT / "data" / "shorteners.txt").read_text().split())
    tranco = [d for d in (ROOT / "data" / "tranco_top10k.txt").read_text().split() if d not in hosting]
    sample = random.sample(tranco, 140)
    tr = asyncio.run(crawl_all(["https://" + d for d in sample], 1))
    print("tranco", len(tr))
    rows += [(u, "legit", "tranco", "crawled from Tranco top-10k site") for u in tr]

    rows += [(u, "legit", "legit_hosting", "well-known organisation site on a free hosting platform") for u in LEGIT_HOSTING]

    seen, final = set(), []
    for r in rows:
        if r[0] not in seen and len(r[0]) < 2000:
            seen.add(r[0])
            final.append(r)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label", "slice", "source"])
        w.writerows(final)
    counts: dict[str, int] = {}
    for r in final:
        counts[r[2]] = counts.get(r[2], 0) + 1
    print(json.dumps(counts, indent=1), "total", len(final), file=sys.stderr)


if __name__ == "__main__":
    main()
