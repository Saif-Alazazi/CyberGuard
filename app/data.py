"""Loads the curated data files once and exposes lookup helpers."""
import json
import re
import unicodedata
from functools import lru_cache

import tldextract

from app.config import DATA_DIR

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

AR_DIACRITICS = re.compile(r"[ؐ-ًؚ-ٰٟۖ-ۭـ]")
AR_MAP = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي", "ی": "ي", "ک": "ك", "ة": "ه",
                        **{c: str(i) for i, c in enumerate("٠١٢٣٤٥٦٧٨٩")},
                        **{c: str(i) for i, c in enumerate("۰۱۲۳۴۵۶۷۸۹")}})


def normalize_text(text: str) -> str:
    """NFKC (full-width -> ASCII), Arabic normalisation, lower case."""
    text = unicodedata.normalize("NFKC", text)
    text = AR_DIACRITICS.sub("", text).translate(AR_MAP)
    return text.lower()


def split_host(host: str):
    """(subdomain, domain label, public suffix, registrable eTLD+1)."""
    ext = _EXTRACT(host)
    reg = ext.registered_domain or host
    return ext.subdomain, ext.domain, ext.suffix, reg


def _lines(name: str) -> list[str]:
    return [l.strip().lower() for l in (DATA_DIR / name).read_text(encoding="utf-8").splitlines() if l.strip()]


class Data:
    def __init__(self) -> None:
        raw = json.loads((DATA_DIR / "uae_brands.json").read_text(encoding="utf-8"))
        self.brands = {b["id"]: b for b in raw["brands"]}
        glob = json.loads((DATA_DIR / "global_brands.json").read_text(encoding="utf-8"))
        self.global_brands = {b["id"]: b for b in glob["brands"]}
        self.generic_tokens = raw["generic_tokens"]
        self.domain_brand: dict[str, str] = {}
        for b in self.brands.values():
            for d in b["domains"]:
                self.domain_brand[d] = b["id"]
        self.global_domain_brand: dict[str, str] = {}
        for b in self.global_brands.values():
            for d in b["domains"]:
                self.global_domain_brand[d] = b["id"]
        self.shorteners = set(_lines("shorteners.txt"))
        self.hosting = _lines("free_hosting.txt")
        self.abused_tlds = set(_lines("abused_tlds.txt"))
        self.tranco = {d: i + 1 for i, d in enumerate(_lines("tranco_top10k.txt"))}
        self.lures = json.loads((DATA_DIR / "lures_en_ar.json").read_text(encoding="utf-8"))
        self.confusables = json.loads((DATA_DIR / "confusables_min.json").read_text(encoding="utf-8"))["map"]
        fav = DATA_DIR / "favicon_hashes.json"
        self.favicons = json.loads(fav.read_text(encoding="utf-8"))["hashes"] if fav.exists() else {}
        self.helplines: dict[str, list[dict]] = {}
        for b in self.brands.values():
            for h in b["helplines"]:
                self.helplines.setdefault(h["number"], []).append({"brand": b["id"], **h})
        # Token -> brand id, for UAE and global brands
        self.tokens: list[tuple[str, str, str]] = []  # (token, brand_id, scope)
        for b in self.brands.values():
            for t in b["tokens"]:
                self.tokens.append((t.replace("-", ""), b["id"], "uae"))
        for b in self.global_brands.values():
            for t in b["tokens"]:
                self.tokens.append((t.replace("-", ""), b["id"], "global"))
        self.name_patterns: list[tuple[str, str]] = []  # (normalised name, brand_id)
        for b in self.brands.values():
            for n in [b["name_ar"], *b.get("aliases_ar", []), *b.get("aliases_en", [])]:
                n = normalize_text(n).strip()
                if len(n) >= 4:
                    self.name_patterns.append((n, b["id"]))

    def brand(self, brand_id: str) -> dict | None:
        return self.brands.get(brand_id) or self.global_brands.get(brand_id)

    def official_brand(self, registrable: str) -> str | None:
        return self.domain_brand.get(registrable)

    def global_official(self, registrable: str) -> str | None:
        return self.global_domain_brand.get(registrable)

    def hosting_suffix(self, host: str) -> str | None:
        for suf in self.hosting:
            if host == suf or host.endswith("." + suf):
                return suf
        return None

    def is_shortener(self, host: str) -> bool:
        return split_host(host)[3] in self.shorteners or host in self.shorteners

    def tranco_rank(self, registrable: str) -> int | None:
        if registrable in self.shorteners:
            return None
        return self.tranco.get(registrable)


@lru_cache(maxsize=1)
def data() -> Data:
    return Data()
