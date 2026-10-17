"""Lexical hostname features for the URL model, plus brand-impersonation checks.

The URL model scores the *hostname only*. In the PhiUSIIL training data every legitimate URL
is a bare homepage while phishing URLs carry paths, so a model fed full URLs would learn
"has a path = phishing". Path keywords are handled separately as signals (see signals.py).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache

from .config import load_json, load_lines
from .urls import registered_domain

FEATURE_NAMES = [
    "len_host", "n_labels", "len_reg_label", "n_digits", "digit_ratio", "n_hyphens",
    "is_ip", "has_punycode", "tld_suspicious", "tld_len", "is_shortener", "entropy",
    "longest_digit_run", "vowel_ratio", "longest_label", "kw_in_host", "brand_mismatch",
    "brand_edit_distance",
]

_HOST_KEYWORDS = ("login", "verify", "secure", "update", "kyc", "account", "bank", "support",
                  "reward", "refund", "wallet", "auth", "confirm", "signin", "billing", "help")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@lru_cache(maxsize=1)
def _brands() -> dict[str, list[str]]:
    return {k: v for k, v in load_json("brands.json").items() if not k.startswith("_")}


@lru_cache(maxsize=1)
def _official_domains() -> frozenset[str]:
    return frozenset(d for ds in _brands().values() for d in ds)


@lru_cache(maxsize=1)
def _suspicious_tlds() -> frozenset[str]:
    return frozenset(load_lines("suspicious_tlds.txt"))


@lru_cache(maxsize=1)
def shorteners() -> frozenset[str]:
    return frozenset(load_lines("shorteners.txt"))


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@lru_cache(maxsize=200_000)
def brand_impersonation(host: str) -> tuple[str, str] | None:
    """Return (brand, registered_domain) if the host mentions or imitates a brand it doesn't belong to."""
    reg = registered_domain(host)
    if not reg or reg in _official_domains() or any(host.endswith("." + d) for d in _official_domains()):
        return None
    tokens = re.split(r"[.\-_]", host)
    for brand, domains in _brands().items():
        for tok in tokens:
            if tok == brand or (len(brand) >= 4 and brand in tok) or (
                len(brand) == 3 and (tok.startswith(brand) or tok.endswith(brand))
            ):
                return brand, reg
    # Typosquats of an official domain's first label, e.g. "hdfcbnak.com" vs "hdfcbank.com".
    reg_label = reg.split(".")[0]
    if len(reg_label) >= 5:
        for brand, domains in _brands().items():
            for d in domains:
                off_label = d.split(".")[0]
                if (len(off_label) >= 5 and reg_label != off_label and abs(len(off_label) - len(reg_label)) <= 1
                        and levenshtein(reg_label, off_label) <= 1):
                    return brand, reg
    return None


@lru_cache(maxsize=1)
def _official_labels() -> tuple[str, ...]:
    return tuple(sorted({d.split(".")[0] for d in _official_domains()}))


@lru_cache(maxsize=200_000)
def _min_brand_distance(reg_label: str) -> int:
    best = 10
    for off in _official_labels():
        if abs(len(off) - len(reg_label)) >= best:  # edit distance >= length difference
            continue
        best = min(best, levenshtein(reg_label, off))
    return best


def url_features(host: str) -> list[float]:
    """Feature vector for one hostname (already lower-case, no 'www.'). Order == FEATURE_NAMES."""
    host = host.lower().strip(".")
    reg = registered_domain(host)
    labels = host.split(".") if host else [""]
    reg_label = reg.split(".")[0] if reg else ""
    tld = labels[-1] if labels else ""
    digits = sum(ch.isdigit() for ch in host)
    letters = [ch for ch in host if ch.isalpha()]
    runs = re.findall(r"\d+", host)
    return [
        len(host),
        len(labels),
        len(reg_label),
        digits,
        digits / max(len(host), 1),
        host.count("-"),
        float(bool(_IP_RE.match(host))),
        float("xn--" in host),
        float(tld in _suspicious_tlds()),
        len(tld),
        float(reg in shorteners() or host in shorteners()),
        _entropy(host.replace(".", "")),
        max((len(r) for r in runs), default=0),
        sum(ch in "aeiou" for ch in letters) / max(len(letters), 1),
        max((len(l) for l in labels), default=0),
        float(any(k in host for k in _HOST_KEYWORDS)),
        float(brand_impersonation(host) is not None),
        _min_brand_distance(reg_label) if reg_label else 10,
    ]
