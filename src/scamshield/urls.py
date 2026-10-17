"""Find links in a message and parse their hosts. Links are never fetched or visited."""
from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import urlsplit

from .config import load_lines

_TRAILING = ".,;:!?)]}'\"…"


@lru_cache(maxsize=1)
def _patterns():
    tlds = "|".join(sorted(load_lines("common_tlds.txt"), key=len, reverse=True))
    explicit = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
    bare = re.compile(
        rf"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{tlds}))(?![\w-])(/[^\s<>\"']*)?",
        re.I,
    )
    return explicit, bare


@lru_cache(maxsize=1)
def _multi_suffixes() -> frozenset[str]:
    return frozenset(load_lines("public_suffixes.txt"))


def extract_urls(norm_text: str) -> list[str]:
    """Return URLs/bare domains found in normalised text, in order, de-duplicated."""
    explicit, bare = _patterns()
    found: list[str] = []
    spans: list[tuple[int, int]] = []
    for m in explicit.finditer(norm_text):
        found.append(m.group(0).rstrip(_TRAILING))
        spans.append(m.span())
    for m in bare.finditer(norm_text):
        if any(s <= m.start() < e for s, e in spans):
            continue
        candidate = m.group(0).rstrip(_TRAILING)
        host = candidate.split("/", 1)[0]
        labels = host.split(".")
        # Skip things like "e.g" / "a.m" / version numbers; keep real-looking hosts.
        if len(labels) < 2 or labels[-2].isdigit() or len(host) < 4:
            continue
        found.append(candidate)
    seen, out = set(), []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def host_of(url: str) -> str:
    """Hostname (lower-case, no port, no leading 'www.')."""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        host = ""
    return host[4:] if host.startswith("www.") else host


def registered_domain(host: str) -> str:
    """'a.b.sbi.co.in' -> 'sbi.co.in'; 'login.sbi-kyc.top' -> 'sbi-kyc.top'."""
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _multi_suffixes():
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def path_of(url: str) -> str:
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return (parts.path or "") + ("?" + parts.query if parts.query else "")


def defang(url: str) -> str:
    """Make a URL non-clickable for display: 'http://a.top/x' -> 'hxxp://a[.]top/x'."""
    return url.replace("http", "hxxp").replace(".", "[.]")
