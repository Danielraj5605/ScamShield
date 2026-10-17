"""One preparation step shared by training, evaluation and serving (prevents train/serve skew)."""
from __future__ import annotations

from dataclasses import dataclass

from .normalize import normalize, placeholderize
from .signals import Signal, detect_signals
from .urls import extract_urls, host_of


@dataclass
class Prepared:
    original: str
    norm: str
    urls: list[str]
    hosts: list[str]
    model_text: str  # placeholderised text fed to the text models
    signals: list[Signal]


def prepare(text: str) -> Prepared:
    norm = normalize(text)
    urls = extract_urls(norm)
    bare = [u for u in urls if not u.startswith(("http", "www."))]
    hosts = [h for h in (host_of(u) for u in urls) if h]
    return Prepared(text, norm, urls, hosts, placeholderize(norm, bare), detect_signals(norm, urls))
