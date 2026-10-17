"""Generative-AI explainer: hosted LLM + retrieval-augmented generation (RAG), with a safe fallback.

Design rules:
* The classifier ensemble (running on IBM LinuxONE) decides the risk level. The LLM only explains that
  decision in plain language, grounded in retrieved knowledge-base cards (kb/*.md). It never changes
  the verdict.
* The LLM is reached through any OpenAI-compatible chat API on a free tier (e.g. Groq or Google
  Gemini's OpenAI-compatible endpoint). Configure it with SS_LLM_BASE_URL / SS_LLM_API_KEY /
  SS_LLM_MODEL. Nothing is downloaded or run locally.
* Privacy: only the *scrubbed* message is sent (links, phone numbers, amounts and numbers replaced by
  placeholders), plus the detected warning signs.
* Output is validated (no links, no unknown phone numbers, no "this is safe" on a HIGH verdict).
  If the API is not configured, unreachable, slow or fails validation, a template explanation is
  returned instead, so the product works fully offline.
"""
from __future__ import annotations

import json
import math
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache

from .advice import TYPE_LABELS
from .config import KB_DIR, env, env_bool, env_float, env_int

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = set("a an the and or of to in on for is are be you your it this that with by at from as our we".split())


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]


@dataclass
class Card:
    id: str
    title: str
    types: list[str]
    body: str


@lru_cache(maxsize=1)
def load_kb() -> list[Card]:
    cards = []
    for path in sorted(KB_DIR.glob("*.md")):
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        title = lines[0].lstrip("# ").strip()
        types = [t.strip() for t in lines[1].split(":", 1)[1].split(",")] if lines[1].startswith("types:") else []
        cards.append(Card(path.stem, title, types, " ".join(lines[2:]).strip()))
    return cards


class BM25:
    """Okapi BM25 over the knowledge-base cards (pure Python; the KB is tiny)."""

    def __init__(self, docs: list[str], k1: float = 1.5, b: float = 0.75):
        self.docs = [_tokens(d) for d in docs]
        self.k1, self.b = k1, b
        self.avg = sum(map(len, self.docs)) / max(len(self.docs), 1)
        df = Counter(t for d in self.docs for t in set(d))
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}
        self.tf = [Counter(d) for d in self.docs]

    def scores(self, query: str) -> list[float]:
        q = _tokens(query)
        out = []
        for tf, d in zip(self.tf, self.docs):
            s = 0.0
            for t in q:
                if t in tf:
                    s += self.idf[t] * tf[t] * (self.k1 + 1) / (tf[t] + self.k1 * (1 - self.b + self.b * len(d) / self.avg))
            out.append(s)
        return out


@lru_cache(maxsize=1)
def _index() -> BM25:
    return BM25([f"{c.title} {c.body}" for c in load_kb()])


def retrieve(query: str, scam_type: str | None, k: int = 2) -> list[Card]:
    cards = load_kb()
    scores = _index().scores(query)
    # Boost cards tagged with the detected scam type; the generic "report" card is always appended.
    ranked = sorted(range(len(cards)), key=lambda i: -(scores[i] + (5.0 if scam_type and scam_type in cards[i].types else 0)))
    picked = [cards[i] for i in ranked if cards[i].id != "report"][:k]
    report = [c for c in cards if c.id == "report"]
    return picked + report


# ------------------------------------------------------------------ LLM client
class LLMClient:
    def __init__(self):
        self.base_url = env("SS_LLM_BASE_URL", "").rstrip("/")
        self.api_key = env("SS_LLM_API_KEY", "")
        self.model = env("SS_LLM_MODEL", "")
        self.enabled = env_bool("SS_LLM_ENABLED", True) and bool(self.base_url and self.model)
        self.timeout = env_float("SS_LLM_TIMEOUT", 20.0)
        self.max_tokens = env_int("SS_LLM_MAX_TOKENS", 200)
        self._available: tuple[float, bool] | None = None

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def available(self) -> bool:
        """Cached (30 s) reachability probe so the UI can show whether GenAI is on."""
        if not self.enabled:
            return False
        now = time.time()
        if self._available and now - self._available[0] < 30:
            return self._available[1]
        ok = False
        try:
            req = urllib.request.Request(f"{self.base_url}/models", headers=self._headers())
            with urllib.request.urlopen(req, timeout=5) as r:
                ok = r.status == 200
        except (urllib.error.URLError, OSError, ValueError):
            ok = False
        self._available = (now, ok)
        return ok

    def chat(self, system: str, user: str, max_tokens: int | None = None, temperature: float = 0.2) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": temperature,
            "max_tokens": max_tokens or self.max_tokens,
            "stream": False,
        }).encode()
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body, headers=self._headers())
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read().decode())
        return data["choices"][0]["message"]["content"].strip()


_client: LLMClient | None = None


def client() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client


# ------------------------------------------------------------------ explanation
SYSTEM_PROMPT = (
    "You are ScamShield, a kind assistant that helps elderly and non-technical people understand "
    "whether a text message is a scam. A separate AI system has ALREADY decided the risk level; you must "
    "not change it or contradict it. Explain the decision using ONLY the detected warning signs and the "
    "safety facts provided. Rules: write {n} short, simple sentences in plain English; no links or website "
    "addresses; no phone numbers except 1930; never tell the reader to call or click anything from the "
    "message; do not invent facts."
)

_BAD_PATTERNS = [
    re.compile(r"https?://|www\.|\b[a-z0-9-]+\.(com|in|top|xyz|ly|net|org)\b", re.I),
]
_SAFE_CLAIM = re.compile(r"\b(is|looks|seems|appears)\s+(to be\s+)?(safe|genuine|legitimate|real)\b", re.I)


def validate(text: str, level: str) -> str | None:
    """Return a reason string if the LLM output must be rejected, else None."""
    if not text or len(text) > 900:
        return "empty_or_too_long"
    if any(p.search(text) for p in _BAD_PATTERNS):
        return "contains_link"
    phones = [re.sub(r"\D", "", m) for m in re.findall(r"\+?\d[\d\s-]{5,}\d", text)]
    if any(p and p != "1930" for p in phones):
        return "contains_phone_number"
    if level == "HIGH" and _SAFE_CLAIM.search(text) and not re.search(r"\bnot\s+(safe|genuine|legitimate|real)", text, re.I):
        return "contradicts_verdict"
    return None


def template_explanation(level: str, scam_type: str | None, reasons: list[str]) -> str:
    if level == "LOW":
        return ("We didn't find the usual warning signs of a scam in this message. Still, if anything feels wrong, check with someone you trust.")
    kind = TYPE_LABELS.get(scam_type or "", "")
    head = (f"This looks like a {kind} scam." if kind and level == "HIGH"
            else "This message has warning signs of a scam." if level == "HIGH"
            else "Be careful with this message.")
    body = " ".join(reasons[:2])
    return f"{head} {body}".strip()


def build_user_prompt(message: str, level: str, scam_type: str | None, reasons: list[str], cards: list[Card]) -> str:
    facts = "\n".join(f"- {c.title}: {c.body}" for c in cards)
    signs = "\n".join(f"- {r}" for r in reasons) or "- (no specific warning signs)"
    kind = TYPE_LABELS.get(scam_type or "", "unknown")
    return (f"Message (links removed):\n\"\"\"{message[:600]}\"\"\"\n\n"
            f"Risk level decided by the AI system: {level}\nLikely scam type: {kind}\n"
            f"Detected warning signs:\n{signs}\n\nSafety facts:\n{facts}\n\n"
            f"Explain to the reader why this message got this risk level and what they should do.")


def explain(message_defanged: str, level: str, scam_type: str | None, reasons: list[str]) -> dict:
    """LLM explanation grounded in retrieved KB cards; falls back to a template."""
    cards = retrieve(" ".join([message_defanged, scam_type or ""] + reasons), scam_type)
    fallback = {"text": template_explanation(level, scam_type, reasons), "source": "template",
                "kb_refs": [c.id for c in cards]}
    llm = client()
    if not llm.available():
        return {**fallback, "llm_status": "unavailable"}
    system = SYSTEM_PROMPT.format(n="2 to 3")
    t0 = time.perf_counter()
    try:
        text = llm.chat(system, build_user_prompt(message_defanged, level, scam_type, reasons, cards))
    except (urllib.error.URLError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        return {**fallback, "llm_status": f"error:{type(exc).__name__}"}
    problem = validate(text, level)
    if problem:
        return {**fallback, "llm_status": f"rejected:{problem}"}
    return {"text": text, "source": f"llm:{llm.model}", "kb_refs": [c.id for c in cards],
            "llm_status": "ok", "llm_latency_ms": round((time.perf_counter() - t0) * 1000)}


# ------------------------------------------------------------------ zero-shot LLM baseline
JUDGE_PROMPT = (
    "You classify SMS/WhatsApp messages. Answer with exactly one word: SCAM if the message is spam, phishing, "
    "a scam or fraud attempt; SAFE otherwise."
)


def llm_classify(message: str) -> int | None:
    """Zero-shot Granite baseline used in evaluation ("why not just ask an LLM?"). 1=scam, 0=safe, None=unparseable."""
    out = client().chat(JUDGE_PROMPT, f"Message:\n\"\"\"{message[:600]}\"\"\"\nAnswer:", max_tokens=4, temperature=0.0)
    word = out.strip().upper()
    if word.startswith("SCAM"):
        return 1
    if word.startswith("SAFE"):
        return 0
    return None
