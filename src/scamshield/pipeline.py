"""ScamShield inference: one object that loads the trained artifacts and analyses messages."""
from __future__ import annotations

import json
import platform
import time

import joblib
import numpy as np

from . import genai
from .advice import build_advice
from .config import ARTIFACTS_DIR, env_bool
from .ensemble import decide_level, stack_row
from .features import Prepared, prepare
from .models import neural, url_model
from .signals import CRITICAL, HIGH, MED, SAFE
from .urls import defang

_SEV_ORDER = {CRITICAL: 0, HIGH: 1, MED: 2, SAFE: 3}
# Function words are never shown as "suspicious words" even if removing them shifts the score.
_STOPWORDS = set("""a an the and or but if of to in on at by for from with as is are was were be been am i
me my you your yours we our us he she it its they them this that these those there here not no do does did
have has had will would can could should may might shall so than then too very just only also all any
some such into out up down over about after before again more most other own same s t""".split())


class ArchMismatchError(RuntimeError):
    pass


class ScamShield:
    def __init__(self, artifacts_dir=ARTIFACTS_DIR, allow_arch_mismatch: bool | None = None):
        self.meta = json.loads((artifacts_dir / "meta.json").read_text())
        if allow_arch_mismatch is None:
            allow_arch_mismatch = env_bool("SS_ALLOW_ARCH_MISMATCH", False)
        here = platform.machine()
        if self.meta["trained_on_arch"] != here and not allow_arch_mismatch:
            raise ArchMismatchError(
                f"Artifacts were trained on {self.meta['trained_on_arch']} but this machine is {here}. "
                "Retrain here (make train) or set SS_ALLOW_ARCH_MISMATCH=1.")
        self.lr = joblib.load(artifacts_dir / "text_lr.joblib")
        self.url_hgb = joblib.load(artifacts_dir / "url_hgb.joblib")
        self.url_char = joblib.load(artifacts_dir / "url_char.joblib")
        self.type_model = joblib.load(artifacts_dir / "type_lr.joblib")
        self.stacker = joblib.load(artifacts_dir / "stacker.joblib")
        self.use_cnn = bool(self.meta.get("use_cnn")) and neural.TORCH_AVAILABLE
        self.cnn = neural.load(artifacts_dir / "text_cnn.pt") if self.use_cnn else None
        self.thresholds = self.meta["thresholds"]
        self.version = self.meta["version"]

    # ------------------------------------------------------------- scoring
    def _text_probs(self, texts: list[str]) -> tuple[np.ndarray, np.ndarray | None]:
        p_lr = self.lr.predict_proba(texts)[:, 1]
        p_cnn = neural.predict_proba(self.cnn, texts) if self.use_cnn else None
        return p_lr, p_cnn

    def _url_prob(self, hosts: list[str]) -> float | None:
        return float(url_model.score_hosts(hosts, self.url_hgb, self.url_char).max()) if hosts else None

    def _stack(self, p_lr, p_cnn, p_url, signals) -> np.ndarray:
        rows = [stack_row(float(a), (float(p_cnn[i]) if p_cnn is not None else None), p_url, signals, self.use_cnn)
                for i, a in enumerate(p_lr)]
        return self.stacker.predict_proba(np.array(rows))[:, 1]

    def score_batch(self, preps: list[Prepared]) -> list[dict]:
        """Vectorised scoring used by evaluation and benchmarks (no explanations)."""
        p_lr, p_cnn = self._text_probs([p.model_text for p in preps])
        all_hosts = sorted({h for p in preps for h in p.hosts})
        host_p = dict(zip(all_hosts, url_model.score_hosts(all_hosts, self.url_hgb, self.url_char))) if all_hosts else {}
        rows, p_urls = [], []
        for i, p in enumerate(preps):
            p_url = max(float(host_p[h]) for h in p.hosts) if p.hosts else None
            p_urls.append(p_url)
            rows.append(stack_row(float(p_lr[i]), float(p_cnn[i]) if p_cnn is not None else None, p_url, p.signals, self.use_cnn))
        scores = self.stacker.predict_proba(np.array(rows))[:, 1]
        return [{"score": float(s), "level": decide_level(float(s), p.signals, self.thresholds),
                 "p_text_lr": float(p_lr[i]), "p_text_cnn": float(p_cnn[i]) if p_cnn is not None else None,
                 "p_url": p_urls[i]} for i, (s, p) in enumerate(zip(scores, preps))]

    # ------------------------------------------------------------- explanations
    def _word_impacts(self, prep: Prepared, base: float, p_url) -> list[dict]:
        """Occlusion: drop each distinct word and measure how much the ensemble score falls."""
        words = prep.model_text.split()
        candidates = sorted({w for w in words if not w.startswith("__") and len(w.strip(".,!?:;")) > 1
                             and w.strip(".,!?:;\"'()").lower() not in _STOPWORDS})[:80]
        if not candidates:
            return []
        variants = [" ".join(w for w in words if w != c) for c in candidates]
        p_lr, p_cnn = self._text_probs(variants)
        scores = self._stack(p_lr, p_cnn, p_url, prep.signals)
        impacts = [(c.strip(".,!?:;\"'()"), base - s) for c, s in zip(candidates, scores)]
        impacts = [(w, d) for w, d in impacts if d > 0.01 and w]
        return [{"word": w, "impact": round(float(d), 3)} for w, d in sorted(impacts, key=lambda t: -t[1])[:5]]

    def _scam_type(self, prep: Prepared, level: str) -> str | None:
        if level == "LOW":
            return None
        typed = sorted((s for s in prep.signals if s.scam_type), key=lambda s: (_SEV_ORDER[s.severity], -s.weight))
        if typed:
            return typed[0].scam_type
        probs = self.type_model.predict_proba([prep.model_text])[0]
        best = int(np.argmax(probs))
        return str(self.type_model.classes_[best]) if probs[best] >= 0.4 else None

    @staticmethod
    def _reasons(prep: Prepared, level: str, p_url, highlights: list[dict]) -> list[dict]:
        sigs = sorted((s for s in prep.signals if s.severity != SAFE), key=lambda s: (_SEV_ORDER[s.severity], -s.weight))
        out = [{"id": s.id, "text": s.reason} for s in sigs[:3]]
        if level != "LOW" and p_url is not None and p_url >= 0.8 and not any(r["id"] in {"R04", "R04B"} for r in out) and len(out) < 3:
            out.append({"id": "AI_URL", "text": "The AI link checker says this web address looks like known phishing sites."})
        if level != "LOW" and highlights and len(out) < 3:
            words = ", ".join(f"'{h['word']}'" for h in highlights[:3])
            out.append({"id": "AI_TEXT", "text": f"The AI model found scam-like wording, especially {words}."})
        if level == "LOW":
            safe = [s for s in prep.signals if s.severity == SAFE]
            out = [{"id": s.id, "text": s.reason} for s in safe] or [{"id": "NONE", "text": "No common scam warning signs were found."}]
        return out

    # ------------------------------------------------------------- public API
    def analyze(self, text: str, explain_words: bool = True) -> dict:
        t0 = time.perf_counter()
        prep = prepare(text)
        p_lr, p_cnn = self._text_probs([prep.model_text])
        p_url = self._url_prob(prep.hosts)
        score = float(self._stack(p_lr, p_cnn, p_url, prep.signals)[0])
        level = decide_level(score, prep.signals, self.thresholds)
        highlights = self._word_impacts(prep, score, p_url) if explain_words and level != "LOW" else []
        scam_type = self._scam_type(prep, level)
        reasons = self._reasons(prep, level, p_url, highlights)
        return {
            "risk_level": level,
            "risk_score": round(score, 4),
            "scam_type": scam_type,
            "reasons": reasons,
            "advice": build_advice(level, scam_type),
            "highlights": highlights,
            "signals": {
                "p_text_lr": round(float(p_lr[0]), 4),
                "p_text_cnn": round(float(p_cnn[0]), 4) if p_cnn is not None else None,
                "p_url": round(p_url, 4) if p_url is not None else None,
                "urls": [defang(u) for u in prep.urls],
                "rules": [s.id for s in prep.signals],
                "guardrail": any(s.severity == CRITICAL for s in prep.signals),
            },
            "model_version": self.version,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            "disclaimer": "Automated check. It can be wrong.",
        }

    def explain(self, text: str, result: dict | None = None) -> dict:
        """GenAI explanation (hosted LLM + RAG) for an analysed message, with template fallback.

        Privacy: the LLM receives the scrubbed text (links/phones/amounts/numbers -> placeholders)."""
        result = result or self.analyze(text, explain_words=True)
        scrubbed = prepare(text).model_text.replace("__url__", "[link]").replace("__phone__", "[phone]") \
            .replace("__amt__", "[amount]").replace("__email__", "[email]").replace("__num__", "[number]")
        reasons = [r["text"] for r in result["reasons"]]
        return genai.explain(scrubbed, result["risk_level"], result["scam_type"], reasons)
