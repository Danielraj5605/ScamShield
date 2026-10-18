"""Score a hand-collected blind test set.

Ask people who have not seen the training templates to write or collect messages, label each
one, and save them as a CSV with the columns:  text,label  (label = scam or genuine).
Then run:  python -m scamshield blind path/to/messages.csv

The report states recall and false-alarm rates with 95% Wilson intervals, lists every
mistake, and warns about messages that also appear in the training data.
"""
from __future__ import annotations

import json
import math

import pandas as pd

from .config import PROCESSED_DIR, REPORTS_DIR
from .features import prepare
from .normalize import normalize
from .pipeline import ScamShield
from .platform_info import fingerprint

SCAM = {"scam", "1", "spam", "phishing", "fraud"}
GENUINE = {"genuine", "0", "ham", "legit", "legitimate", "safe"}


def wilson(k: int, n: int, z: float = 1.96) -> list[float | None]:
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return [None, None]
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def load_blind(path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    missing = {"text", "label"} - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing column(s): {', '.join(sorted(missing))}. Expected: text,label")
    df["text"] = df["text"].str.strip()
    df = df[df["text"] != ""].copy()
    labels = df["label"].str.strip().str.lower()
    bad = df[~labels.isin(SCAM | GENUINE)]
    if len(bad):
        raise ValueError(f"{len(bad)} row(s) have a label that is not 'scam' or 'genuine', e.g. {bad['label'].iloc[0]!r}")
    df["y"] = labels.isin(SCAM).astype(int)
    before = len(df)
    df = df.drop_duplicates("text")
    df.attrs["duplicates_removed"] = before - len(df)
    return df


def evaluate_blind(path, log=print) -> dict:
    df = load_blind(path)
    n_scam, n_gen = int(df.y.sum()), int((1 - df.y).sum())
    train_keys = set()
    msgs_csv = PROCESSED_DIR / "messages.csv"
    if msgs_csv.exists():
        train_keys = set(pd.read_csv(msgs_csv, keep_default_na=False)["text"].map(normalize))
    overlap = [t for t in df["text"] if normalize(t) in train_keys]

    ss = ScamShield()
    res = ss.score_batch([prepare(t) for t in df["text"]])
    df["level"] = [r["level"] for r in res]
    df["score"] = [round(r["score"], 3) for r in res]
    pos, neg = df[df.y == 1], df[df.y == 0]
    caught_high, caught_any = int((pos.level == "HIGH").sum()), int((pos.level != "LOW").sum())
    fa_high, fa_any = int((neg.level == "HIGH").sum()), int((neg.level != "LOW").sum())
    report = {
        "platform": {k: fingerprint().get(k) for k in ("arch", "byteorder", "cpus", "python")},
        "model_version": ss.version,
        "file": str(path), "messages": len(df), "scams": n_scam, "genuine": n_gen,
        "duplicates_removed": df.attrs.get("duplicates_removed", 0),
        "also_in_training_data": len(overlap),
        "scams_rated_high": {"count": caught_high, "of": n_scam, "rate": round(caught_high / n_scam, 4) if n_scam else None, "ci95": wilson(caught_high, n_scam)},
        "scams_rated_medium_or_high": {"count": caught_any, "of": n_scam, "rate": round(caught_any / n_scam, 4) if n_scam else None, "ci95": wilson(caught_any, n_scam)},
        "genuine_rated_high": {"count": fa_high, "of": n_gen, "rate": round(fa_high / n_gen, 4) if n_gen else None, "ci95": wilson(fa_high, n_gen)},
        "genuine_rated_medium_or_high": {"count": fa_any, "of": n_gen, "rate": round(fa_any / n_gen, 4) if n_gen else None, "ci95": wilson(fa_any, n_gen)},
        "mistakes": [{"label": "scam" if r.y else "genuine", "rated": r.level, "score": r.score, "text": r.text[:200]}
                     for r in df.itertuples() if (r.y == 1 and r.level == "LOW") or (r.y == 0 and r.level == "HIGH")],
    }
    arch = ss.meta["trained_on_arch"]
    out = REPORTS_DIR / f"blind_{arch}.json"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    log(f"[blind] {len(df)} messages ({n_scam} scam, {n_gen} genuine)")
    if overlap:
        log(f"[blind] WARNING: {len(overlap)} message(s) also appear in the training data. Remove them for a fair test.")
    s, g = report["scams_rated_high"], report["genuine_rated_high"]
    log(f"[blind] scams rated high risk: {s['count']}/{s['of']} ({s['rate']}), 95% CI {s['ci95']}")
    log(f"[blind] genuine rated high risk: {g['count']}/{g['of']} ({g['rate']}), 95% CI {g['ci95']}")
    log(f"[blind] {len(report['mistakes'])} mistake(s) listed in reports/{out.name}")
    return report
