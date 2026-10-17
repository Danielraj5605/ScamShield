"""Latency and throughput benchmark. Run it ON the LinuxONE server for the numbers you report."""
from __future__ import annotations

import json
import random
import statistics
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

from .config import PROCESSED_DIR, REPORTS_DIR, SEED
from .features import prepare
from .pipeline import ScamShield
from .platform_info import fingerprint


def _pct(values, q):
    v = sorted(values)
    return round(v[min(len(v) - 1, int(q * len(v)))], 3) if v else None


def _summary(lat_ms: list[float], wall_s: float) -> dict:
    return {"n": len(lat_ms), "p50_ms": _pct(lat_ms, 0.5), "p95_ms": _pct(lat_ms, 0.95), "p99_ms": _pct(lat_ms, 0.99),
            "mean_ms": round(statistics.mean(lat_ms), 3) if lat_ms else None,
            "throughput_msgs_per_s": round(len(lat_ms) / wall_s, 1) if wall_s else None}


def run_bench(n: int = 2000, url: str | None = None, concurrency: int = 4, log=print) -> dict:
    msgs = pd.read_csv(PROCESSED_DIR / "messages.csv", keep_default_na=False)
    pool = msgs[msgs.split.isin(["test", "test_india"])]["text"].tolist()
    rng = random.Random(SEED)
    sample = [rng.choice(pool) for _ in range(n)]
    ss = ScamShield()
    for t in sample[:20]:  # warm-up
        ss.analyze(t, explain_words=False)

    res = {"platform": fingerprint(), "model_version": ss.version, "neural_model": ss.use_cnn}

    lat, t0 = [], time.perf_counter()
    for t in sample:
        s = time.perf_counter()
        ss.analyze(t, explain_words=False)
        lat.append((time.perf_counter() - s) * 1000)
    res["in_process_single"] = _summary(lat, time.perf_counter() - t0)
    log(f"[bench] single message, no explanation: {res['in_process_single']}")

    k = min(300, n)
    lat, t0 = [], time.perf_counter()
    for t in sample[:k]:
        s = time.perf_counter()
        ss.analyze(t, explain_words=True)
        lat.append((time.perf_counter() - s) * 1000)
    res["in_process_with_word_explanations"] = _summary(lat, time.perf_counter() - t0)
    log(f"[bench] single message + word explanations: {res['in_process_with_word_explanations']}")

    t0 = time.perf_counter()
    for i in range(0, len(sample), 256):
        ss.score_batch([prepare(t) for t in sample[i: i + 256]])
    wall = time.perf_counter() - t0
    res["batch_256"] = {"n": len(sample), "throughput_msgs_per_s": round(len(sample) / wall, 1)}
    log(f"[bench] batch scoring: {res['batch_256']}")

    if url:
        endpoint = url.rstrip("/") + "/api/analyze"

        def call(text):
            body = json.dumps({"text": text}).encode()
            req = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"})
            s = time.perf_counter()
            with urllib.request.urlopen(req, timeout=30) as r:
                r.read()
            return (time.perf_counter() - s) * 1000

        m = min(1000, n)
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            lat = list(ex.map(call, sample[:m]))
        res["http"] = {**_summary(lat, time.perf_counter() - t0), "concurrency": concurrency, "endpoint": endpoint}
        log(f"[bench] HTTP x{concurrency}: {res['http']}")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"bench_{res['platform']['arch']}.json"
    path.write_text(json.dumps(res, indent=2))
    log(f"[bench] wrote {path.name}")
    return res
