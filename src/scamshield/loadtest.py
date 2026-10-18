"""Provider-side load test: score many messages across 1..N worker processes.

This is the measured version of the "a bank or telecom scans messages at volume" argument.
It reports throughput on the machine it runs on, so run it on the LinuxONE server for the
numbers you quote. Messages are generated from the synthetic templates with a seed that
differs from training, so they are new messages, but they are labelled as synthetic.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import time

from .config import REPORTS_DIR
from .platform_info import fingerprint

LOAD_SEED_BASE = 20261018   # differs from the training seed on purpose
CHUNK = 256
_ss = None


def _init() -> None:
    """Runs once in each worker: load the models and keep PyTorch to one thread per worker."""
    global _ss
    from .pipeline import ScamShield
    _ss = ScamShield()
    try:
        import torch
        torch.set_num_threads(1)
    except ImportError:
        pass


def _score(chunk: list[str]) -> dict:
    from .features import prepare
    res = _ss.score_batch([prepare(t) for t in chunk])
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in res:
        counts[r["level"]] += 1
    return counts


def build_messages(n: int) -> tuple[list[str], int]:
    """Return n messages and how many of them are unique. Cycles only if the unique pool is too small."""
    from .data import load_synthetic
    seen, pool = set(), []
    for k in range(40):
        for text in load_synthetic(LOAD_SEED_BASE + k)["text"]:
            if text not in seen:
                seen.add(text)
                pool.append(text)
        if len(pool) >= n:
            break
    unique = min(len(pool), n)
    msgs = (pool * (n // len(pool) + 1))[:n]
    return msgs, unique


def run_loadtest(n: int = 10000, workers: tuple[int, ...] = (1, 2, 3), log=print) -> dict:
    cpus = os.cpu_count() or 1
    workers = tuple(w for w in workers if w <= cpus) or (1,)
    msgs, unique = build_messages(n)
    chunks = [msgs[i: i + CHUNK] for i in range(0, len(msgs), CHUNK)]
    log(f"[loadtest] {n} messages ({unique} unique), {len(chunks)} chunks of {CHUNK}, cpus={cpus}")
    ctx = mp.get_context("spawn")
    runs = []
    for w in workers:
        with ctx.Pool(w, initializer=_init) as pool:
            pool.map(_score, [chunks[0]] * w)            # warm-up: models loaded, caches filled
            t0 = time.perf_counter()
            parts = pool.map(_score, chunks, chunksize=1)
            wall = time.perf_counter() - t0
        levels = {k: sum(p[k] for p in parts) for k in ("HIGH", "MEDIUM", "LOW")}
        run = {"workers": w, "seconds": round(wall, 2), "messages_per_second": round(n / wall, 1), "levels": levels}
        runs.append(run)
        log(f"[loadtest] workers={w}: {run['messages_per_second']} messages/s ({run['seconds']} s)")
    base = runs[0]["messages_per_second"]
    for r in runs:
        r["speedup_vs_1_worker"] = round(r["messages_per_second"] / base, 2)
    report = {"platform": fingerprint(), "messages": n, "unique_messages": unique,
              "message_source": "synthetic templates, generated with seeds different from training",
              "includes": "text cleaning, all models, ensemble and decision (no word-level explanations)",
              "torch_threads_per_worker": 1, "runs": runs}
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"loadtest_{report['platform']['arch']}.json"
    path.write_text(json.dumps(report, indent=2))
    log(f"[loadtest] wrote {path.name}")
    return report
