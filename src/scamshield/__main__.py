"""Command-line entry point: python -m scamshield <command>.

Works the same on Windows, x86 Linux and IBM LinuxONE (s390x); the Makefile only wraps these commands.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time

from .config import EVIDENCE_DIR, REPORTS_DIR, ROOT, SEED, env, env_int


def cmd_data(_):
    from .data import build_all
    s = build_all()
    print(json.dumps(s, indent=1))


def cmd_train(a):
    from .train import train_all
    train_all(seed=a.seed, use_cnn=not a.no_cnn, oof_folds=a.oof_folds)


def cmd_eval(a):
    from .evaluate import evaluate_all
    evaluate_all(seed=a.seed, cross=not a.skip_cross, cross_cnn=a.cross_cnn, llm_judge=a.llm_judge,
                 template_folds=a.template_folds)


def cmd_analyze(a):
    from .pipeline import ScamShield
    ss = ScamShield()
    r = ss.analyze(a.text)
    if a.explain:
        r["explanation"] = ss.explain(a.text, r)
    print(json.dumps(r, indent=2, ensure_ascii=False))


def cmd_serve(a):
    from .api import create_app
    logging.basicConfig(level=env("SS_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    app = create_app()
    app.run(host=a.host, port=a.port, threaded=True)


def cmd_bench(a):
    from .bench import run_bench
    run_bench(n=a.n, url=a.url, concurrency=a.concurrency)


def cmd_loadtest(a):
    from .loadtest import run_loadtest
    run_loadtest(n=a.n, workers=tuple(int(w) for w in a.workers.split(",")))


def cmd_blind(a):
    from .blind import evaluate_blind
    evaluate_blind(a.csv)


def cmd_evidence(_):
    """Platform fingerprint, installed package versions and git commit -> docs/evidence/."""
    from importlib import metadata
    from .platform_info import fingerprint
    fp = fingerprint()
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        sha = ""
    pkgs = sorted(f"{d.metadata['Name']}=={d.version}" for d in metadata.distributions() if d.metadata["Name"])
    out = {"collected_at": time.strftime("%Y-%m-%d %H:%M:%S %z"), "git_commit": sha, "fingerprint": fp, "packages": pkgs}
    path = EVIDENCE_DIR / f"platform_{fp['arch']}.json"
    path.write_text(json.dumps(out, indent=2))
    print(f"wrote {path.relative_to(ROOT)}  ({fp['arch']}, byteorder={fp['byteorder']}, commit={sha[:8] or 'n/a'})")


def cmd_all(a):
    cmd_data(a)
    cmd_train(a)
    cmd_eval(a)
    cmd_bench(a)
    cmd_evidence(a)


def main(argv=None):
    p = argparse.ArgumentParser(prog="scamshield", description="ScamShield: AI scam-message triage on IBM LinuxONE")
    p.add_argument("--seed", type=int, default=SEED)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("data", help="build processed datasets + splits").set_defaults(fn=cmd_data)
    t = sub.add_parser("train", help="train all models + ensemble")
    t.add_argument("--no-cnn", action="store_true", help="skip the PyTorch neural model")
    t.add_argument("--oof-folds", type=int, default=4, help="folds for out-of-fold ensemble training (0 = use validation split only; faster)")
    t.set_defaults(fn=cmd_train)
    e = sub.add_parser("eval", help="evaluate on all test sets -> reports/")
    e.add_argument("--skip-cross", action="store_true")
    e.add_argument("--template-folds", type=int, default=5, help="re-run the Indian-context test under N template splits (0 = off)")
    e.add_argument("--cross-cnn", action="store_true", help="also retrain the CNN for the cross-source test (slow)")
    e.add_argument("--llm-judge", type=int, default=0, metavar="N", help="compare a zero-shot LLM on N test messages")
    e.set_defaults(fn=cmd_eval)
    an = sub.add_parser("analyze", help="analyse one message")
    an.add_argument("text")
    an.add_argument("--explain", action="store_true", help="add the GenAI explanation")
    an.set_defaults(fn=cmd_analyze)
    s = sub.add_parser("serve", help="run the API + web UI")
    s.add_argument("--host", default=env("SS_HOST", "127.0.0.1"))
    s.add_argument("--port", type=int, default=env_int("SS_PORT", 8000))
    s.set_defaults(fn=cmd_serve)
    b = sub.add_parser("bench", help="latency/throughput benchmark -> reports/bench_<arch>.json")
    b.add_argument("--n", type=int, default=2000)
    b.add_argument("--url", default=None, help="also benchmark a running server, e.g. http://127.0.0.1:8000")
    b.add_argument("--concurrency", type=int, default=4)
    b.set_defaults(fn=cmd_bench)
    lt = sub.add_parser("loadtest", help="score many messages across worker processes -> reports/loadtest_<arch>.json")
    lt.add_argument("--n", type=int, default=10000)
    lt.add_argument("--workers", default="1,2,3", help="comma-separated worker counts")
    lt.set_defaults(fn=cmd_loadtest)
    bl = sub.add_parser("blind", help="score a hand-collected CSV (columns: text,label) -> reports/blind_<arch>.json")
    bl.add_argument("csv")
    bl.set_defaults(fn=cmd_blind)
    sub.add_parser("evidence", help="platform fingerprint -> docs/evidence/").set_defaults(fn=cmd_evidence)
    al = sub.add_parser("all", help="data + train + eval + bench + evidence")
    al.add_argument("--no-cnn", action="store_true")
    al.add_argument("--oof-folds", type=int, default=4)
    al.add_argument("--skip-cross", action="store_true")
    al.add_argument("--template-folds", type=int, default=5)
    al.add_argument("--cross-cnn", action="store_true")
    al.add_argument("--llm-judge", type=int, default=0)
    al.add_argument("--n", type=int, default=2000)
    al.add_argument("--url", default=None)
    al.add_argument("--concurrency", type=int, default=4)
    al.set_defaults(fn=cmd_all)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
