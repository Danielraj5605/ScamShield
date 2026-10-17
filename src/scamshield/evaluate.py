"""Evaluate every model and baseline on every test set; write reports/metrics.json and reports/metrics.md.

Test sets (never used for training or threshold selection):
  test_in     held-out UCI + Mendeley messages (in-distribution)
  test_india  synthetic Indian-context messages from templates never seen in training
  test_cross  Mendeley-only messages, scored by text models retrained WITHOUT any Mendeley data
  test_adv    hand-written adversarial messages (tests/adversarial/adv_messages.json)
  url_test    PhiUSIIL hostnames from registered domains never seen in training
"""
from __future__ import annotations

import json
import random
import time

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

from .config import PROCESSED_DIR, REPORTS_DIR, ROOT, SEED
from .features import prepare
from .models import neural, text_classic, url_model
from .pipeline import ScamShield
from .platform_info import fingerprint
from .signals import rules_only_score

ADV_PATH = ROOT / "tests" / "adversarial" / "adv_messages.json"
TRANSACTIONAL = {"legit:otp", "legit:debit", "legit:credit", "legit:service", "legit:statement"}


def _safe_auc(fn, y, s):
    return round(float(fn(y, s)), 4) if len(set(y)) == 2 else None


def recall_at_fpr(y, s, max_fpr=0.01):
    if len(set(y)) < 2:
        return None
    fpr, tpr, _ = roc_curve(y, s)
    ok = tpr[fpr <= max_fpr]
    return round(float(ok.max()) if len(ok) else 0.0, 4)


def score_metrics(y, s) -> dict:
    y, s = np.asarray(y), np.asarray(s)
    return {"pr_auc": _safe_auc(average_precision_score, y, s), "roc_auc": _safe_auc(roc_auc_score, y, s),
            "recall_at_fpr_1pct": recall_at_fpr(y, s)}


def level_metrics(y, levels) -> dict:
    y, lv = np.asarray(y), np.asarray(levels)
    pos, neg = y == 1, y == 0
    high, flagged = lv == "HIGH", lv != "LOW"
    return {
        "n": int(len(y)), "n_pos": int(pos.sum()), "n_neg": int(neg.sum()),
        "recall_high": round(float(high[pos].mean()), 4) if pos.any() else None,
        "recall_flagged": round(float(flagged[pos].mean()), 4) if pos.any() else None,
        "fpr_high": round(float(high[neg].mean()), 4) if neg.any() else None,
        "fpr_flagged": round(float(flagged[neg].mean()), 4) if neg.any() else None,
        "precision_high": round(float(pos[high].mean()), 4) if high.any() else None,
    }


def bootstrap_ci(y, s, levels, n_boot=1000, seed=SEED) -> dict:
    rng = np.random.default_rng(seed)
    y, s, lv = np.asarray(y), np.asarray(s), np.asarray(levels)
    aps, recs, fprs = [], [], []
    for _ in range(n_boot):
        idx = rng.integers(0, len(y), len(y))
        yy = y[idx]
        if len(set(yy)) < 2:
            continue
        aps.append(average_precision_score(yy, s[idx]))
        recs.append((lv[idx][yy == 1] == "HIGH").mean())
        fprs.append((lv[idx][yy == 0] == "HIGH").mean())
    q = lambda a: [round(float(np.percentile(a, 2.5)), 4), round(float(np.percentile(a, 97.5)), 4)]
    return {"pr_auc_95ci": q(aps), "recall_high_95ci": q(recs), "fpr_high_95ci": q(fprs)}


def evaluate_set(ss: ScamShield, nb, df: pd.DataFrame, name: str, log) -> dict:
    preps = [prepare(t) for t in df["text"]]
    y = df["label"].to_numpy()
    t0 = time.perf_counter()
    res = ss.score_batch(preps)
    elapsed = time.perf_counter() - t0
    full = np.array([r["score"] for r in res])
    levels = [r["level"] for r in res]
    out = {
        "n": len(df),
        "systems": {
            "B0_rules_only": score_metrics(y, [rules_only_score(p.signals) for p in preps]),
            "B1_naive_bayes": score_metrics(y, nb.predict_proba([p.model_text for p in preps])[:, 1]),
            "text_tfidf_lr": score_metrics(y, [r["p_text_lr"] for r in res]),
            **({"text_char_cnn": score_metrics(y, [r["p_text_cnn"] for r in res])} if ss.use_cnn else {}),
            "scamshield_full": score_metrics(y, full),
        },
        "scamshield_levels": level_metrics(y, levels),
        "scamshield_ci": bootstrap_ci(y, full, levels),
        "batch_ms_per_msg": round(elapsed * 1000 / max(len(df), 1), 3),
    }
    if name == "test_india":
        tx = df["sublabel"].isin(TRANSACTIONAL).to_numpy()
        out["legit_transactional_fpr_high"] = round(float((np.asarray(levels)[tx] == "HIGH").mean()), 4) if tx.any() else None
        out["legit_transactional_n"] = int(tx.sum())
        errors = [{"text": t, "label": int(l), "level": lv, "score": round(float(s), 3)}
                  for t, l, lv, s in zip(df["text"], y, levels, full)
                  if (l == 1 and lv == "LOW") or (l == 0 and lv == "HIGH")]
        out["errors_sample"] = errors[:15]
    f = out["systems"]["scamshield_full"]
    log(f"[eval] {name:<11} n={len(df):<5} PR-AUC={f['pr_auc']} recall@1%FPR={f['recall_at_fpr_1pct']} "
        f"recall_high={out['scamshield_levels']['recall_high']} fpr_high={out['scamshield_levels']['fpr_high']}")
    return out


def evaluate_cross(msgs: pd.DataFrame, seed: int, use_cnn: bool, log) -> dict:
    """Retrain text models without Mendeley, test on Mendeley: measures generalisation to a new source."""
    train = msgs[(msgs.split == "train") & (msgs.source != "mendeley")]
    val = msgs[(msgs.split == "val") & (msgs.source != "mendeley")]
    test = msgs[(msgs.source == "mendeley") & msgs.cross_ok.astype(str).str.lower().eq("true")]
    p = lambda d: [prepare(t).model_text for t in d["text"]]
    xtr, xva, xte = p(train), p(val), p(test)
    lr, _ = text_classic.train_lr(xtr, train.label.to_numpy(), xva, val.label.to_numpy(), seed)
    nb = text_classic.train_nb(xtr, train.label.to_numpy())
    y = test.label.to_numpy()
    out = {"n": len(test), "note": "text models retrained without any Mendeley data",
           "systems": {"B0_rules_only": score_metrics(y, [rules_only_score(prepare(t).signals) for t in test.text]),
                       "B1_naive_bayes": score_metrics(y, nb.predict_proba(xte)[:, 1]),
                       "text_tfidf_lr": score_metrics(y, lr.predict_proba(xte)[:, 1])}}
    if use_cnn:
        cnn, _ = neural.train_cnn(xtr, train.label.to_numpy(), xva, val.label.to_numpy(), seed)
        out["systems"]["text_char_cnn"] = score_metrics(y, neural.predict_proba(cnn, xte))
    log(f"[eval] test_cross  n={len(test):<5} LR PR-AUC={out['systems']['text_tfidf_lr']['pr_auc']}")
    return out


def evaluate_template_folds(ss: ScamShield, msgs: pd.DataFrame, n_folds: int, log) -> dict:
    """Re-run the Indian-context test under several different template splits.

    Which synthetic templates are held out decides how hard test_india is, so a single split can be
    lucky or unlucky. For each fold we hold out a different 30% of templates, retrain the fast parts
    (TF-IDF model + ensemble; the neural and link models are reused) and re-measure.
    """
    from .data import _split_synthetic
    from .ensemble import decide_level, stack_row, train_stacker
    from .train import group_oof, url_probs_for

    syn = msgs[msgs.source == "synthetic"].copy()
    real = msgs[msgs.source != "synthetic"]
    prep = {i: prepare(t) for i, t in zip(msgs.index, msgs.text)}
    texts = {i: p.model_text for i, p in prep.items()}
    p_url = dict(zip(msgs.index, url_probs_for([prep[i] for i in msgs.index], ss.url_hgb, ss.url_char)))
    folds = []
    for k in range(n_folds):
        fold_split = _split_synthetic(syn, SEED + 1000 * (k + 1))
        tr = pd.concat([real[real.split == "train"], syn[fold_split == "train"]])
        va = pd.concat([real[real.split == "val"], syn[fold_split == "val"]])
        te = syn[fold_split == "test_india"]
        pool = pd.concat([tr, va])
        lr, info = text_classic.train_lr([texts[i] for i in tr.index], tr.label.to_numpy(),
                                         [texts[i] for i in va.index], va.label.to_numpy(), SEED)
        groups = np.where(pool.template_id.to_numpy() != "", pool.template_id.to_numpy(), pool.msg_id.to_numpy())
        oof = group_oof([texts[i] for i in pool.index], pool.label.to_numpy(), groups, 4, SEED,
                        lambda xa, ya, xb: text_classic.fit_lr(xa, ya, info["best_C"], SEED).predict_proba(xb)[:, 1])
        xs = np.array([stack_row(a, None, p_url[i], prep[i].signals, False) for a, i in zip(oof, pool.index)])
        stk, thr = train_stacker(xs, pool.label.to_numpy(), SEED, groups=groups)
        pt = lr.predict_proba([texts[i] for i in te.index])[:, 1]
        scores = stk.predict_proba(np.array([stack_row(a, None, p_url[i], prep[i].signals, False)
                                             for a, i in zip(pt, te.index)]))[:, 1]
        levels = np.array([decide_level(float(s), prep[i].signals, thr) for s, i in zip(scores, te.index)])
        y = te.label.to_numpy()
        tx = te["sublabel"].isin(TRANSACTIONAL).to_numpy()
        folds.append({"fold": k + 1, "n_test": len(te),
                      "recall_high": round(float((levels[y == 1] == "HIGH").mean()), 4),
                      "fpr_high": round(float((levels[y == 0] == "HIGH").mean()), 4),
                      "legit_transactional_fpr_high": round(float((levels[tx] == "HIGH").mean()), 4) if tx.any() else None,
                      "pr_auc": round(float(average_precision_score(y, scores)), 4)})
    agg = lambda key: {"mean": round(float(np.mean([f[key] for f in folds])), 4),
                       "min": round(float(min(f[key] for f in folds)), 4), "max": round(float(max(f[key] for f in folds)), 4)}
    out = {"n_folds": n_folds, "note": "TF-IDF model + out-of-fold ensemble retrained per fold; neural and link models reused (neural model not part of the fold ensemble)",
           "recall_high": agg("recall_high"), "fpr_high": agg("fpr_high"), "pr_auc": agg("pr_auc"),
           "legit_transactional_fpr_high": agg("legit_transactional_fpr_high"), "folds": folds}
    log(f"[eval] template_folds x{n_folds}: recall_high {out['recall_high']} fpr_high {out['fpr_high']} "
        f"legit_tx_fpr {out['legit_transactional_fpr_high']}")
    return out


def evaluate_adversarial(ss: ScamShield, log) -> dict:
    cases = json.loads(ADV_PATH.read_text(encoding="utf-8"))
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    results, passed = [], 0
    for c in cases:
        r = ss.analyze(c["text"], explain_words=False)
        exp = c["expect"]
        ok = (order[r["risk_level"]] >= order[exp[:-1]]) if exp.endswith("+") else \
             (order[r["risk_level"]] <= order[exp[:-1]]) if exp.endswith("-") else r["risk_level"] == exp
        passed += ok
        results.append({"id": c["id"], "category": c["category"], "expect": exp, "got": r["risk_level"],
                        "score": r["risk_score"], "pass": bool(ok)})
    rate = round(passed / len(cases), 4)
    log(f"[eval] test_adv    n={len(cases):<5} pass_rate={rate}")
    return {"n": len(cases), "pass_rate": rate, "failures": [r for r in results if not r["pass"]], "results": results}


def evaluate_urls(ss: ScamShield, msgs: pd.DataFrame, log) -> dict:
    urls = pd.read_csv(PROCESSED_DIR / "urls.csv", keep_default_na=False)
    te = urls[urls.split == "test"]
    y = te.label.to_numpy()
    x = url_model.featurize(te.host)
    p_h, p_c = ss.url_hgb.predict_proba(x)[:, 1], ss.url_char.predict_proba(list(te.host))[:, 1]
    out = {"n": len(te), "note": "hostname only; PhiUSIIL legit URLs are homepages, so full-URL models would leak",
           "systems": {"hgb_lexical": score_metrics(y, p_h), "char_ngram_lr": score_metrics(y, p_c),
                       "average": score_metrics(y, (p_h + p_c) / 2)}}
    # India check: invented scam hosts from held-out synthetic messages vs. official brand hosts.
    syn = msgs[(msgs.source == "synthetic") & (msgs.split == "test_india") & (msgs.label == 1)]
    scam_hosts = sorted({h for t in syn.text for h in prepare(t).hosts} - {""})
    from .url_features import _official_domains
    legit_hosts = sorted(_official_domains())
    hosts = scam_hosts + legit_hosts
    yy = np.array([1] * len(scam_hosts) + [0] * len(legit_hosts))
    out["india_hosts"] = {
        "n_scam_hosts": len(scam_hosts), "n_official_hosts": len(legit_hosts),
        "without_allowlist": score_metrics(yy, url_model.score_hosts(hosts, ss.url_hgb, ss.url_char, use_allowlist=False)),
        "official_flagged_rate_without_allowlist": round(float((url_model.score_hosts(legit_hosts, ss.url_hgb, ss.url_char, use_allowlist=False) >= 0.5).mean()), 4),
        "scam_hosts_flagged_rate": round(float((url_model.score_hosts(scam_hosts, ss.url_hgb, ss.url_char) >= 0.5).mean()), 4) if scam_hosts else None,
    }
    log(f"[eval] url_test    n={len(te):<5} avg PR-AUC={out['systems']['average']['pr_auc']}")
    return out


def evaluate_llm_judge(ss: ScamShield, msgs: pd.DataFrame, n: int, seed: int, log) -> dict:
    """Compare a zero-shot hosted LLM with ScamShield on the same random test sample."""
    from . import genai
    if not genai.client().available():
        return {"skipped": "LLM API not configured or unreachable (set SS_LLM_BASE_URL/SS_LLM_API_KEY/SS_LLM_MODEL)"}
    pool = msgs[msgs.split.isin(["test", "test_india"])]
    sample = pool.sample(n=min(n, len(pool)), random_state=seed)
    preds, times, unparsed = [], [], 0
    for t in sample.text:
        t0 = time.perf_counter()
        try:
            p = genai.llm_classify(t)
        except Exception:  # noqa: BLE001 - network errors count as unparsed
            p = None
        times.append(time.perf_counter() - t0)
        unparsed += p is None
        preds.append(p if p is not None else 0)
        time.sleep(0.2)  # be gentle with free-tier rate limits
    y = sample.label.to_numpy()
    ours = [r["level"] for r in ss.score_batch([prepare(t) for t in sample.text])]
    ours_bin = np.array([lv != "LOW" for lv in ours], dtype=int)
    llm = np.array(preds)
    acc = lambda pr: round(float((pr == y).mean()), 4)
    rec = lambda pr: round(float(pr[y == 1].mean()), 4)
    fpr = lambda pr: round(float(pr[y == 0].mean()), 4)
    out = {"n": len(sample), "model": genai.client().model, "unparsed": unparsed,
           "llm_zero_shot": {"accuracy": acc(llm), "recall": rec(llm), "fpr": fpr(llm),
                             "median_latency_ms": round(float(np.median(times)) * 1000)},
           "scamshield_flagged": {"accuracy": acc(ours_bin), "recall": rec(ours_bin), "fpr": fpr(ours_bin)}}
    log(f"[eval] llm_judge   n={len(sample)} LLM acc={out['llm_zero_shot']['accuracy']} ours acc={out['scamshield_flagged']['accuracy']}")
    return out


def _md_table(report: dict) -> str:
    lines = ["# ScamShield evaluation report", "",
             f"Generated {report['generated_at']} on `{report['platform']['arch']}` "
             f"({report['platform']['cpus']} CPUs, Python {report['platform']['python']}). Model `{report['model_version']}`.", "",
             "## PR-AUC by system and test set", "",
             "| System | test_in | test_india | test_cross |", "|---|---|---|---|"]
    names = ["B0_rules_only", "B1_naive_bayes", "text_tfidf_lr", "text_char_cnn", "scamshield_full"]
    for n in names:
        cells = []
        for s in ("test_in", "test_india", "test_cross"):
            v = report["sets"].get(s, {}).get("systems", {}).get(n, {}).get("pr_auc")
            cells.append("n/a" if v is None else f"{v:.3f}")
        lines.append(f"| {n} | " + " | ".join(cells) + " |")
    lines += ["", "## ScamShield risk levels", "", "| Test set | recall (HIGH) | recall (HIGH+MEDIUM) | false-positive rate (HIGH) | FPR (HIGH+MEDIUM) |", "|---|---|---|---|---|"]
    for s in ("test_in", "test_india"):
        lv = report["sets"][s]["scamshield_levels"]
        lines.append(f"| {s} | {lv['recall_high']} | {lv['recall_flagged']} | {lv['fpr_high']} | {lv['fpr_flagged']} |")
    ti = report["sets"]["test_india"]
    lines += ["", f"Genuine transactional messages (OTPs, debit/credit alerts) wrongly rated HIGH in test_india: "
              f"**{ti.get('legit_transactional_fpr_high')}** (n={ti.get('legit_transactional_n')}).",
              "", f"Adversarial set pass rate: **{report['sets']['test_adv']['pass_rate']}** (n={report['sets']['test_adv']['n']}).",
              "", f"URL model (hostname only) PR-AUC on unseen domains: **{report['sets']['url_test']['systems']['average']['pr_auc']}**."]
    tf = report["sets"].get("template_folds")
    if tf:
        lines += ["", f"Across {tf['n_folds']} different template splits (Indian-context test): recall HIGH mean {tf['recall_high']['mean']} "
                  f"(range {tf['recall_high']['min']}-{tf['recall_high']['max']}); false-alarm rate HIGH mean {tf['fpr_high']['mean']} "
                  f"(range {tf['fpr_high']['min']}-{tf['fpr_high']['max']}); genuine transactional messages rated HIGH mean "
                  f"{tf['legit_transactional_fpr_high']['mean']} (range {tf['legit_transactional_fpr_high']['min']}-{tf['legit_transactional_fpr_high']['max']})."]
    lj = report["sets"].get("llm_judge")
    if lj and "skipped" not in lj:
        lines += ["", f"Zero-shot LLM `{lj['model']}` vs ScamShield on {lj['n']} test messages: LLM accuracy "
                  f"{lj['llm_zero_shot']['accuracy']} (median {lj['llm_zero_shot']['median_latency_ms']} ms/msg) vs ScamShield "
                  f"{lj['scamshield_flagged']['accuracy']}."]
    return "\n".join(lines) + "\n"


def evaluate_all(seed: int = SEED, cross: bool = True, cross_cnn: bool = False, llm_judge: int = 0,
                 template_folds: int = 5, log=print) -> dict:
    random.seed(seed)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ss = ScamShield()
    import joblib
    from .config import ARTIFACTS_DIR
    nb = joblib.load(ARTIFACTS_DIR / "text_nb.joblib")
    msgs = pd.read_csv(PROCESSED_DIR / "messages.csv", keep_default_na=False)
    sets = {
        "test_in": evaluate_set(ss, nb, msgs[(msgs.split == "test") & (msgs.source != "synthetic")], "test_in", log),
        "test_india": evaluate_set(ss, nb, msgs[msgs.split == "test_india"], "test_india", log),
        "test_adv": evaluate_adversarial(ss, log),
        "url_test": evaluate_urls(ss, msgs, log),
    }
    if template_folds:
        sets["template_folds"] = evaluate_template_folds(ss, msgs, template_folds, log)
    if cross:
        sets["test_cross"] = evaluate_cross(msgs, seed, cross_cnn and ss.use_cnn, log)
    if llm_judge:
        sets["llm_judge"] = evaluate_llm_judge(ss, msgs, llm_judge, seed, log)
    report = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "platform": fingerprint(),
              "model_version": ss.version, "trained_on_arch": ss.meta["trained_on_arch"],
              "thresholds": ss.thresholds, "sets": sets}
    arch = report["platform"]["arch"]
    (REPORTS_DIR / f"metrics_{arch}.json").write_text(json.dumps(report, indent=2))
    (REPORTS_DIR / f"metrics_{arch}.md").write_text(_md_table(report), encoding="utf-8")
    log(f"[eval] wrote reports/metrics_{arch}.json and .md")
    return report
