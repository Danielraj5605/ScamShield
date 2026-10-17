"""Train every model and the ensemble; write artifacts/ and artifacts/meta.json."""
from __future__ import annotations

import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score
from sklearn.model_selection import StratifiedGroupKFold

from .config import ARTIFACTS_DIR, PROCESSED_DIR, SEED
from .ensemble import feature_names, stack_row, train_stacker
from .features import prepare
from .models import neural, text_classic, type_model, url_model
from .platform_info import fingerprint, one_line


def load_prepared() -> tuple[pd.DataFrame, list]:
    msgs = pd.read_csv(PROCESSED_DIR / "messages.csv", keep_default_na=False)
    prepared = [prepare(t) for t in msgs["text"]]
    return msgs, prepared


def url_probs_for(prepared, url_hgb, url_char) -> list[float | None]:
    """Max phishing probability across each message's hosts (None if the message has no link)."""
    all_hosts = sorted({h for p in prepared for h in p.hosts})
    if not all_hosts:
        return [None] * len(prepared)
    probs = dict(zip(all_hosts, url_model.score_hosts(all_hosts, url_hgb, url_char)))
    return [max(float(probs[h]) for h in p.hosts) if p.hosts else None for p in prepared]


def group_oof(texts, y, groups, k: int, seed: int, fit_predict) -> np.ndarray:
    """Out-of-fold probabilities where all messages from one template stay in the same fold.

    Every row is predicted by a model that never saw its template, which mimics how the system
    meets unfamiliar genuine messages in the real world (and makes the stacker's inputs honest).
    """
    texts = np.asarray(texts, dtype=object)
    y = np.asarray(y)
    oof = np.zeros(len(y))
    cv = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed)
    for tr_idx, te_idx in cv.split(texts, y, groups):
        oof[te_idx] = fit_predict(list(texts[tr_idx]), y[tr_idx], list(texts[te_idx]))
    return oof


def train_all(seed: int = SEED, use_cnn: bool = True, oof_folds: int = 4, log=print) -> dict:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    fp = fingerprint()
    log(f"[train] {one_line(fp)}")
    timings, metrics = {}, {}

    t = time.perf_counter()
    msgs, prepared = load_prepared()
    texts = np.array([p.model_text for p in prepared], dtype=object)
    y = msgs["label"].to_numpy()
    tr, va = (msgs["split"] == "train").to_numpy(), (msgs["split"] == "val").to_numpy()
    timings["prepare_s"] = round(time.perf_counter() - t, 2)
    log(f"[train] messages train={tr.sum()} val={va.sum()} ({timings['prepare_s']}s)")

    # 1) Classical text model + Naive Bayes baseline
    t = time.perf_counter()
    lr, lr_info = text_classic.train_lr(list(texts[tr]), y[tr], list(texts[va]), y[va], seed)
    nb = text_classic.train_nb(list(texts[tr]), y[tr])
    timings["text_lr_s"] = round(time.perf_counter() - t, 2)
    p_lr_va = lr.predict_proba(list(texts[va]))[:, 1]
    metrics["val_pr_auc_text_lr"] = round(float(average_precision_score(y[va], p_lr_va)), 4)
    metrics["val_pr_auc_text_nb"] = round(float(average_precision_score(y[va], nb.predict_proba(list(texts[va]))[:, 1])), 4)
    metrics["text_lr"] = lr_info
    joblib.dump(lr, ARTIFACTS_DIR / "text_lr.joblib")
    joblib.dump(nb, ARTIFACTS_DIR / "text_nb.joblib")
    log(f"[train] text LR val PR-AUC={metrics['val_pr_auc_text_lr']} NB={metrics['val_pr_auc_text_nb']} ({timings['text_lr_s']}s)")

    # 2) Neural character-level CNN
    use_cnn = use_cnn and neural.TORCH_AVAILABLE
    p_cnn_va = None
    if use_cnn:
        t = time.perf_counter()
        cnn, cnn_info = neural.train_cnn(list(texts[tr]), y[tr], list(texts[va]), y[va], seed)
        timings["text_cnn_s"] = round(time.perf_counter() - t, 2)
        neural.save(cnn, ARTIFACTS_DIR / "text_cnn.pt")
        p_cnn_va = neural.predict_proba(cnn, list(texts[va]))
        metrics["val_pr_auc_text_cnn"] = cnn_info["best_val_pr_auc"]
        metrics["text_cnn"] = cnn_info
        log(f"[train] text CNN val PR-AUC={cnn_info['best_val_pr_auc']} params={cnn_info['params']} ({timings['text_cnn_s']}s)")
    else:
        log("[train] PyTorch not available or disabled: skipping the neural model")

    # 3) URL (hostname) model
    t = time.perf_counter()
    urls = pd.read_csv(PROCESSED_DIR / "urls.csv", keep_default_na=False)
    utr, uva = urls[urls.split == "train"], urls[urls.split == "val"]
    xu_tr, xu_va = url_model.featurize(utr["host"]), url_model.featurize(uva["host"])
    url_hgb = url_model.train_hgb(xu_tr, utr["label"].to_numpy(), seed)
    url_char = url_model.train_char_lr(utr["host"], utr["label"].to_numpy(), seed)
    url_lr = url_model.train_lr_baseline(xu_tr, utr["label"].to_numpy(), seed)
    timings["url_s"] = round(time.perf_counter() - t, 2)
    yu = uva["label"].to_numpy()
    p_hgb, p_char = url_hgb.predict_proba(xu_va)[:, 1], url_char.predict_proba(list(uva["host"]))[:, 1]
    metrics["val_pr_auc_url_hgb"] = round(float(average_precision_score(yu, p_hgb)), 4)
    metrics["val_pr_auc_url_char"] = round(float(average_precision_score(yu, p_char)), 4)
    metrics["val_pr_auc_url_avg"] = round(float(average_precision_score(yu, (p_hgb + p_char) / 2)), 4)
    metrics["val_pr_auc_url_lr_baseline"] = round(float(average_precision_score(yu, url_lr.predict_proba(xu_va)[:, 1])), 4)
    joblib.dump(url_hgb, ARTIFACTS_DIR / "url_hgb.joblib")
    joblib.dump(url_char, ARTIFACTS_DIR / "url_char.joblib")
    joblib.dump(url_lr, ARTIFACTS_DIR / "url_lr.joblib")
    log(f"[train] URL val PR-AUC hgb={metrics['val_pr_auc_url_hgb']} char={metrics['val_pr_auc_url_char']} "
        f"avg={metrics['val_pr_auc_url_avg']} lr-baseline={metrics['val_pr_auc_url_lr_baseline']} ({timings['url_s']}s)")

    # 4) Scam-type model (synthetic scam rows only: they carry type labels)
    t = time.perf_counter()
    typ_mask = tr & (msgs["source"] == "synthetic").to_numpy() & (y == 1)
    typ = type_model.train_type_model(list(texts[typ_mask]), msgs.loc[typ_mask, "scam_type"].tolist(), seed)
    joblib.dump(typ, ARTIFACTS_DIR / "type_lr.joblib")
    timings["type_s"] = round(time.perf_counter() - t, 2)

    # 5) Learned ensemble. Default: trained on group-out-of-fold predictions over train+val, so the
    #    meta-model learns from messages whose templates the base models had never seen.
    t = time.perf_counter()
    if oof_folds and oof_folds >= 2:
        pool = (tr | va)
        pool_idx = np.flatnonzero(pool)
        pool_prep = [prepared[i] for i in pool_idx]
        yp = y[pool_idx]
        tid = msgs["template_id"].to_numpy()[pool_idx]
        groups = np.where(tid != "", tid, msgs["msg_id"].to_numpy()[pool_idx])
        best_c = lr_info["best_C"]
        p_lr_pool = group_oof(texts[pool_idx], yp, groups, oof_folds, seed,
                              lambda xa, ya, xb: text_classic.fit_lr(xa, ya, best_c, seed).predict_proba(xb)[:, 1])
        p_cnn_pool = None
        if use_cnn:
            epochs = max(1, int(np.argmax([h["val_pr_auc"] for h in cnn_info["history"]])) + 1)
            p_cnn_pool = group_oof(texts[pool_idx], yp, groups, oof_folds, seed,
                                   lambda xa, ya, xb: neural.predict_proba(neural.train_cnn(xa, ya, None, None, seed, epochs=epochs)[0], xb))
        p_url_pool = url_probs_for(pool_prep, url_hgb, url_char)
        xs = np.array([stack_row(a, (p_cnn_pool[i] if use_cnn else None), u, p.signals, use_cnn)
                       for i, (a, u, p) in enumerate(zip(p_lr_pool, p_url_pool, pool_prep))])
        stacker, thresholds = train_stacker(xs, yp, seed, groups=groups)
        metrics["stacker_training"] = f"group-out-of-fold over train+val, {oof_folds} folds, n={len(yp)}"
    else:
        va_prep = [p for p, m in zip(prepared, va) if m]
        p_url_va = url_probs_for(va_prep, url_hgb, url_char)
        xs = np.array([stack_row(a, (p_cnn_va[i] if use_cnn else None), u, p.signals, use_cnn)
                       for i, (a, u, p) in enumerate(zip(p_lr_va, p_url_va, va_prep))])
        stacker, thresholds = train_stacker(xs, y[va], seed)
        metrics["stacker_training"] = f"validation split only, n={int(va.sum())}"
    joblib.dump(stacker, ARTIFACTS_DIR / "stacker.joblib")
    timings["stacker_s"] = round(time.perf_counter() - t, 2)
    weights = dict(zip(feature_names(use_cnn), np.round(stacker.coef_[0], 3).tolist()))
    log(f"[train] ensemble ({metrics['stacker_training']}) thresholds={thresholds} ({timings['stacker_s']}s)")

    meta = {
        "version": f"ss-{time.strftime('%Y%m%d-%H%M%S')}",
        "trained_on_arch": fp["arch"],
        "trained_on_byteorder": fp["byteorder"],
        "platform": fp,
        "seed": seed,
        "use_cnn": use_cnn,
        "thresholds": thresholds,
        "ensemble_weights": weights,
        "val_metrics": metrics,
        "timings": timings,
    }
    (ARTIFACTS_DIR / "meta.json").write_text(json.dumps(meta, indent=2))
    log(f"[train] done: {meta['version']}")
    return meta
