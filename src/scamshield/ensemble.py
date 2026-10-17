"""Learned ensemble: a logistic-regression meta-model over the base models and the signals.

The meta-model learns, from held-out validation data, how much to trust each base model and each
signal. Thresholds for HIGH/MEDIUM are chosen on cross-validated meta-model scores.
"""
from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold, cross_val_predict

from .models.text_classic import logit
from .signals import CRITICAL, HIGH, SIGNAL_IDS, Signal

HIGH_PRECISION_TARGET = 0.95
MED_RECALL_TARGET = 0.97
MED_MIN = 0.2
# MEDIUM means "uncertain, be careful": the band must stay wide even when validation data is easy.
MED_MAX_FRACTION_OF_HIGH = 0.5


def stack_row(p_lr: float, p_cnn: float | None, p_url: float | None, signals: list[Signal], use_cnn: bool) -> list[float]:
    ids = {s.id for s in signals}
    row = [float(logit(np.array([p_lr]))[0])]
    if use_cnn:
        row.append(float(logit(np.array([p_cnn if p_cnn is not None else p_lr]))[0]))
    row += [p_url if p_url is not None else 0.0, float(p_url is not None)]
    row += [float(i in ids) for i in SIGNAL_IDS]
    return row


def feature_names(use_cnn: bool) -> list[str]:
    return ["text_lr_logit"] + (["text_cnn_logit"] if use_cnn else []) + ["url_prob", "has_url"] + [f"sig_{i}" for i in SIGNAL_IDS]


def train_stacker(x: np.ndarray, y: np.ndarray, seed: int, groups=None) -> tuple[LogisticRegression, dict]:
    """Fit the meta-model; thresholds come from cross-validated scores (grouped by template when given)."""
    model = LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced", random_state=seed)
    if groups is not None:
        cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        oof = cross_val_predict(model, x, y, cv=cv, groups=groups, method="predict_proba")[:, 1]
    else:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
        oof = cross_val_predict(model, x, y, cv=cv, method="predict_proba")[:, 1]
    model.fit(x, y)
    return model, choose_thresholds(y, oof)


def choose_thresholds(y: np.ndarray, scores: np.ndarray) -> dict:
    prec, rec, thr = precision_recall_curve(y, scores)
    prec, rec = prec[:-1], rec[:-1]
    ok_high = np.where(prec >= HIGH_PRECISION_TARGET)[0]
    t_high = float(thr[ok_high[0]]) if len(ok_high) else 0.9
    ok_med = np.where(rec >= MED_RECALL_TARGET)[0]
    t_med = float(thr[ok_med[-1]]) if len(ok_med) else 0.3
    t_med = min(max(t_med, MED_MIN), t_high * MED_MAX_FRACTION_OF_HIGH)
    return {"high": round(t_high, 4), "med": round(t_med, 4),
            "targets": {"high_precision": HIGH_PRECISION_TARGET, "med_recall": MED_RECALL_TARGET,
                        "med_max_fraction_of_high": MED_MAX_FRACTION_OF_HIGH}}


def decide_level(score: float, signals: list[Signal], thresholds: dict) -> str:
    if any(s.severity == CRITICAL for s in signals):
        return "HIGH"  # guardrail: never downgrade a critical scam pattern
    if score >= thresholds["high"]:
        return "HIGH"
    if score >= thresholds["med"]:
        # Corroboration: the model is suspicious AND a strong, specific scam pattern fired.
        return "HIGH" if any(s.severity == HIGH for s in signals) else "MEDIUM"
    return "LOW"
