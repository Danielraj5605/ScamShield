"""Hostname phishing models.

Two complementary models are averaged:
  * HGB on hand-crafted lexical features (brand look-alikes, entropy, suspicious TLD, ...)
  * Logistic regression on character 2-5-grams of the hostname (learns patterns automatically)
Verified official brand domains (configs/brands.json) are allow-listed, because the public training
data contains few Indian domains and both models would otherwise flag e.g. "onlinesbi.sbi".
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ..url_features import _official_domains, url_features
from ..urls import registered_domain

ALLOWLIST_PROB = 0.01


def featurize(hosts) -> np.ndarray:
    return np.array([url_features(h) for h in hosts], dtype=np.float64)


def train_hgb(x: np.ndarray, y: np.ndarray, seed: int) -> HistGradientBoostingClassifier:
    model = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, early_stopping=True,
                                           validation_fraction=0.1, class_weight="balanced", random_state=seed)
    return model.fit(x, y)


def train_char_lr(hosts, y: np.ndarray, seed: int):
    return make_pipeline(
        TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3, sublinear_tf=True, max_features=300000),
        LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced", random_state=seed),
    ).fit(list(hosts), y)


def train_lr_baseline(x: np.ndarray, y: np.ndarray, seed: int):
    return make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced",
                                                              random_state=seed)).fit(x, y)


def is_allowlisted(host: str) -> bool:
    official = _official_domains()
    return registered_domain(host) in official or host in official


def score_hosts(hosts: list[str], hgb, char_lr, use_allowlist: bool = True) -> np.ndarray:
    """Averaged phishing probability per host, with allow-listed official domains forced low."""
    if not hosts:
        return np.zeros(0)
    p = (hgb.predict_proba(featurize(hosts))[:, 1] + char_lr.predict_proba(list(hosts))[:, 1]) / 2
    if use_allowlist:
        p = np.array([ALLOWLIST_PROB if is_allowlisted(h) else v for h, v in zip(hosts, p)])
    return p
