"""Classical text models: TF-IDF + logistic regression (main) and Naive Bayes (baseline B1)."""
from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import FeatureUnion, Pipeline


def _vectorizers() -> FeatureUnion:
    return FeatureUnion([
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, max_features=50000,
                                 sublinear_tf=True, token_pattern=r"(?u)\b\w[\w']*\b")),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=100000,
                                 sublinear_tf=True)),
    ])


def train_lr(x_train, y_train, x_val, y_val, seed: int) -> tuple[Pipeline, dict]:
    """Tune C on the validation set by PR-AUC, then return the best pipeline."""
    best, best_ap, scores = None, -1.0, {}
    for c in (0.5, 1.0, 2.0, 4.0, 8.0):
        pipe = Pipeline([("tfidf", _vectorizers()),
                         ("clf", LogisticRegression(C=c, class_weight="balanced", max_iter=3000, random_state=seed))])
        pipe.fit(x_train, y_train)
        ap = average_precision_score(y_val, pipe.predict_proba(x_val)[:, 1])
        scores[str(c)] = round(float(ap), 4)
        if ap > best_ap:
            best, best_ap = pipe, ap
    return best, {"val_pr_auc_by_C": scores, "best_C": best.named_steps["clf"].C}


def fit_lr(x, y, C: float, seed: int) -> Pipeline:
    """Fit the TF-IDF + logistic regression pipeline with a fixed C (used for out-of-fold stacking)."""
    pipe = Pipeline([("tfidf", _vectorizers()),
                     ("clf", LogisticRegression(C=C, class_weight="balanced", max_iter=3000, random_state=seed))])
    return pipe.fit(x, y)


def train_nb(x_train, y_train) -> Pipeline:
    pipe = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
                     ("clf", MultinomialNB(alpha=0.1))])
    return pipe.fit(x_train, y_train)


def word_contributions(pipe: Pipeline, model_text: str, top_k: int = 5) -> list[tuple[str, float]]:
    """Top word n-grams pushing this message towards 'suspicious' (coef x tf-idf), for explanations."""
    union: FeatureUnion = pipe.named_steps["tfidf"]
    word_vec: TfidfVectorizer = dict(union.transformer_list)["word"]
    coef = pipe.named_steps["clf"].coef_[0][: len(word_vec.vocabulary_)]
    row = word_vec.transform([model_text]).tocoo()
    names = word_vec.get_feature_names_out()
    contrib = [(names[j], float(v * coef[j])) for j, v in zip(row.col, row.data)]
    contrib = [(w, c) for w, c in contrib if c > 0 and not w.startswith("__")]
    return sorted(contrib, key=lambda t: -t[1])[:top_k]


def logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))
