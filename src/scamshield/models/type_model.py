"""Scam-type classifier (multi-class) used when no signal already names the scam type."""
from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline


def train_type_model(texts, types, seed: int) -> Pipeline:
    pipe = Pipeline([
        ("tfidf", FeatureUnion([
            ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
        ])),
        ("clf", LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced", random_state=seed)),
    ])
    return pipe.fit(texts, types)
