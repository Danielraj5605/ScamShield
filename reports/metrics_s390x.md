# ScamShield evaluation report

Generated 2026-10-18 14:14:04 on `s390x` (3 CPUs, Python 3.12.3). Model `ss-20261018-141241`.

## PR-AUC by system and test set

| System | test_in | test_india | test_cross |
|---|---|---|---|
| B0_rules_only | 0.357 | 0.936 | 0.616 |
| B1_naive_bayes | 0.983 | 0.945 | 0.991 |
| text_tfidf_lr | 0.988 | 0.967 | 0.988 |
| text_char_cnn | 0.980 | 0.973 | n/a |
| scamshield_full | 0.987 | 0.997 | n/a |

## ScamShield risk levels

| Test set | recall (HIGH) | recall (HIGH+MEDIUM) | false-positive rate (HIGH) | FPR (HIGH+MEDIUM) |
|---|---|---|---|---|
| test_in | 0.9686 | 0.9748 | 0.0053 | 0.0211 |
| test_india | 1.0 | 1.0 | 0.0618 | 0.1197 |

Genuine transactional messages (OTPs, debit/credit alerts) wrongly rated HIGH in test_india: **0.0455** (n=132).

Adversarial set pass rate: **0.9444** (n=36).

URL model (hostname only) PR-AUC on unseen domains: **0.9198**.

Across 5 different template splits (Indian-context test): recall HIGH mean 1.0 (range 1.0-1.0); false-alarm rate HIGH mean 0.0132 (range 0.0-0.044); genuine transactional messages rated HIGH mean 0.0061 (range 0.0-0.0305).
