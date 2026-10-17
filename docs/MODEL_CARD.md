# Model card: ScamShield

## Intended use
Advisory triage of a single SMS/WhatsApp message pasted by a person (or a helper), returning a risk level, plain-language reasons and advice. It is also usable for provider-side batch scoring.

**Out of scope:** automatically blocking or deleting messages; legal or financial decisions; languages other than English; images, voice calls and screenshots.

## Architecture

| Layer | Model | Notes |
|---|---|---|
| Text AI #1 | TF-IDF (word 1–2-grams + char 3–5-grams) → logistic regression | C tuned on validation PR-AUC; coefficients also used for explanations |
| Text AI #2 | Character/byte-level CNN (PyTorch), kernels 3/5/7, 100,305 parameters | Trained from scratch on the target machine; robust to obfuscation such as "0TP" and look-alike letters; optional |
| Link AI | Average of HGB on 18 lexical hostname features and char 2–5-gram logistic regression | Hostname only (see DATA_CARD); verified official brand domains allow-listed |
| Signals | 23 interpretable signals: 20 warning detectors (OTP-share request, brand look-alike, digital arrest, UPI-PIN-to-receive, mistaken-payment request, …) and 3 genuine-pattern signals (OTP notice, bank transaction notice, all-links-official) | Features for the ensemble, user-facing reasons, and 5 CRITICAL guardrails |
| Ensemble | Logistic-regression meta-model over model logits + link score + signal flags | Trained on group-out-of-fold predictions over train+val; thresholds from grouped 5-fold CV |
| Decision policy | HIGH if score ≥ T_high (precision ≥ 0.95 on validation), or a CRITICAL guardrail fired, or score ≥ T_med and a HIGH-severity signal fired. MEDIUM if score ≥ T_med. Otherwise LOW | T_med is capped at half of T_high, so a "be careful" band always exists |
| Explanations | Word-level occlusion (which words raised the ensemble score), signal reasons, scam-type classifier | |
| GenAI (optional) | Hosted LLM via an OpenAI-compatible API + BM25 retrieval over `kb/*.md` | Explains, never decides. Receives scrubbed text only. Output validated; template fallback |

## Results (measured on IBM LinuxONE, s390x, IBM z17 VM; models trained there)

From `reports/metrics_s390x.md` (model `ss-20261017-105456`):

| Test set | ScamShield PR-AUC | Rules-only | Naive Bayes | TF-IDF only | Recall (HIGH) | False-positive rate (HIGH) |
|---|---|---|---|---|---|---|
| test_in (n=916, held-out public data) | 0.987 (95% CI 0.973-0.998) | 0.357 | 0.983 | 0.988 | 0.969 | 0.005 (CI 0.001-0.011) |
| test_india (n=461, unseen templates) | 0.997 (95% CI 0.994-0.999) | 0.926 | 0.945 | 0.967 | 1.000 | 0.066 (CI 0.038-0.097) |

- **On public SMS data the ensemble does not beat a simple TF-IDF model** (0.987 vs 0.988). Its advantage appears on the Indian-context set.
- **Genuine transactional messages (OTP, debit/credit alerts) rated HIGH:** 7 of 132 (5.3%) on the main split. Re-running the Indian-context test under 5 different template splits (TF-IDF model plus ensemble retrained each time, neural model not included) gave false-alarm rate 1.5% (range 0.4-3.2%) and genuine-transactional rate 1.2% (range 0-2.3%), with 100% of scams rated HIGH in every split. The gap to the main split suggests the neural model adds false alarms on unfamiliar genuine styles.
- Cross-source (text models retrained without Mendeley, tested on it, n=945): TF-IDF PR-AUC 0.988 vs Naive Bayes 0.991. **No measurable drop**, but the 945 messages are a small sample.
- URL models on unseen domains (n=33,373): average PR-AUC 0.920 (feature HGB 0.878, char-gram LR 0.911). Without the allowlist, 17% of official Indian brand domains would be flagged.
- Adversarial set: 34 of 36. **Caveat:** written by the same team and extended after seeing failures, so it is a regression suite, not an unbiased estimate.
- Speed on s390x (3 vCPUs): median 2.7 ms per message (p95 8.5 ms, p99 21 ms), about 250 messages/s single-threaded, 410/s batched; with word explanations the median is 4.1 ms (p95 88 ms).
- Training time on the VM: TF-IDF 5 s, neural CNN 159 s, link models 127 s, out-of-fold ensemble 372 s.

## Training-data caveat for the ensemble
The meta-model is trained on **group-out-of-fold** predictions over train and validation data (4 folds, all messages of a template in the same fold). Earlier versions trained it on the validation split only and over-flagged unfamiliar genuine messages; the out-of-fold change cut the multi-split false-alarm rate from about 17% to about 1.5%. Templates for genuine refund, bill and debit styles were added after errors on such messages were examined, so the Indian-context numbers are not a clean blind test.

## Known failure modes
- **Genuine messages in unfamiliar styles can be over-flagged.** Example: every variant of a housing-society water-supply notice in the held-out templates was rated HIGH.
- **Genuine UPI payment confirmations and renewal reminders** were rated HIGH in the adversarial set.
- **Novel scam scripts with no warning signs** can be missed.
- English only; dataset age (D1 ~2012).
- Rules can be read in the open-source repository and evaded by a determined scammer. The learned models reduce, but don't remove, that risk.

## Fairness and safety
- No demographic attributes are used. The system profiles messages, not people.
- LOW is worded as "no common scam signs", **never** as "safe". Every result carries a disclaimer.
- Message text is never logged or stored by default; see THREAT_MODEL.md.
