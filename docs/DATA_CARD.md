# Data card

| ID | Dataset | Licence | Size used | Role |
|---|---|---|---|---|
| D1 | UCI SMS Spam Collection (Almeida & Hidalgo) — <https://archive.ics.uci.edu/dataset/228/sms+spam+collection> | CC BY 4.0 | 5,159 unique messages after de-duplication (4,517 ham / 642 spam) | Text models: train/val/test |
| D2 | SMS Phishing Dataset for Machine Learning and Pattern Recognition (Mishra & Soni, 2022), DOI 10.17632/f45bkkt8pr.1 — <https://data.mendeley.com/datasets/f45bkkt8pr/1> | CC BY 4.0 | 945 unique messages not present in D1 (524 ham / 421 spam+smishing) | Text models; cross-source test |
| D3 | PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024) — <https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset> | CC BY 4.0 | 219,036 unique hostnames (84,244 phishing / 134,792 legitimate) | URL models |
| D4 | ScamShield synthetic Indian-context messages (this repo: `data/templates/templates.json`) | Same as this repository | 60 scam + 72 genuine templates × 12 generated messages → 1,418 unique (635 scam / 783 genuine) | Gap filler; held-out-template test (`test_india`) |

Checksums (SHA-256 of the downloaded zips) are pinned in `scripts/download_data.sh`.

## Processing decisions (and why)

- **Label convention:** 1 = suspicious (spam, smishing, scam, phishing), 0 = legitimate.
- **D2 label spellings** (`ham`, `spam`/`Spam`, `Smishing`/`smishing`) are normalised.
- **De-duplication across sources:** about 5,000 of D2's 5,971 messages are copies of D1 messages. Duplicates are removed after text normalisation, keeping the D1 copy. The **cross-source test** uses only the 945 D2 messages that never appear in D1.
- **PhiUSIIL label encoding:** `label = 1` means **legitimate**, `0` means **phishing**. This was verified on known domains (e.g. `www.sbi.co.in` is 1); we invert it to our convention.
- **Hostname-only URL model:** in D3, *every* legitimate URL is a bare homepage (0% have a path), while phishing URLs often have paths. A model fed full URLs would learn "has a path = phishing". We therefore score hostnames only, strip `www.`, and drop hosts that are labelled both ways.
- **URL split by registered domain:** a domain never appears in both train and test.
- **Synthetic set split by template:** whole templates are held out (30% → `test_india`, plus about 1 per type → validation), so the test measures generalisation to unseen *wording*, not to unseen slot values.
- **Synthetic data hygiene:** written in our own words from public cyber-safety advisories. Phone numbers are masked (`9XXXXX1234`), scam domains are invented, and brand names appear only as the subject of impersonation. No real person's data is included.

## Known biases and limits

- D1 is UK/Singapore English from about 2012, and D2 is mostly English. Indian-context coverage comes **only** from D4, which was written by the team. D4 test results show generalisation to unseen templates written by the *same authors*, which is optimistic compared with real messages.
- D3's legitimate class is popular homepages, so it has few Indian domains. That is why official brand domains are allow-listed (`configs/brands.json`).
- No regional-language scripts (Devanagari, Tamil, etc.) are covered yet.
