"""Build the processed datasets and splits.

Outputs (CSV only, so no pyarrow is needed on s390x):
  data/processed/messages.csv  msg_id,text,label,sublabel,source,template_id,scam_type,split,cross_ok
  data/processed/urls.csv      host,reg_domain,label,split
Label convention everywhere: 1 = suspicious/phishing, 0 = legitimate.
"""
from __future__ import annotations

import hashlib
import json
import random
import string

import pandas as pd

from .config import PROCESSED_DIR, RAW_DIR, SEED, TEMPLATES_PATH
from .normalize import normalize
from .urls import host_of, registered_domain

SYNTH_PER_TEMPLATE = 12


# ---------------------------------------------------------------- public datasets
def load_uci() -> pd.DataFrame:
    path = RAW_DIR / "uci_sms" / "SMSSpamCollection"
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        if "\t" not in line:
            continue
        lab, text = line.split("\t", 1)
        rows.append({"msg_id": f"uci_{i}", "text": text.strip(), "label": int(lab == "spam"),
                     "sublabel": lab, "source": "uci_sms"})
    return pd.DataFrame(rows)


def load_mendeley() -> pd.DataFrame:
    path = RAW_DIR / "mendeley" / "Dataset_5971.csv"
    df = pd.read_csv(path, encoding="utf-8", encoding_errors="replace")
    df["sublabel"] = df["LABEL"].str.strip().str.lower()
    df = df[df["sublabel"].isin(["ham", "spam", "smishing"])]
    return pd.DataFrame({
        "msg_id": [f"mend_{i}" for i in df.index],
        "text": df["TEXT"].astype(str).str.strip(),
        "label": (df["sublabel"] != "ham").astype(int),
        "sublabel": df["sublabel"],
        "source": "mendeley",
    })


# ---------------------------------------------------------------- synthetic set
class _Slots(dict):
    """Fills template slots lazily; a slot used twice in one message gets the same value."""

    def __init__(self, rng: random.Random, spec: dict):
        super().__init__()
        self.rng, self.spec = rng, spec

    def _code(self, n: int) -> str:
        return "".join(self.rng.choice(string.ascii_uppercase + string.digits) for _ in range(n))

    def __missing__(self, key: str) -> str:
        r = self.rng
        lists = self.spec["slots"]
        if key in lists:
            value = r.choice(lists[key]).replace("{code}", self._code(6).lower())
        elif key == "amt":
            value = f"{r.randint(199, 49999):,}" + (f".{r.randint(0, 99):02d}" if r.random() < 0.4 else "")
        elif key == "small_amt":
            value = str(r.choice([10, 15, 25, 29, 49, 50, 99, 149]))
        elif key == "big_amt":
            value = f"{r.choice([5000, 8000, 10000, 25000, 50000, 100000, 200000]):,}"
        elif key == "otp":
            value = f"{r.randint(0, 999999):06d}"
        elif key == "last4":
            value = f"{r.randint(0, 9999):04d}"
        elif key == "date":
            value = f"{r.randint(1, 28):02d}-{r.choice(['Sep', 'Oct', 'Nov'])}-26"
        elif key == "phone":
            value = r.choice(["9", "8", "7"]) + "XXXXX" + f"{r.randint(0, 9999):04d}"
        elif key == "tollfree":
            value = "1800-XXX-XXXX"
        elif key in ("order", "code"):
            value = self._code(r.choice([8, 10]))
        elif key == "upi":
            value = f"{r.choice(lists['name']).lower()}{r.randint(10, 999)}@{r.choice(['ybl', 'okaxis', 'paytm', 'oksbi'])}"
        elif key == "fake_link":
            value = self._fake_link()
        else:
            raise KeyError(key)
        self[key] = value
        return value

    def _fake_link(self) -> str:
        r, p = self.rng, self.spec["fake_link_parts"]
        if r.random() < 0.25:
            return f"{r.choice(p['shorteners'])}/{self._code(6)}"
        brand, word = r.choice(p["brands"]), r.choice(p["words"])
        host = r.choice([f"{brand}-{word}", f"{word}-{brand}", f"{brand}{word}", f"{brand}-{word}{r.randint(1, 99)}"])
        path = r.choice(p["paths"]).replace("{code}", self._code(5))
        prefix = r.choice(["http://", "https://", "www.", ""])
        return f"{prefix}{host}.{r.choice(p['tlds'])}{path}"


def load_synthetic(seed: int = SEED) -> pd.DataFrame:
    spec = json.loads(TEMPLATES_PATH.read_text(encoding="utf-8"))
    rng = random.Random(seed)
    rows = []
    for cls, label in (("scam", 1), ("legit", 0)):
        for t in spec[cls]:
            for k in range(SYNTH_PER_TEMPLATE):
                text = t["text"].format_map(_Slots(rng, spec))
                if rng.random() < 0.15:
                    text = text.lower()
                rows.append({"msg_id": f"syn_{t['id']}_{k}", "text": text, "label": label,
                             "sublabel": f"{cls}:{t['type']}", "source": "synthetic",
                             "template_id": t["id"], "scam_type": t["type"] if label else ""})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- splits
def _bucket(key: str) -> float:
    """Deterministic pseudo-random number in [0,1) from a string (stable across machines)."""
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF


def _split_real(df: pd.DataFrame) -> pd.Series:
    """Stratified 70/15/15 by (source,label), deterministic from the message key."""
    split = pd.Series("train", index=df.index)
    for _, g in df.groupby(["source", "label"]):
        order = g["key"].map(lambda k: _bucket("real|" + k)).sort_values()
        n = len(order)
        split[order.index[: int(round(0.15 * n))]] = "test"
        split[order.index[int(round(0.15 * n)): int(round(0.30 * n))]] = "val"
    return split


def _split_synthetic(df: pd.DataFrame, seed: int) -> pd.Series:
    """Hold out whole templates: generated messages from one template never span train and test."""
    rng = random.Random(seed)
    template_split: dict[str, str] = {}
    meta = df.drop_duplicates("template_id")[["template_id", "label", "sublabel"]]
    for _, g in meta.groupby("sublabel"):
        ids = sorted(g["template_id"])
        rng.shuffle(ids)
        n = len(ids)
        n_test = max(1, round(0.3 * n)) if n >= 2 else 0
        n_val = 1 if n - n_test >= 3 else 0
        for i, tid in enumerate(ids):
            template_split[tid] = "test_india" if i < n_test else ("val" if i < n_test + n_val else "train")
    return df["template_id"].map(template_split)


def build_messages(seed: int = SEED) -> pd.DataFrame:
    real = pd.concat([load_uci(), load_mendeley()], ignore_index=True)
    real["key"] = real["text"].map(normalize)
    real = real[real["key"].str.len() > 0]
    # The Mendeley set re-uses many UCI messages. Keep one copy; remember which keys are shared so
    # the cross-source test only uses messages the UCI-trained model has never seen.
    uci_keys = set(real.loc[real.source == "uci_sms", "key"])
    real["cross_ok"] = ~((real.source == "mendeley") & real["key"].isin(uci_keys))
    real = real.drop_duplicates("key", keep="first")
    real["split"] = _split_real(real)
    real["template_id"], real["scam_type"] = "", ""

    synth = load_synthetic(seed)
    synth["key"] = synth["text"].map(normalize)
    synth = synth.drop_duplicates("key")
    synth["cross_ok"] = True
    synth["split"] = _split_synthetic(synth, seed)

    cols = ["msg_id", "text", "label", "sublabel", "source", "template_id", "scam_type", "split", "cross_ok"]
    return pd.concat([real[cols], synth[cols]], ignore_index=True)


def build_urls() -> pd.DataFrame:
    path = RAW_DIR / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    df = pd.read_csv(path, usecols=["URL", "label"], encoding="utf-8-sig")
    out = pd.DataFrame({"host": df["URL"].map(host_of), "label": (df["label"] == 0).astype(int)})  # 0 = phishing in PhiUSIIL
    out = out[out["host"].str.len() > 0]
    # A host labelled both ways (e.g. abused free-hosting domains) is ambiguous: drop it.
    conflict = out.groupby("host")["label"].nunique()
    out = out[~out["host"].isin(conflict[conflict > 1].index)].drop_duplicates("host")
    out["reg_domain"] = out["host"].map(registered_domain)
    b = out["reg_domain"].map(lambda d: _bucket("url|" + d))  # group split: a domain never spans splits
    out["split"] = "train"
    out.loc[b >= 0.70, "split"] = "val"
    out.loc[b >= 0.85, "split"] = "test"
    return out[["host", "reg_domain", "label", "split"]]


def build_all(seed: int = SEED) -> dict:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    msgs = build_messages(seed)
    msgs.to_csv(PROCESSED_DIR / "messages.csv", index=False)
    urls = build_urls()
    urls.to_csv(PROCESSED_DIR / "urls.csv", index=False)
    summary = {
        "messages": msgs.groupby(["source", "split", "label"]).size().rename("n").reset_index().to_dict("records"),
        "urls": urls.groupby(["split", "label"]).size().rename("n").reset_index().to_dict("records"),
    }
    return summary
