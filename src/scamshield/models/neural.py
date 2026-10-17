"""Character-level CNN text classifier (PyTorch), trained from scratch.

Why character/byte level: scammers obfuscate ("0TP", "S B I", look-alike letters, unusual spellings).
Byte-level convolutions see those patterns directly, need no tokenizer download, and keep the model
small (about 100k parameters) so it trains in minutes on 3 vCPUs. Training from scratch on the target
machine also avoids loading little-endian pretrained weights on big-endian s390x.

PyTorch is optional: if it is not installed, the rest of ScamShield still works without this model.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import numpy as np

try:
    import torch
    from torch import nn
    TORCH_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the platform
    TORCH_AVAILABLE = False

MAX_LEN = 256


def encode(texts: list[str], max_len: int = MAX_LEN) -> np.ndarray:
    """UTF-8 bytes shifted by +1 so 0 is padding."""
    out = np.zeros((len(texts), max_len), dtype=np.int64)
    for i, t in enumerate(texts):
        b = t.encode("utf-8", errors="ignore")[:max_len]
        out[i, : len(b)] = np.frombuffer(b, dtype=np.uint8).astype(np.int64) + 1
    return out


if TORCH_AVAILABLE:
    class ByteCNN(nn.Module):
        def __init__(self, emb_dim: int = 48, filters: int = 96, kernels=(3, 5, 7), hidden: int = 64, dropout: float = 0.3):
            super().__init__()
            self.emb = nn.Embedding(257, emb_dim, padding_idx=0)
            self.convs = nn.ModuleList([nn.Conv1d(emb_dim, filters, k, padding=k // 2) for k in kernels])
            self.drop = nn.Dropout(dropout)
            self.fc = nn.Sequential(nn.Linear(filters * len(kernels), hidden), nn.ReLU(), nn.Linear(hidden, 1))

        def forward(self, x):
            mask = (x != 0).unsqueeze(1)                      # (B,1,L)
            h = self.emb(x).transpose(1, 2)                   # (B,E,L)
            pooled = []
            for conv in self.convs:
                c = torch.relu(conv(h)).masked_fill(~mask, 0.0)
                pooled.append(c.max(dim=2).values)
            return self.fc(self.drop(torch.cat(pooled, dim=1))).squeeze(1)


def _set_threads() -> None:
    torch.set_num_threads(max(1, os.cpu_count() or 1))


def train_cnn(x_train: list[str], y_train: np.ndarray, x_val: list[str] | None, y_val: np.ndarray | None, seed: int,
              epochs: int = 15, patience: int = 3, batch_size: int = 64, lr: float = 2e-3) -> tuple[object, dict]:
    from sklearn.metrics import average_precision_score

    _set_threads()
    torch.manual_seed(seed)
    np.random.seed(seed)
    fixed = x_val is None  # no validation set: train exactly `epochs` epochs (used for out-of-fold stacking)
    xt = torch.from_numpy(encode(x_train))
    xv = None if fixed else torch.from_numpy(encode(x_val))
    yt = torch.tensor(np.asarray(y_train), dtype=torch.float32)
    model = ByteCNN()
    pos = float(yt.sum())
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor((len(yt) - pos) / max(pos, 1.0)))
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    gen = torch.Generator().manual_seed(seed)
    best_ap, best_state, bad, history = -1.0, None, 0, []
    t0 = time.perf_counter()
    for epoch in range(1, epochs + 1):
        model.train()
        perm = torch.randperm(len(xt), generator=gen)
        total = 0.0
        for i in range(0, len(perm), batch_size):
            idx = perm[i: i + batch_size]
            opt.zero_grad()
            loss = loss_fn(model(xt[idx]), yt[idx])
            loss.backward()
            opt.step()
            total += loss.item() * len(idx)
        if fixed:
            history.append({"epoch": epoch, "train_loss": round(total / len(xt), 4)})
            continue
        ap = float(average_precision_score(y_val, predict_proba(model, xv)))
        history.append({"epoch": epoch, "train_loss": round(total / len(xt), 4), "val_pr_auc": round(ap, 4)})
        if ap > best_ap:
            best_ap, best_state, bad = ap, {k: v.clone() for k, v in model.state_dict().items()}, 0
        else:
            bad += 1
            if bad >= patience:
                break
    if not fixed:
        model.load_state_dict(best_state)
    model.eval()
    return model, {"history": history, "best_val_pr_auc": round(best_ap, 4),
                   "train_seconds": round(time.perf_counter() - t0, 1),
                   "params": sum(p.numel() for p in model.parameters()), "threads": torch.get_num_threads()}


def predict_proba(model, x) -> np.ndarray:
    """x: list[str] or an already-encoded tensor."""
    if not isinstance(x, torch.Tensor):
        x = torch.from_numpy(encode(list(x)))
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(x), 512):
            out.append(torch.sigmoid(model(x[i: i + 512])).numpy())
    return np.concatenate(out) if out else np.zeros(0)


def save(model, path: Path) -> None:
    torch.save(model.state_dict(), path)
    path.with_suffix(".json").write_text(json.dumps({"arch": "ByteCNN", "max_len": MAX_LEN}))


def load(path: Path):
    _set_threads()
    model = ByteCNN()
    model.load_state_dict(torch.load(path, map_location="cpu", weights_only=True))
    model.eval()
    return model
