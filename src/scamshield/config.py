"""Paths, settings and small helpers shared by every module."""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "configs"
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
TEMPLATES_PATH = DATA_DIR / "templates" / "templates.json"
ARTIFACTS_DIR = ROOT / "artifacts"
REPORTS_DIR = ROOT / "reports"
KB_DIR = ROOT / "kb"
WEB_DIR = ROOT / "web"
EVIDENCE_DIR = ROOT / "docs" / "evidence"


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader (avoids a python-dotenv dependency). Real env vars win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


_load_dotenv(ROOT / ".env")


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def env_int(name: str, default: int) -> int:
    return int(env(name, str(default)))


def env_float(name: str, default: float) -> float:
    return float(env(name, str(default)))


def env_bool(name: str, default: bool) -> bool:
    return env(name, "1" if default else "0").lower() in {"1", "true", "yes", "on"}


SEED = env_int("SS_SEED", 42)
MAX_CHARS = env_int("SS_MAX_CHARS", 2000)


def load_json(name: str):
    return json.loads((CONFIG_DIR / name).read_text(encoding="utf-8"))


def load_lines(name: str) -> list[str]:
    lines = (CONFIG_DIR / name).read_text(encoding="utf-8").splitlines()
    return [l.strip().lower() for l in lines if l.strip() and not l.startswith("#")]
