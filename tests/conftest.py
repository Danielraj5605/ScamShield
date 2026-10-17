import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

ARTIFACTS_READY = (ROOT / "artifacts" / "meta.json").exists()
needs_artifacts = pytest.mark.skipif(not ARTIFACTS_READY, reason="run `python -m scamshield train` first")


@pytest.fixture(scope="session")
def shield():
    if not ARTIFACTS_READY:
        pytest.skip("no trained artifacts")
    from scamshield.pipeline import ScamShield
    return ScamShield()
