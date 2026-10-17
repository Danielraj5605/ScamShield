#!/usr/bin/env bash
# One-time environment setup on the IBM LinuxONE Community Cloud VM (Ubuntu or RHEL, s390x).
# Safe to re-run. Prefers packages that are already installed or available as distro builds for s390x,
# and only falls back to pip binary wheels, so nothing slow is compiled from source by accident.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

echo "== platform =="
uname -m; grep PRETTY_NAME /etc/os-release || true; nproc; free -h | head -2
[ "$(uname -m)" = "s390x" ] || echo "WARNING: this is not s390x; the IBM Z evidence must come from the LinuxONE VM."

echo "== system packages =="
if command -v apt-get >/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y python3-venv python3-pip git curl unzip tmux sqlite3 \
    python3-numpy python3-pandas python3-sklearn python3-joblib python3-flask libopenblas0 libgomp1 || true
elif command -v dnf >/dev/null; then
  sudo dnf install -y python3 python3-pip git curl unzip tmux sqlite \
    python3-numpy python3-pandas python3-scikit-learn python3-joblib python3-flask || true
fi

echo "== virtualenv (sees system packages) =="
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null

need() { python - "$1" <<'EOF'
import importlib, sys
try:
    importlib.import_module(sys.argv[1]); sys.exit(0)
except Exception:
    sys.exit(1)
EOF
}
for spec in "numpy:numpy>=1.21" "pandas:pandas>=1.3" "sklearn:scikit-learn>=1.2" "joblib:joblib" "flask:flask>=2.0" "pytest:pytest"; do
  mod=${spec%%:*}; pkg=${spec#*:}
  if need "$mod"; then echo "ok      $mod"; else
    echo "install $pkg"; pip install --only-binary=:all: "$pkg" || pip install "$pkg"
  fi
done
python - <<'EOF'
import sklearn, sys
v = tuple(int(x) for x in sklearn.__version__.split(".")[:2])
if v < (1, 2):
    sys.exit(f"scikit-learn {sklearn.__version__} is too old (need >= 1.2): run  pip install --upgrade scikit-learn")
print("scikit-learn", sklearn.__version__)
EOF

echo "== optional: PyTorch for the neural model =="
if need torch; then echo "ok      torch (already installed)"; else
  pip install --only-binary=:all: torch \
    || pip install --only-binary=:all: torch --index-url https://download.pytorch.org/whl/cpu \
    || echo "PyTorch has no binary wheel here: ScamShield will train without the neural model (use --no-cnn)."
fi

[ -f .env ] || cp .env.example .env
python -m scamshield evidence
echo "== setup done. Next: make data train eval bench serve =="
