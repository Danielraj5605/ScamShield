# Thin wrapper around `python -m scamshield <cmd>` (Windows users: run those commands directly).
PY ?= .venv/bin/python
RUN = PYTHONPATH=src $(PY) -m scamshield

.PHONY: setup download data train eval bench serve test evidence all clean

setup:          ## one-time environment setup on LinuxONE (or any Linux)
	bash scripts/setup_linuxone.sh

download:       ## fetch public datasets (checksummed)
	sh scripts/download_data.sh

data: download  ## build processed datasets + splits
	$(RUN) data

train:          ## train all models + learned ensemble
	$(RUN) train

eval:           ## evaluate on all test sets -> reports/metrics_<arch>.{json,md}
	$(RUN) eval

bench:          ## latency/throughput -> reports/bench_<arch>.json
	$(RUN) bench

serve:          ## API + web UI on 127.0.0.1:8000 (use an SSH tunnel to view)
	$(RUN) serve

test:           ## unit, integration, privacy and demo tests
	PYTHONPATH=src $(PY) -m pytest -q

evidence:       ## platform fingerprint + package versions + git commit -> docs/evidence/
	$(RUN) evidence

all: data train eval test bench evidence

clean:
	rm -rf artifacts/* data/processed/* .pytest_cache
