# Running ScamShield on IBM LinuxONE

This is the exact procedure for getting a LinuxONE server, deploying ScamShield on it, and collecting the evidence that it runs on IBM Z (s390x).

> Event details below (event code, flavour, one server per team) come from the IBM Z Datathon 2026 setup session as summarised in `IBM_Datathon.md`. Confirm them against the official Hack2Skill guidebook and the organisers' setup link.

## 1. Get a server (LinuxONE Community Cloud)

1. **IBM ID:** create one at <https://www.ibm.com/account/> if you don't have one.
2. **Register:** open the LinuxONE Community Cloud registration link **from the official Datathon / Hack2Skill materials** (don't use a link from a search engine). Fill in the form and enter the event code **`SSF2026`**. This is what gives you the datathon image and the 3 vCPU / 8 GB flavour.
3. **Activate:** click the activation link in the email you receive (check spam), then sign in.
4. **Create an SSH key** on your laptop (Git Bash / PowerShell / macOS / Linux):
   ```bash
   ssh-keygen -t ed25519 -C "scamshield-l1cc" -f ~/.ssh/l1cc_datathon
   ```
   You'll upload `~/.ssh/l1cc_datathon.pub`. **Never share or commit the private key** (`~/.ssh/l1cc_datathon`).
5. **Create the instance:**
   - In the dashboard, open **Manage Instances / Virtual Servers → Create**.
   - Choose the image ending in **`-datathon`**. Pick **Ubuntu** if offered, preferably 24.04: it ships scikit-learn 1.4, while ScamShield needs ≥ 1.2.
   - Choose the **AI-labs flavour** (3 vCPU / 8 GB).
   - Select or import your public key.
   - Each team gets **one** server.
6. Wait until the status is **Active**. Note the **public IP** and the **username** shown in the portal.
7. **Connect:**
   ```bash
   ssh -i ~/.ssh/l1cc_datathon <USER>@<IP>
   uname -m        # must print: s390x
   ```
   Optional `~/.ssh/config` entry, so `ssh l1cc` works:
   ```
   Host l1cc
       HostName <IP>
       User <USER>
       IdentityFile ~/.ssh/l1cc_datathon
       ServerAliveInterval 60
   ```

If the `-datathon` image or flavour isn't visible, the event code probably wasn't applied. Ask in the event Discord/support channel rather than picking a random flavour.

## 2. Deploy

```bash
ssh l1cc
tmux new -s app                                  # survives SSH disconnects (re-attach: tmux attach -t app)
git clone https://github.com/Danielraj5605/ScamShield.git scamshield && cd scamshield
make setup        # system packages + venv + optional PyTorch, writes docs/evidence/platform_s390x.json
make data         # downloads datasets (checksummed) and builds splits
make train        # trains every model ON s390x  (about 11 min on the 3-vCPU VM)
make eval         # reports/metrics_s390x.{json,md}
make test         # unit, API, privacy and demo tests
make bench        # reports/bench_s390x.json
make serve        # API + UI on 127.0.0.1:8000
```

View the UI from your laptop through an SSH tunnel. Don't open public ports on a shared cloud:

```bash
ssh -L 8000:127.0.0.1:8000 l1cc      # then open http://127.0.0.1:8000
```

The page footer shows **"Running on IBM LinuxONE (s390x)"**, read live from the server.

PyTorch installed from a prebuilt s390x wheel on the datathon image, after `libopenblas0` was added (`make setup` does this).

**If PyTorch can't be installed** (no s390x wheel), run `PYTHONPATH=src .venv/bin/python -m scamshield train --no-cnn`. Everything still works with the classical models, and the report states that the neural model was off.

## 3. Why the models are trained on the server

s390x is **big-endian**, while laptops are little-endian. Binary model files built on a laptop can be misread on IBM Z; the 2025 Datathon winners hit exactly this with PyTorch. ScamShield therefore:

- trains every model on the LinuxONE VM itself,
- records `trained_on_arch` in `artifacts/meta.json`,
- **refuses to load** artifacts trained on a different architecture (override only with `SS_ALLOW_ARCH_MISMATCH=1`).

## 4. What runs where

| Component | Runs on |
|---|---|
| Data processing, synthetic data generation | IBM LinuxONE (s390x) |
| Training: TF-IDF model, neural CNN, URL models, ensemble | IBM LinuxONE |
| Evaluation, benchmark, tests | IBM LinuxONE |
| API + web UI server | IBM LinuxONE |
| Browser | User's laptop (client only, through an SSH tunnel) |
| Optional GenAI explanation | Free hosted LLM API (receives only the scrubbed text). Off by default; the template explanation is used instead |
| Code editing | Laptops (never used for reported numbers) |

## 5. Evidence to collect (commit to `docs/evidence/`)

| Evidence | How |
|---|---|
| Platform fingerprint, package versions, git commit | `make evidence` → `platform_s390x.json` |
| Training log | `make train 2>&1 \| tee docs/evidence/train_s390x.log` |
| Test log | `make test 2>&1 \| tee docs/evidence/tests_s390x.log` |
| Metrics | `reports/metrics_s390x.md/json` (contains `arch: s390x`) |
| Benchmark | `reports/bench_s390x.json` |
| Screenshots | Terminal showing `uname -m` next to the UI footer "Running on IBM LinuxONE (s390x)"; `/api/health` JSON |
| Screen recording | 60–90 s: `ssh`, `uname -m`, `make serve`, UI analysing the demo messages |

## 6. Optional: IBM Z AI accelerator check

```bash
grep -o -w nnpa /proc/cpuinfo | head -1   # present on z16/z17 if exposed to the VM
```

ScamShield's models run on the CPU through scikit-learn and PyTorch. **Do not claim** they use the Telum on-chip AI accelerator unless an accelerated runtime (e.g. IBM Z Accelerated for PyTorch / Snap ML) was actually installed and measured.

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `Permission denied (publickey)` | Use the username from the portal; `chmod 600 ~/.ssh/l1cc_datathon`; check that the right public key was attached |
| `scikit-learn ... too old` | `.venv/bin/pip install --upgrade scikit-learn` (may compile for a while on s390x), or use the Ubuntu 24.04 image |
| `ArchMismatchError` at startup | Artifacts came from another machine: run `make train` on this server |
| Training killed (out of memory) | `dmesg \| grep -i kill`; close other processes; run `train --no-cnn` |
| SSH session drops during training | Always run inside `tmux` |
| UI not reachable | Keep the tunnel terminal open; check that `make serve` is running in tmux |
