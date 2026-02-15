#!/usr/bin/env bash
set -euo pipefail

VENV_DIR=".venv"

python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "[tool-check] nmap"
if command -v nmap >/dev/null 2>&1; then
  nmap --version | head -n 1
else
  echo "nmap is missing. Install nmap before running recon phases."
fi

echo "Setup complete. Activate with: source .venv/bin/activate"
