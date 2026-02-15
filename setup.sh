#!/usr/bin/env bash
set -euo pipefail
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

echo "[tool-check] nmap"
command -v nmap >/dev/null && nmap --version | head -n 1 || echo "nmap missing (required)"
for t in whatweb naabu amass httprobe msfconsole; do
  command -v "$t" >/dev/null && echo "$t found" || echo "$t missing (optional for demo)"
done

echo "Setup complete."
