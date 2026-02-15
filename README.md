# Autonomous Penetration Analyst 3.0 – Adaptive Cyber Attack Intelligence

Offline, academic penetration testing lab orchestrator for Kali Linux against authorized host-only targets only.

## Safety Model
- Offline/local datasets only.
- Strict whitelist enforcement (`config/whitelist.txt`).
- Default mode is `--dry-run`.
- Full-run requires all gates: `--full-run`, settings enabled, valid token.
- No payload generation, persistence, lateral movement, credential dumping, or destructive actions.

## Quick Start
```bash
./setup.sh
python scripts/demo_runner.py --target 192.168.56.101 --dry-run
python src/dashboard/app.py
```
