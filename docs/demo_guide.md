# Demo Guide

## Lab-safe Metasploit validation model

This project uses **Metasploit auxiliary scanners only** for service/version validation in a controlled lab.

- Allowed: `auxiliary/scanner/*` modules for benign fingerprinting.
- Blocked: all `exploit/*` and `post/*` modules.
- No payload generation, no sessions, no credential dumping, and no hash extraction.

This means the workflow demonstrates **vulnerability validation**, not exploitation. The scanner output is used to confirm that a target service/version appears to match the AI-ranked candidate.

## Evidence handling

During `--full-run`, Metasploit validation output is written to:

- `runs/<run_id>/raw/msf_validation.log`

The evidence collector includes this log in the manifest (`runs/<run_id>/report/evidence.json`) with SHA-256 hashes for integrity verification.

## Demo steps

1. Run `./setup.sh`.
2. Verify `config/whitelist.txt` contains only authorized targets.
3. Start dashboard: `python src/dashboard/app.py`.
4. Dry-run demo: `python scripts/demo_runner.py --target 192.168.56.101 --dry-run`.
   - This writes a note such as: `would run module X with options Y`.
5. Optional gated full-run benign validation:
   - set `enable_exploit_engine=true` and token in settings.
   - run with `--full-run --confirm-token <token>`.
   - review `runs/<run_id>/raw/msf_validation.log` and `runs/<run_id>/report/evidence.json`.
