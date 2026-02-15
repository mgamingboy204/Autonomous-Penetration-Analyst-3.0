# Demo Guide

## Why auxiliary modules are used

This project performs **safe vulnerability validation only**. It intentionally uses only Metasploit **auxiliary scanner modules** to validate service fingerprints against AI-ranked candidates.

- Allowed: `auxiliary/scanner/*` modules for benign checks (for example version scanning).
- Blocked: all `exploit/*` and `post/*` modules.
- Out of scope: payload delivery, shell access, credential dumping, hash extraction.

This keeps the workflow academic, reproducible, and examiner-friendly while still providing evidence that a ranked service/CVE candidate was technically validated.

## Dry-run vs safe full-run

- **Dry-run (`--dry-run`)**
  - No Metasploit RPC action is executed.
  - The orchestrator writes a simulated action to `runs/<run_id>/raw/exploit_simulation.log`.

- **Safe full-run (`--full-run --confirm-token <token>` with dry-run disabled)**
  - Gating checks are evaluated and logged (`dry_run`, `full_run`, `enable_exploit_engine`, `token_match`, `target_in_lab`).
  - The highest-ranked candidate service is mapped to a safe auxiliary module.
  - Metasploit RPC executes that auxiliary scanner and output is saved to `runs/<run_id>/raw/msf_validation.log`.
  - Evidence manifest includes SHA-256 hashes for validation output.

## Metasploit RPC startup requirement

For examiner demos, start `msfrpcd` manually before a full-run:

```bash
msfrpcd -P DEMO_PASS -S -a 127.0.0.1
```

The orchestrator can attempt to start RPC if unavailable, but manual startup is preferred during demonstrations for deterministic behavior.

## Examiner walkthrough (sample)

1. Confirm target is inside `config/whitelist.txt` and `config/settings.json` lab CIDRs.
2. Run dry-run first:
   ```bash
   python3 scripts/demo_runner.py --target 192.168.224.129 --dry-run
   ```
3. Enable safe full-run gates in settings (`enable_exploit_engine=true`, valid token).
4. Start Metasploit RPC:
   ```bash
   msfrpcd -P DEMO_PASS -S -a 127.0.0.1
   ```
5. Execute safe full-run:
   ```bash
   python3 scripts/demo_runner.py --target 192.168.224.129 --full-run --confirm-token DEMO123
   ```
6. Review evidence:
   - `runs/<run_id>/raw/msf_validation.log`
   - `runs/<run_id>/report/evidence.json`
   - `runs/<run_id>/logs/app.log` (gating and decision trace)
