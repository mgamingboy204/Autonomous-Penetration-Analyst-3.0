# Demo Guide

1. Run `./setup.sh`.
2. Verify `config/whitelist.txt` contains only authorized targets.
3. Dry-run demo: `python scripts/demo_runner.py --target 192.168.56.101 --dry-run`.
4. Open `runs/<run_id>/report/report.html`.
5. Start dashboard: `python src/dashboard/app.py`.
6. Optional gated full-run benign validation:
   - set `enable_exploit_engine=true` and token in settings.
   - run with `--full-run --confirm-token <token>`.
