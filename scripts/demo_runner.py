#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.orchestrator import run_pipeline

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--full-run", action="store_true")
    parser.add_argument("--confirm-token")
    args = parser.parse_args()

    for step in [
        "[1/9] whitelist check ...",
        "[2/9] recon execution ...",
        "[3/9] normalization ...",
        "[4/9] local CVE mapping ...",
        "[5/9] ML risk prediction ...",
        "[6/9] strategy selection ...",
        "[7/9] controlled validation step ...",
        "[8/9] evidence collation ...",
        "[9/9] report generation ...",
    ]:
        print(step)

    result = run_pipeline(args.target, dry_run=args.dry_run or not args.full_run, full_run=args.full_run, confirm_token=args.confirm_token)
    print("Run complete")
    print("Report:", result["report"])
    print("Dashboard command: python src/dashboard/app.py")
