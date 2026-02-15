#!/usr/bin/env python3
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.orchestrator import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Examiner-friendly phase-0 runner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--full-run", action="store_true")
    parser.add_argument("--confirm-token", default=None)
    args = parser.parse_args()

    steps = [
        "[1/5] whitelist check",
        "[2/5] run_id + folders",
        "[3/5] status.json + app.log",
        "[4/5] placeholder pipeline",
        "[5/5] completion summary",
    ]
    for step in steps:
        print(step)

    result = run_pipeline(
        target=args.target,
        dry_run=args.dry_run,
        full_run=args.full_run,
        confirm_token=args.confirm_token,
    )

    print("Run completed.")
    print(f"Run folder: {result['run_dir']}")
    print(f"Normalized scan JSON: {result['scan_json_path']}")


if __name__ == "__main__":
    main()
