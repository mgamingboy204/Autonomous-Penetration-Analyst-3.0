import argparse
import ipaddress
import json
import logging
import random
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.ai_brain.cve_mapper import map_scan_to_cves
from src.recon_engine.normalizer import normalize_nmap_xml
from src.recon_engine.scanner import run_nmap

ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = ROOT / "config" / "settings.json"
WHITELIST_PATH = ROOT / "config" / "whitelist.txt"


def load_settings(path: Path = SETTINGS_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def is_target_allowed(target: str, whitelist_path: Path = WHITELIST_PATH) -> bool:
    ip = ipaddress.ip_address(target)
    for raw_line in whitelist_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line:
            if ip in ipaddress.ip_network(line, strict=False):
                return True
        elif line == target:
            return True
    return False


def create_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{ts}_{suffix}"


def setup_run_directories(root: Path, run_id: str) -> dict[str, Path]:
    run_dir = root / "runs" / run_id
    paths = {
        "run_dir": run_dir,
        "raw": run_dir / "raw",
        "normalized": run_dir / "normalized",
        "logs": run_dir / "logs",
        "report": run_dir / "report",
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return paths


def setup_logging(log_path: Path) -> logging.Logger:
    logger = logging.getLogger("apa3")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def write_status(status_path: Path, status_data: dict[str, Any]) -> None:
    status_path.write_text(json.dumps(status_data, indent=2), encoding="utf-8")


def update_step(
    status_path: Path,
    status_data: dict[str, Any],
    step: str,
    logger: logging.Logger,
    details: dict[str, Any] | None = None,
) -> None:
    step_payload: dict[str, Any] = {
        "state": "done",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if details:
        step_payload["details"] = details

    status_data["steps"][step] = step_payload
    status_data["current_step"] = step
    write_status(status_path, status_data)
    logger.info("Step complete: %s", step)


def run_pipeline(
    target: str,
    dry_run: bool = True,
    full_run: bool = False,
    confirm_token: str | None = None,
    root: Path = ROOT,
) -> dict[str, str]:
    settings = load_settings(root / "config" / "settings.json")

    if not is_target_allowed(target, root / "config" / "whitelist.txt"):
        raise ValueError(f"Target {target} is not in config/whitelist.txt")

    if full_run:
        expected_token = settings.get("full_run_token")
        exploit_enabled = settings.get("enable_exploit_engine", False)
        if not exploit_enabled or confirm_token != expected_token:
            raise ValueError("Full run denied: exploit engine disabled or invalid token")

    run_id = create_run_id()
    paths = setup_run_directories(root, run_id)
    status_path = paths["run_dir"] / "status.json"
    logger = setup_logging(paths["logs"] / "app.log")

    status_data: dict[str, Any] = {
        "run_id": run_id,
        "target": target,
        "dry_run": dry_run,
        "full_run": full_run,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "current_step": "initialized",
        "steps": {},
        "artifacts": {},
    }
    write_status(status_path, status_data)
    logger.info("Initialized run %s for target %s", run_id, target)

    print("[pipeline] recon_started")
    update_step(status_path, status_data, "recon_started", logger)

    scan_paths = run_nmap(target=target, out_dir=paths["raw"], logger=logger)
    status_data["artifacts"]["nmap_xml"] = scan_paths["xml_path"]
    status_data["artifacts"]["nmap_txt"] = scan_paths["txt_path"]
    status_data["artifacts"]["nmap_run_log"] = scan_paths["run_log_path"]
    print("[pipeline] recon_done")
    update_step(status_path, status_data, "recon_done", logger, details=scan_paths)

    scan_json_path = paths["normalized"] / "scan.json"
    normalized = normalize_nmap_xml(Path(scan_paths["xml_path"]), target, scan_json_path)
    status_data["artifacts"]["scan_json"] = str(scan_json_path)
    print("[pipeline] normalize_done")
    update_step(
        status_path,
        status_data,
        "normalize_done",
        logger,
        details={"scan_json": str(scan_json_path), "open_ports": len(normalized["ports"])},
    )

    cves_json_path = paths["normalized"] / "cves.json"
    cve_matches = map_scan_to_cves(normalized)
    cves_json_path.write_text(json.dumps(cve_matches, indent=2), encoding="utf-8")
    status_data["artifacts"]["cves_json"] = str(cves_json_path)
    print("[pipeline] ai_done")
    update_step(
        status_path,
        status_data,
        "ai_done",
        logger,
        details={"cves_json": str(cves_json_path), "candidate_count": len(cve_matches)},
    )

    exploit_note = "Dry run enabled; exploit step skipped" if dry_run else "Exploit phase not implemented in Phase 1"
    print("[pipeline] exploit_skipped")
    update_step(status_path, status_data, "exploit_skipped", logger, details={"note": exploit_note})

    print("[pipeline] report_skipped")
    update_step(status_path, status_data, "report_skipped", logger, details={"note": "Reporting phase not implemented in Phase 1"})

    logger.info("Phase-1 run completed")

    return {
        "run_id": run_id,
        "run_dir": str(paths["run_dir"]),
        "status_path": str(status_path),
        "log_path": str(paths["logs"] / "app.log"),
        "scan_json_path": str(scan_json_path),
        "cves_json_path": str(cves_json_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="APA3 phase-1 orchestrator")
    parser.add_argument("--target", required=True, help="Target IPv4 address")
    parser.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--full-run", action="store_true", help="Requires enabled settings + valid token")
    parser.add_argument("--confirm-token", default=None)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = run_pipeline(
        target=args.target,
        dry_run=args.dry_run,
        full_run=args.full_run,
        confirm_token=args.confirm_token,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
