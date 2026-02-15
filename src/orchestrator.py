import argparse
import ipaddress
import json
import logging
import random
import string
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.ai_brain.cve_mapper import map_scan_to_cves
from src.ai_brain.ml_predictor import predict_and_rank
from src.exploit_engine.metasploit_wrapper import MetasploitRPCClient, select_validation_module, simulate, write_validation_log
from src.learning_db.database import LearningDB
from src.post_exploit.evidence_collector import collect_evidence
from src.recon_engine.normalizer import normalize_nmap_xml
from src.recon_engine.scanner import run_nmap

ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = ROOT / "config" / "settings.json"
WHITELIST_PATH = ROOT / "config" / "whitelist.txt"


@dataclass
class RunContext:
    run_id: str
    target: str
    run_dir: Path
    raw_dir: Path
    normalized_dir: Path
    logs_dir: Path
    report_dir: Path
    evidence_dir: Path
    full_run_enabled: bool


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


def is_target_in_lab_network(target: str, lab_network_cidrs: list[str]) -> bool:
    ip = ipaddress.ip_address(target)
    for cidr in lab_network_cidrs:
        if ip in ipaddress.ip_network(cidr, strict=False):
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
        "evidence": run_dir / "evidence",
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


def _build_ranked_choice(candidate: dict[str, Any] | None) -> dict[str, Any] | None:
    if not candidate:
        return None
    matched = candidate.get("matched_service", {})
    return {
        "cve_id": candidate.get("cve_id"),
        "service": matched.get("service"),
        "port": matched.get("port"),
        "utility": candidate.get("utility"),
        "prob": candidate.get("prob"),
    }


def run_pipeline(
    target: str,
    dry_run: bool = True,
    full_run: bool = False,
    confirm_token: str | None = None,
    root: Path = ROOT,
) -> dict[str, str]:
    settings = load_settings(root / "config" / "settings.json")

    if full_run and dry_run:
        dry_run = False

    if not is_target_allowed(target, root / "config" / "whitelist.txt"):
        raise ValueError(f"Target {target} is not in config/whitelist.txt")

    expected_token = settings.get("full_run_token")
    token_match = bool(confirm_token and confirm_token == expected_token)
    target_in_lab = is_target_in_lab_network(target, settings.get("lab_network_cidrs", []))

    if full_run and (not token_match or not target_in_lab):
        raise ValueError("Full run denied: exploit engine disabled or invalid token")

    run_id = create_run_id()
    paths = setup_run_directories(root, run_id)
    status_path = paths["run_dir"] / "status.json"
    logger = setup_logging(paths["logs"] / "app.log")

    run_ctx = RunContext(
        run_id=run_id,
        target=target,
        run_dir=paths["run_dir"],
        raw_dir=paths["raw"],
        normalized_dir=paths["normalized"],
        logs_dir=paths["logs"],
        report_dir=paths["report"],
        evidence_dir=paths["evidence"],
        full_run_enabled=full_run,
    )

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

    learning_db = LearningDB(root / "data" / "learning.db")
    ranked_json_path = paths["normalized"] / "ranked.json"
    ranked_candidates = predict_and_rank(normalized, cve_matches, db=learning_db)
    ranked_json_path.write_text(json.dumps(ranked_candidates, indent=2), encoding="utf-8")

    planned_attempts: list[dict[str, Any]] = []
    planned_success = 0 if dry_run else None
    for candidate in ranked_candidates:
        matched_service = candidate.get("matched_service", {})
        service = str(matched_service.get("service") or "unknown")
        cve_id = str(candidate.get("cve_id") or "")
        attempt_id = learning_db.record_attempt(
            run_id=run_id,
            target=target,
            service=service,
            cve_id=cve_id,
            features={
                "prob": candidate.get("prob"),
                "utility": candidate.get("utility"),
                "cvss": candidate.get("cvss"),
                "matched_service": matched_service,
            },
            success=planned_success,
            evidence={"state": "planned", "dry_run": dry_run},
        )
        planned_attempts.append({"attempt_id": attempt_id, "service": service, "cve_id": cve_id})

    status_data["artifacts"]["cves_json"] = str(cves_json_path)
    status_data["artifacts"]["ranked_json"] = str(ranked_json_path)
    status_data["artifacts"]["learning_db"] = str(root / "data" / "learning.db")
    print("[pipeline] ai_done")
    update_step(
        status_path,
        status_data,
        "ai_done",
        logger,
        details={
            "cves_json": str(cves_json_path),
            "ranked_json": str(ranked_json_path),
            "candidate_count": len(cve_matches),
            "ranked_count": len(ranked_candidates),
            "planned_attempt_count": len(planned_attempts),
        },
    )

    top_candidate = ranked_candidates[0] if ranked_candidates else None
    ranked_choice = _build_ranked_choice(top_candidate)

    logger.info(
        "Validation gates | dry_run=%s full_run=%s enable_exploit_engine=%s token_match=%s target_in_lab=%s",
        dry_run,
        full_run,
        settings.get("enable_exploit_engine", False),
        token_match,
        target_in_lab,
    )

    validate = bool(full_run and not dry_run and settings.get("enable_exploit_engine", False))

    if validate:
        selected = select_validation_module(target, ranked_choice)
        if selected.module_name is None:
            validation_result = {
                "success": False,
                "output": selected.reason,
                "artifacts": [],
                "module": None,
                "options": {},
                "evidence_files": [],
            }
            logger.info("Safe validation skipped: %s", selected.reason)
        else:
            if hasattr(MetasploitRPCClient, "from_config"):
                client = MetasploitRPCClient.from_config(root / "config" / "settings.json")
            else:  # pragma: no cover - test doubles
                client = MetasploitRPCClient()

            smoke_result: dict[str, Any] | None = None
            validation_error: Exception | None = None
            try:
                if hasattr(client, "smoke_test"):
                    smoke_result = client.smoke_test()
                validation_result = client.run_aux_module(selected.module_name, selected.options)
            except Exception as exc:
                validation_error = exc
                validation_result = {
                    "success": False,
                    "output": f"Metasploit safe validation failed: {exc}",
                    "artifacts": [],
                }
            finally:
                client.stop_rpc()

            log_path = run_ctx.raw_dir / "msf_validation.log"
            write_validation_log(log_path, selected.module_name, selected.options, validation_result)
            debug_path = run_ctx.raw_dir / "msf_rpc_debug.json"
            debug_payload = dict(getattr(client, "debug_trace", {}))
            if smoke_result is not None:
                debug_payload["smoke_test"] = {
                    "scheme": smoke_result.get("scheme"),
                    "endpoint": smoke_result.get("endpoint"),
                    "host": smoke_result.get("host"),
                    "port": smoke_result.get("port"),
                    "auth_result": smoke_result.get("auth_result"),
                }
            if validation_error is not None:
                debug_payload["validation_error"] = str(validation_error)
            debug_path.write_text(json.dumps(debug_payload, indent=2), encoding="utf-8")

            validation_result["module"] = selected.module_name
            validation_result["options"] = selected.options
            validation_result["evidence_files"] = [str(log_path)]
            validation_result["artifacts"] = list(validation_result.get("artifacts", [])) + [str(log_path), str(debug_path)]
            status_data["artifacts"]["msf_rpc_debug_json"] = str(debug_path)

        for attempt in planned_attempts:
            matched = attempt["cve_id"] == str((ranked_choice or {}).get("cve_id") or "")
            learning_db.update_attempt(
                attempt["attempt_id"],
                success=1 if matched and validation_result["success"] else 0,
                evidence={"state": "safe_validation", "selected": matched, "result": validation_result},
            )

        status_data["artifacts"]["safe_validation_evidence"] = validation_result.get("evidence_files", [])
        if validation_result.get("evidence_files"):
            status_data["artifacts"]["msf_validation_log"] = validation_result["evidence_files"][0]

        evidence_manifest = collect_evidence(run_ctx, validation_result.get("artifacts", []))
        status_data["artifacts"]["evidence_manifest"] = str(run_ctx.report_dir / "evidence.json")
        status_data["artifacts"]["evidence_count"] = evidence_manifest["evidence_count"]

        print("[pipeline] exploit_done")
        update_step(
            status_path,
            status_data,
            "exploit_done",
            logger,
            details={"exploit_skipped": False, "mode": "safe_full_run", "result": validation_result},
        )
    else:
        logger.info("Safe validation skipped by gating decision")
        if dry_run:
            simulation_result = simulate(run_ctx, ranked_choice)
            for attempt in planned_attempts:
                learning_db.update_attempt(
                    attempt["attempt_id"],
                    success=0,
                    evidence={"state": "simulated", "result": simulation_result},
                )
            status_data["artifacts"]["exploit_simulation_log"] = str(run_ctx.raw_dir / "exploit_simulation.log")
            details = {"exploit_skipped": True, "mode": "simulate", "result": simulation_result}
        else:
            for attempt in planned_attempts:
                learning_db.update_attempt(
                    attempt["attempt_id"],
                    success=0,
                    evidence={"state": "skipped", "reason": "gating_decision_false"},
                )
            details = {"exploit_skipped": True, "reason": "gating_decision_false"}

        print("[pipeline] exploit_skipped")
        update_step(status_path, status_data, "exploit_skipped", logger, details=details)

    print("[pipeline] report_skipped")
    update_step(status_path, status_data, "report_skipped", logger, details={"note": "Reporting phase not implemented in Phase 5"})

    logger.info("Phase-5 run completed")

    return {
        "run_id": run_id,
        "run_dir": str(paths["run_dir"]),
        "status_path": str(status_path),
        "log_path": str(paths["logs"] / "app.log"),
        "scan_json_path": str(scan_json_path),
        "cves_json_path": str(cves_json_path),
        "ranked_json_path": str(ranked_json_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="APA3 phase-5 orchestrator")
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
