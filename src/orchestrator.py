import argparse
import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.ai_brain.cve_mapper import load_cve_dataset, map_services_to_cves
from src.ai_brain.ml_predictor import rank_candidates, train_or_load_model
from src.exploit_engine.metasploit_wrapper import run_validation
from src.exploit_engine.sandbox import select_strategy
from src.learning_db.database import LearningDB
from src.post_exploit.evidence_collector import collect_evidence
from src.recon_engine.normalizer import parse_nmap_xml, write_normalized
from src.recon_engine.scanner import run_recon
from src.reporting.report_generator import generate_report


@dataclass
class RunContext:
    run_id: str
    root: Path
    dry_run: bool
    full_run_enabled: bool

    @property
    def run_dir(self):
        return self.root / "runs" / self.run_id

    @property
    def raw_dir(self):
        return self.run_dir / "raw"

    @property
    def logs_dir(self):
        return self.run_dir / "logs"

    @property
    def report_dir(self):
        return self.run_dir / "report"

    @property
    def evidence_dir(self):
        return self.run_dir / "evidence"

    @property
    def status_path(self):
        return self.run_dir / "status.json"


def load_settings(root):
    return json.loads((root / "config" / "settings.json").read_text())


def is_target_allowed(target, whitelist_path):
    ip = ipaddress.ip_address(target)
    for line in whitelist_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line and ip in ipaddress.ip_network(line, strict=False):
            return True
        if line == target:
            return True
    return False


def setup_logging(ctx):
    ctx.logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = ctx.logs_dir / "app.log"
    logging.basicConfig(level=logging.INFO, handlers=[logging.FileHandler(log_file), logging.StreamHandler()])
    return logging.getLogger("apa3")


def write_status(ctx, stage, extra=None):
    payload = {
        "run_id": ctx.run_id,
        "stage": stage,
        "dry_run": ctx.dry_run,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        payload.update(extra)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ctx.status_path.write_text(json.dumps(payload, indent=2))


def run_pipeline(target, dry_run=True, full_run=False, confirm_token=None):
    root = Path(__file__).resolve().parents[1]
    settings = load_settings(root)
    full_run_enabled = bool(full_run and settings.get("enable_exploit_engine") and confirm_token == settings.get("full_run_token"))
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    ctx = RunContext(run_id=run_id, root=root, dry_run=dry_run and not full_run_enabled, full_run_enabled=full_run_enabled)
    logger = setup_logging(ctx)

    if not is_target_allowed(target, root / "config" / "whitelist.txt"):
        raise ValueError(f"Target {target} not in authorized whitelist")

    db = LearningDB(root / "data" / "learning.db")
    write_status(ctx, "recon_started")
    recon = run_recon(target, ctx)
    normalized = parse_nmap_xml(recon["nmap_xml"], target)
    write_normalized(normalized, ctx.run_dir / "normalized.json")

    write_status(ctx, "ai_mapping")
    cve_data = load_cve_dataset(root / "data" / "cve_database" / "curated_cves.json")
    mapped = map_services_to_cves(normalized, cve_data)
    model = train_or_load_model(root / "data" / "models" / "model.joblib", root / "data" / "training_data" / "sample_training.json")
    ranked = rank_candidates(normalized, mapped, db, model)
    selected = select_strategy(ranked) if ranked else None

    write_status(ctx, "validation")
    action = run_validation(target, selected or {}, ctx)

    evidence = collect_evidence(ctx)
    if selected:
        db.insert_attempt({
            "run_id": ctx.run_id,
            "target_fingerprint": normalized.get("host_os_guess", "unknown"),
            "cve_id": selected["cve_id"],
            "exploit_id": action.get("module"),
            "features_json": selected.get("features", []),
            "success_bool": action.get("returncode", 0) == 0 if ctx.full_run_enabled else False,
            "evidence_paths": [e["path"] for e in evidence],
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    report = generate_report(ctx, {
        "title": settings.get("report_title"),
        "run_id": ctx.run_id,
        "target": target,
        "whitelist": (root / "config" / "whitelist.txt").read_text(),
        "normalized": normalized,
        "mapped": mapped,
        "ranked": ranked,
        "selected": selected,
        "action": action,
        "evidence": evidence,
        "dry_run": ctx.dry_run,
        "full_run_enabled": ctx.full_run_enabled,
    })
    write_status(ctx, "completed", {"report": str(report), "action": action})
    logger.info("Run completed: %s", ctx.run_id)
    return {"run_id": ctx.run_id, "report": str(report), "status": str(ctx.status_path)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--full-run", action="store_true")
    parser.add_argument("--confirm-token")
    args = parser.parse_args()
    result = run_pipeline(args.target, dry_run=args.dry_run or not args.full_run, full_run=args.full_run, confirm_token=args.confirm_token)
    print(json.dumps(result, indent=2))
