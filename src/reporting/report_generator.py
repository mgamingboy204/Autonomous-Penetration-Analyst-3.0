import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.post_exploit.evidence_collector import sha256_file

ROOT = Path(__file__).resolve().parents[2]


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_whitelist(whitelist_path: Path) -> list[str]:
    if not whitelist_path.exists():
        return []
    entries: list[str] = []
    for raw_line in whitelist_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def _build_evidence_manifest(run_id: str, run_dir: Path) -> dict[str, Any]:
    evidence_path = run_dir / "report" / "evidence.json"
    if evidence_path.exists():
        return _load_json(evidence_path, {})

    files: list[dict[str, str]] = []
    for folder in ["raw", "normalized", "logs", "evidence", "report"]:
        folder_path = run_dir / folder
        if not folder_path.exists():
            continue
        for file_path in sorted(folder_path.rglob("*")):
            if file_path.is_file() and file_path.name != "report.html":
                stat = file_path.stat()
                files.append(
                    {
                        "path": str(file_path.relative_to(run_dir)),
                        "sha256": sha256_file(file_path),
                        "timestamp": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    }
                )

    return {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_count": len(files),
        "files": files,
    }


def build_report(run_id: str, root: Path = ROOT) -> Path:
    run_dir = root / "runs" / run_id
    if not run_dir.exists():
        raise FileNotFoundError(f"Run not found: {run_id}")

    template_text = (root / "templates" / "report_template.html").read_text(encoding="utf-8")

    status = _load_json(run_dir / "status.json", {})
    normalized = _load_json(run_dir / "normalized" / "scan.json", {})
    mapped = _load_json(run_dir / "normalized" / "cves.json", [])
    ranked = _load_json(run_dir / "normalized" / "ranked.json", [])

    whitelist_entries = _read_whitelist(root / "config" / "whitelist.txt")
    target = status.get("target", "unknown")
    whitelist_match = "yes" if any(target == w for w in whitelist_entries) else "unknown/network rule"

    recon_services = []
    for port in normalized.get("ports", []):
        recon_services.append(
            {
                "port": port.get("port"),
                "protocol": port.get("protocol", "tcp"),
                "service": port.get("service", "unknown"),
                "version": port.get("version", ""),
            }
        )

    mapped_rows = [
        {
            "cve_id": item.get("cve_id", ""),
            "service": item.get("matched_service", {}).get("service", ""),
            "port": item.get("matched_service", {}).get("port", ""),
            "cvss": item.get("cvss", ""),
            "description": item.get("description", ""),
        }
        for item in mapped
    ]

    ranked_rows = [
        {
            "cve_id": item.get("cve_id", ""),
            "prob": item.get("prob", item.get("success_probability", "")),
            "utility": item.get("utility", ""),
            "reasoning": item.get("reasoning", ""),
        }
        for item in ranked
    ]

    action_details = {
        "current_step": status.get("current_step"),
        "steps": status.get("steps", {}),
        "artifacts": status.get("artifacts", {}),
    }

    evidence_manifest = _build_evidence_manifest(run_id, run_dir)
    report_dir = run_dir / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "evidence.json").write_text(json.dumps(evidence_manifest, indent=2), encoding="utf-8")

    context = {
        "title": "Autonomous Penetration Analyst Report",
        "run_id": run_id,
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": status.get("dry_run", True),
        "full_run": status.get("full_run", False),
        "whitelist_entries": "\n".join(whitelist_entries) if whitelist_entries else "No whitelist entries found.",
        "whitelist_match": whitelist_match,
        "recon_services": recon_services,
        "mapped": mapped_rows,
        "ranked": ranked_rows,
        "action_details": json.dumps(action_details, indent=2),
        "evidence_files": evidence_manifest.get("files", []),
    }

    try:
        from jinja2 import Template

        html = Template(template_text).render(**context)
    except Exception:
        html = template_text
        for key, value in context.items():
            html = html.replace("{{ " + key + " }}", str(value))

    out = report_dir / "report.html"
    out.write_text(html, encoding="utf-8")
    return out


def generate_report(run_ctx, context):
    template_text = Path("templates/report_template.html").read_text(encoding="utf-8")
    try:
        from jinja2 import Template

        html = Template(template_text).render(**context)
    except Exception:
        html = template_text
        for key, value in context.items():
            html = html.replace("{{ " + key + " }}", str(value))
    run_ctx.report_dir.mkdir(parents=True, exist_ok=True)
    out = run_ctx.report_dir / "report.html"
    out.write_text(html, encoding="utf-8")
    return out
