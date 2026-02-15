import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import json

from src.orchestrator import is_target_allowed, run_pipeline

def test_whitelist_validator_exact_and_cidr(tmp_path: Path):
    whitelist = tmp_path / "whitelist.txt"
    whitelist.write_text("192.168.56.0/24\n10.10.10.10\n", encoding="utf-8")

    assert is_target_allowed("192.168.56.101", whitelist)
    assert is_target_allowed("10.10.10.10", whitelist)
    assert not is_target_allowed("8.8.8.8", whitelist)


def test_run_folder_creation(tmp_path: Path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "whitelist.txt").write_text("192.168.56.0/24\n", encoding="utf-8")
    (tmp_path / "config" / "settings.json").write_text(
        json.dumps(
            {
                "enable_exploit_engine": False,
                "full_run_token": "CHANGE_ME",
                "lab_network_cidrs": ["192.168.56.0/24"],
                "report_title": "Autonomous Penetration Analyst 3.0 Lab Report",
            }
        ),
        encoding="utf-8",
    )

    result = run_pipeline(target="192.168.56.101", root=tmp_path)
    run_dir = Path(result["run_dir"])

    assert run_dir.exists()
    assert (run_dir / "raw").exists()
    assert (run_dir / "normalized").exists()
    assert (run_dir / "logs").exists()
    assert (run_dir / "report").exists()


def test_status_json_structure(tmp_path: Path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "whitelist.txt").write_text("192.168.56.0/24\n", encoding="utf-8")
    (tmp_path / "config" / "settings.json").write_text(
        json.dumps(
            {
                "enable_exploit_engine": False,
                "full_run_token": "CHANGE_ME",
                "lab_network_cidrs": ["192.168.56.0/24"],
                "report_title": "Autonomous Penetration Analyst 3.0 Lab Report",
            }
        ),
        encoding="utf-8",
    )

    result = run_pipeline(target="192.168.56.101", root=tmp_path)
    status = json.loads(Path(result["status_path"]).read_text(encoding="utf-8"))

    assert status["run_id"]
    assert status["target"] == "192.168.56.101"
    assert status["dry_run"] is True
    for step in [
        "recon_started",
        "recon_done",
        "normalize_done",
        "ai_done",
        "exploit_skipped",
        "report_skipped",
    ]:
        assert step in status["steps"]
        assert status["steps"][step]["state"] == "done"