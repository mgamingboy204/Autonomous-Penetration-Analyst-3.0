import json
import sys

import pytest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.orchestrator import is_target_allowed, run_pipeline
from src.recon_engine.normalizer import normalize_nmap_xml


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


def test_normalizer_parses_ports_from_embedded_nmap_xml(tmp_path: Path):
    sample_xml = """<?xml version='1.0'?>
<nmaprun scanner='nmap' startstr='Tue Feb 11 10:00:00 2026'>
  <host>
    <status state='up' reason='syn-ack'/>
    <ports>
      <port protocol='tcp' portid='22'>
        <state state='open'/>
        <service name='ssh' product='OpenSSH' version='8.2p1' extrainfo='Ubuntu'/>
      </port>
      <port protocol='tcp' portid='80'>
        <state state='open'/>
        <service name='http' product='Apache httpd' version='2.4.41'/>
      </port>
      <port protocol='tcp' portid='443'>
        <state state='closed'/>
        <service name='https'/>
      </port>
    </ports>
    <os>
      <osmatch name='Linux 5.X' accuracy='98'/>
    </os>
  </host>
</nmaprun>
"""
    xml_path = tmp_path / "nmap.xml"
    out_path = tmp_path / "scan.json"
    xml_path.write_text(sample_xml, encoding="utf-8")

    normalized = normalize_nmap_xml(xml_path, "192.168.56.101", out_path)

    assert out_path.exists()
    assert normalized["target"] == "192.168.56.101"
    assert normalized["host_os_guess"] == "Linux 5.X"
    assert len(normalized["ports"]) == 2
    assert normalized["ports"][0]["port"] == 22
    assert normalized["ports"][0]["service"] == "ssh"
    assert normalized["ports"][1]["port"] == 80
    assert normalized["ports"][1]["service"] == "http"


def test_full_run_without_token_is_refused(tmp_path: Path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "whitelist.txt").write_text("192.168.56.0/24\n", encoding="utf-8")
    (tmp_path / "config" / "settings.json").write_text(
        json.dumps(
            {
                "enable_exploit_engine": True,
                "full_run_token": "VALID_TOKEN",
                "lab_network_cidrs": ["192.168.56.0/24"],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Full run denied"):
        run_pipeline(target="192.168.56.101", root=tmp_path, dry_run=False, full_run=True, confirm_token=None)
