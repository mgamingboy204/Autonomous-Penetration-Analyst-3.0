import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import src.orchestrator as orchestrator
from src.exploit_engine.metasploit_wrapper import MetasploitRPCClient
from src.orchestrator import is_target_allowed, run_pipeline
from src.recon_engine.normalizer import normalize_nmap_xml


@pytest.fixture
def minimal_scan_xml() -> str:
    return """<?xml version='1.0'?>
<nmaprun scanner='nmap'>
  <host>
    <status state='up'/>
    <ports>
      <port protocol='tcp' portid='80'>
        <state state='open'/>
        <service name='http' product='Apache httpd' version='2.4.41'/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


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


@pytest.mark.parametrize("module_name", ["exploit/windows/smb/ms08_067_netapi", "post/linux/gather/hashdump"])
def test_module_path_validation_blocks_unsafe(module_name: str):
    with pytest.raises(ValueError, match="Blocked unsafe module path"):
        MetasploitRPCClient.validate_module_path(module_name)


def test_run_aux_module_rejects_invalid_module_without_rpc(monkeypatch: pytest.MonkeyPatch):
    client = MetasploitRPCClient()
    called = {"ensure": False}

    def fake_ensure() -> bool:
        called["ensure"] = True
        return True

    monkeypatch.setattr(client, "ensure_rpc_running", fake_ensure)
    with pytest.raises(ValueError):
        client.run_aux_module("exploit/unix/ftp/vsftpd_234_backdoor", {"RHOSTS": "127.0.0.1"})

    assert called["ensure"] is False


def test_orchestrator_updates_learning_db_from_mocked_rpc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, minimal_scan_xml: str):
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

    def fake_run_nmap(target: str, out_dir: Path, logger):
        xml_path = out_dir / "nmap.xml"
        txt_path = out_dir / "nmap.txt"
        run_log_path = out_dir / "nmap_run.log"
        out_dir.mkdir(parents=True, exist_ok=True)
        xml_path.write_text(minimal_scan_xml, encoding="utf-8")
        txt_path.write_text("ok", encoding="utf-8")
        run_log_path.write_text("ok", encoding="utf-8")
        return {"target": target, "xml_path": str(xml_path), "txt_path": str(txt_path), "run_log_path": str(run_log_path)}

    monkeypatch.setattr(orchestrator, "run_nmap", fake_run_nmap)
    monkeypatch.setattr(orchestrator, "map_scan_to_cves", lambda normalized: [{"cve_id": "CVE-1"}])
    monkeypatch.setattr(
        orchestrator,
        "predict_and_rank",
        lambda normalized, matches, db: [{"cve_id": "CVE-1", "utility": 1.0, "prob": 0.9, "cvss": 8.0, "matched_service": {"service": "http", "port": 80}}],
    )

    class FakeRPCClient:
        def run_aux_module(self, module_name: str, options: dict):
            return {"success": True, "output": "http service version detected", "artifacts": []}

        def stop_rpc(self):
            return None

    monkeypatch.setattr(orchestrator, "MetasploitRPCClient", FakeRPCClient)

    result = run_pipeline(
        target="192.168.56.101",
        root=tmp_path,
        dry_run=False,
        full_run=True,
        confirm_token="VALID_TOKEN",
    )

    run_dir = Path(result["run_dir"])
    assert (run_dir / "raw" / "msf_validation.log").exists()

    db_path = tmp_path / "data" / "learning.db"
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT success FROM attempts WHERE cve_id='CVE-1' LIMIT 1").fetchone()
    assert row is not None
    assert row[0] == 1


def test_full_run_auth_failure_writes_msf_rpc_debug_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, minimal_scan_xml: str):
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

    def fake_run_nmap(target: str, out_dir: Path, logger):
        xml_path = out_dir / "nmap.xml"
        txt_path = out_dir / "nmap.txt"
        run_log_path = out_dir / "nmap_run.log"
        out_dir.mkdir(parents=True, exist_ok=True)
        xml_path.write_text(minimal_scan_xml, encoding="utf-8")
        txt_path.write_text("ok", encoding="utf-8")
        run_log_path.write_text("ok", encoding="utf-8")
        return {"target": target, "xml_path": str(xml_path), "txt_path": str(txt_path), "run_log_path": str(run_log_path)}

    monkeypatch.setattr(orchestrator, "run_nmap", fake_run_nmap)
    monkeypatch.setattr(orchestrator, "map_scan_to_cves", lambda normalized: [{"cve_id": "CVE-1"}])
    monkeypatch.setattr(
        orchestrator,
        "predict_and_rank",
        lambda normalized, matches, db: [{"cve_id": "CVE-1", "utility": 1.0, "prob": 0.9, "cvss": 8.0, "matched_service": {"service": "http", "port": 80}}],
    )

    class FakeRPCClient:
        def __init__(self, *args, **kwargs):
            self.debug_trace = {"errors": ["auth failed"]}

        @classmethod
        def from_config(cls, settings_path):
            return cls()

        def smoke_test(self):
            raise RuntimeError("auth failed")

        def stop_rpc(self):
            return None

    monkeypatch.setattr(orchestrator, "MetasploitRPCClient", FakeRPCClient)

    result = run_pipeline(
        target="192.168.56.101",
        root=tmp_path,
        dry_run=False,
        full_run=True,
        confirm_token="VALID_TOKEN",
    )

    run_dir = Path(result["run_dir"])
    debug_path = run_dir / "raw" / "msf_rpc_debug.json"
    assert debug_path.exists()
    payload = json.loads(debug_path.read_text(encoding="utf-8"))
    assert payload["validation_error"] == "auth failed"
