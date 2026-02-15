import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.exploit_engine import metasploit_wrapper
from src.exploit_engine.metasploit_wrapper import MetasploitRPCClient


@pytest.mark.parametrize("module_name", ["exploit/unix/ftp/vsftpd_234_backdoor", "post/linux/gather/hashdump"])
def test_validate_module_path_blocks_unsafe_modules(module_name: str):
    with pytest.raises(ValueError, match="Blocked unsafe module path"):
        MetasploitRPCClient.validate_module_path(module_name)


def test_validate_module_path_allows_auxiliary_modules():
    MetasploitRPCClient.validate_module_path("auxiliary/scanner/http/http_version")


def test_full_run_uses_mocked_rpc_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    class FakeRPCClient:
        def run_aux_module(self, module_name: str, options_dict: dict):
            return {
                "success": True,
                "output_text": f"{module_name} reports service version for {options_dict.get('RHOSTS')}",
                "artifacts": {},
            }

        def stop_rpc(self):
            return None

    monkeypatch.setattr(metasploit_wrapper, "MetasploitRPCClient", FakeRPCClient)

    run_ctx = type(
        "RunCtx",
        (),
        {
            "target": "192.168.56.101",
            "raw_dir": tmp_path / "raw",
        },
    )()

    result = metasploit_wrapper.full_run(
        run_ctx,
        {
            "service": "http",
            "port": 80,
            "cve_id": "CVE-2021-0001",
        },
    )

    assert result["success"] is True
    assert result["module"] == "auxiliary/scanner/http/http_version"
    assert (tmp_path / "raw" / "msf_validation.log").exists()
