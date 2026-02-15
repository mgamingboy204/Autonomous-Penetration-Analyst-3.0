import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.exploit_engine.metasploit_wrapper import MetasploitRPCClient, select_validation_module


@pytest.mark.parametrize("module_name", ["exploit/unix/ftp/vsftpd_234_backdoor", "post/linux/gather/hashdump"])
def test_validate_module_path_blocks_unsafe_modules(module_name: str):
    with pytest.raises(ValueError, match="Blocked unsafe module path"):
        MetasploitRPCClient.validate_module_path(module_name)


def test_validate_module_path_allows_auxiliary_modules():
    MetasploitRPCClient.validate_module_path("auxiliary/scanner/http/http_version")


def test_select_validation_module_returns_no_module_for_unmapped_service():
    selected = select_validation_module("192.168.56.101", {"service": "ssh", "port": 22})
    assert selected.module_name is None
    assert "No safe auxiliary module" in selected.reason
