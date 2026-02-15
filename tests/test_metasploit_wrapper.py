import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.exploit_engine import metasploit_wrapper
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


def test_rpc_call_raises_clear_error_when_msgpack_missing():
    client = MetasploitRPCClient()
    with patch.object(metasploit_wrapper, "msgpack", None):
        with pytest.raises(RuntimeError, match="pip install msgpack"):
            client._rpc_call("auth.login", "msf", "msf")


def test_rpc_call_probes_endpoint_and_selects_working_combo():
    class FakeResponse:
        def __init__(self, body: bytes):
            self._body = body

        def read(self) -> bytes:
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    calls: list[str] = []
    packed = metasploit_wrapper.msgpack.packb({"result": "success", "token": "abc"}, use_bin_type=True)

    def fake_urlopen(request, timeout=20, context=None):
        calls.append(request.full_url)
        if request.full_url.endswith("/api/"):
            return FakeResponse(b"<html>wrong</html>")
        return FakeResponse(packed)

    client = MetasploitRPCClient(ssl_enabled=False)
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = client._rpc_call("auth.login", "msf", "msf")

    assert result["result"] == "success"
    assert client.active_endpoint == "/api"
    assert calls[0].endswith("/api/")
    assert calls[1].endswith("/api")
