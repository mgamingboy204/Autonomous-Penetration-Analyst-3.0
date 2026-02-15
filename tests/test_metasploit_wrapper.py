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


def test_probe_rpc_endpoint_tries_multiple_endpoints_and_selects_first_valid_response():
    if metasploit_wrapper.msgpack is None:
        pytest.skip("msgpack not installed in test environment")
    class FakeResponse:
        def __init__(self, body: bytes, content_type: str):
            self._body = body
            self.headers = {"Content-Type": content_type}

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
        if request.full_url.endswith("/api"):
            return FakeResponse(b"<html>wrong endpoint</html>", "text/html")
        return FakeResponse(packed, "application/msgpack")

    client = MetasploitRPCClient(ssl_enabled=False)
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        uri = client.probe_rpc_endpoint()

    assert uri.endswith("/api/")
    assert client.active_endpoint == "/api/"
    assert calls[0].endswith("/api")
    assert calls[1].endswith("/api/")


def test_rpc_call_returns_structured_error_for_bad_endpoint():
    if metasploit_wrapper.msgpack is None:
        pytest.skip("msgpack not installed in test environment")

    class FakeResponse:
        def __init__(self):
            self.headers = {"Content-Type": "text/html"}
            self.status = 404

        def read(self):
            return b"<html>not found</html>"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    client = MetasploitRPCClient(ssl_enabled=False)
    with patch("urllib.request.urlopen", return_value=FakeResponse()):
        result = client._rpc_call("auth.login", "msf", "msf", base_uri="http://127.0.0.1:55553/api")

    assert result["_rpc_error"] is True
    assert result["http_status"] == 404
    assert result["suspect_endpoint_mismatch"] is True


def test_ensure_rpc_running_reports_running_but_auth_failed(monkeypatch: pytest.MonkeyPatch):
    client = MetasploitRPCClient()
    monkeypatch.setattr(client, "_is_port_open", lambda: True)
    monkeypatch.setattr(client, "_attempt_auth_once", lambda: {"result": "failure", "message": "bad creds"})

    assert client.ensure_rpc_running() is True
    assert client.debug_trace["rpc_state"] == "running_but_auth_failed"
