#!/usr/bin/env python3
"""
Manual validation:
1) No SSL:
   pkill -9 -f msfrpcd
   msfrpcd -f -a 127.0.0.1 -p 55553 -U msf -P msf
   python3 scripts/msf_rpc_smoketest.py
   Expected: status OK, scheme http, chosen_uri ending in /api/, token present.

2) SSL:
   pkill -9 -f msfrpcd
   msfrpcd -f -a 127.0.0.1 -p 55553 -S -U msf -P msf
   python3 scripts/msf_rpc_smoketest.py
   Expected: status OK, scheme https, chosen_uri ending in /api/, token present.

3) Wrong creds:
   Change config password and rerun.
   Expected: clean auth failed with included server response.
"""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.msf_rpc_client import MsfRpcClient, RpcAuthError, RpcClientError, RpcDecodeError, RpcTransportError


def _read_settings() -> dict:
    settings_path = ROOT / "config" / "settings.json"
    if not settings_path.exists():
        return {}
    return json.loads(settings_path.read_text(encoding="utf-8"))


def _ssl_pref(settings: dict) -> bool | None:
    if "msf_rpc_ssl" not in settings:
        return None
    raw = settings.get("msf_rpc_ssl")
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    settings = _read_settings()
    host = str(settings.get("msf_rpc_host", "127.0.0.1"))
    port = int(settings.get("msf_rpc_port", 55553))
    username = str(settings.get("msf_rpc_user", "msf"))
    password = str(settings.get("msf_rpc_pass", "msf"))
    ssl_pref = _ssl_pref(settings)


    client = None
    try:
        client = MsfRpcClient(host, port, username, password, ssl_pref)
        probe = client.probe_and_login()
        version = client.call("core.version")
        print(
            json.dumps(
                {
                    "status": "OK",
                    "scheme": probe.scheme,
                    "chosen_uri": probe.base_url,
                    "endpoint": "/api/",
                    "token_present": bool(probe.token),
                    "auth_result": probe.decoded_login_response.get("result"),
                    "core_version": version,
                    "attempts": client.debug_attempts,
                },
                indent=2,
            )
        )
        return 0
    except RpcAuthError as exc:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "reason": "auth failed",
                    "error": str(exc),
                    "chosen_uri": client.base_url if client else None,
                    "endpoint": "/api/",
                    "attempts": client.debug_attempts if client else [],
                },
                indent=2,
            )
        )
        return 3
    except RpcTransportError as exc:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "reason": "wrong scheme or SSL disabled",
                    "error": str(exc),
                    "chosen_uri": client.base_url if client else None,
                    "endpoint": "/api/",
                    "attempts": client.debug_attempts if client else [],
                },
                indent=2,
            )
        )
        return 2
    except (RpcDecodeError, RpcClientError) as exc:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "reason": "rpc format/decode issue",
                    "error": str(exc),
                    "chosen_uri": client.base_url if client else None,
                    "endpoint": "/api/",
                    "attempts": client.debug_attempts if client else [],
                },
                indent=2,
            )
        )
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
