#!/usr/bin/env python3
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.exploit_engine.metasploit_wrapper import MetasploitRPCClient


def main() -> int:
    client = MetasploitRPCClient.from_config(ROOT / "config" / "settings.json")
    try:
        if not client.ensure_rpc_running():
            print(json.dumps({"status": "ERROR", "reason": "msfrpcd not running", "debug": client.debug_trace}, indent=2))
            return 1

        candidates = client._candidate_probe_uris()
        auth_result = None
        for uri in candidates:
            result = client._rpc_call("auth.login", client.username, client.password, base_uri=uri)
            if result.get("_rpc_error"):
                print(json.dumps({"status": "PROBE_ERROR", "uri": uri, "error": result}, indent=2))
                if result.get("suspect_endpoint_mismatch"):
                    print("Try /api/ vs /api")
                continue
            auth_result = result
            client.uri = uri
            break

        if auth_result is None:
            print(json.dumps({"status": "ERROR", "reason": "All endpoint probes failed", "debug": client.debug_trace}, indent=2))
            print("Try /api/ vs /api")
            return 2

        if auth_result.get("result") != "success":
            print(json.dumps({"status": "ERROR", "reason": "running but auth failed", "auth": auth_result, "debug": client.debug_trace}, indent=2))
            return 3

        token = str(auth_result["token"])
        created = client._rpc_call("console.create", token, base_uri=client.uri)
        if created.get("_rpc_error") or created.get("id") is None:
            print(json.dumps({"status": "ERROR", "reason": "console.create failed", "result": created}, indent=2))
            return 4

        console_id = created["id"]
        try:
            write_result = client._rpc_call("console.write", token, console_id, "version\n", base_uri=client.uri)
            if write_result.get("_rpc_error"):
                print(json.dumps({"status": "ERROR", "reason": "console.write failed", "result": write_result}, indent=2))
                return 5
            read_result = client._rpc_call("console.read", token, console_id, base_uri=client.uri)
            if read_result.get("_rpc_error"):
                print(json.dumps({"status": "ERROR", "reason": "console.read failed", "result": read_result}, indent=2))
                return 6
        finally:
            client._rpc_call("console.destroy", token, console_id, base_uri=client.uri)

        print(
            json.dumps(
                {
                    "status": "OK",
                    "chosen_uri": client.uri,
                    "auth_result": auth_result.get("result"),
                    "console_output": str(read_result.get("data") or ""),
                    "attempted_uris": client.debug_trace.get("attempted_uris", []),
                },
                indent=2,
            )
        )
        return 0
    except Exception as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc), "debug": client.debug_trace}, indent=2))
        return 1
    finally:
        client.stop_rpc()


if __name__ == "__main__":
    raise SystemExit(main())
