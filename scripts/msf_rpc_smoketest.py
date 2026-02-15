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
        result = client.smoke_test()
        print(
            json.dumps(
                {
                    "status": "OK",
                    "scheme": result["scheme"],
                    "endpoint": result["endpoint"],
                    "host": result["host"],
                    "port": result["port"],
                    "auth_result": result["auth_result"],
                    "console_output": result["console_output"],
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
