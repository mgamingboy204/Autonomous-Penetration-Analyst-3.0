import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import xmltodict


CANONICAL_EMPTY = {
    "target": "",
    "timestamp": "",
    "host_os_guess": "unknown",
    "ports": [],
    "http_endpoints": [],
}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_nmap_xml(xml_path: Path, target: str, output_path: Path) -> dict[str, Any]:
    normalized = dict(CANONICAL_EMPTY)
    normalized["target"] = target
    normalized["timestamp"] = datetime.now(timezone.utc).isoformat()

    if not xml_path.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        return normalized

    parsed = xmltodict.parse(xml_path.read_text(encoding="utf-8"))
    nmaprun = parsed.get("nmaprun", {})

    if nmaprun.get("@startstr"):
        normalized["timestamp"] = nmaprun["@startstr"]

    host = _as_list(nmaprun.get("host"))
    host_data = host[0] if host else {}

    os_matches = _as_list(host_data.get("os", {}).get("osmatch"))
    if os_matches:
        normalized["host_os_guess"] = os_matches[0].get("@name", "unknown")

    ports = _as_list(host_data.get("ports", {}).get("port"))
    for port in ports:
        state = port.get("state", {})
        if state.get("@state") != "open":
            continue

        service = port.get("service", {})
        port_num = int(port.get("@portid", 0))
        service_name = service.get("@name", "unknown")
        product = service.get("@product", "")
        version = service.get("@version", "")
        banner = service.get("@extrainfo", "") or service.get("@servicefp", "")

        port_item = {
            "port": port_num,
            "proto": port.get("@protocol", "tcp"),
            "service": service_name,
            "product": product,
            "version": version,
            "banner": banner,
        }
        normalized["ports"].append(port_item)

        if service_name in {"http", "https", "http-alt"}:
            scheme = "https" if service_name == "https" or port_num == 443 else "http"
            normalized["http_endpoints"].append({"url": f"{scheme}://{target}:{port_num}"})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    return normalized
