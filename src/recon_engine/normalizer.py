import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def parse_nmap_xml(xml_path, target):
    schema = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_os_guess": "unknown",
        "ports": [],
        "http_endpoints": [],
    }
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return schema

    osmatch = root.find(".//os/osmatch")
    if osmatch is not None:
        schema["host_os_guess"] = osmatch.attrib.get("name", "unknown")

    for port in root.findall(".//port"):
        service = port.find("service")
        state = port.find("state")
        if state is not None and state.attrib.get("state") != "open":
            continue
        item = {
            "port": int(port.attrib.get("portid", 0)),
            "proto": port.attrib.get("protocol", "tcp"),
            "service": service.attrib.get("name", "unknown") if service is not None else "unknown",
            "product": service.attrib.get("product", "") if service is not None else "",
            "version": service.attrib.get("version", "") if service is not None else "",
            "banner": service.attrib.get("extrainfo", "") if service is not None else "",
        }
        schema["ports"].append(item)
        if item["service"] in {"http", "https", "http-alt"}:
            proto = "https" if item["service"] == "https" or item["port"] == 443 else "http"
            schema["http_endpoints"].append({"url": f"{proto}://{target}:{item['port']}", "server": item["product"], "techs": [t for t in [item["service"], item["product"]] if t]})
    return schema


def write_normalized(normalized, output_path):
    output_path.write_text(json.dumps(normalized, indent=2))
