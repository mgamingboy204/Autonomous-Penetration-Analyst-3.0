import json
from pathlib import Path


def load_cve_dataset(path):
    return json.loads(Path(path).read_text())


def map_services_to_cves(normalized, cve_data):
    mapped = []
    for p in normalized.get("ports", []):
        hay = f"{p.get('service','')} {p.get('product','')} {p.get('version','')}".lower()
        for rec in cve_data:
            keys = [k.lower() for k in rec.get("service_keys", [])]
            if any(k in hay for k in keys):
                mapped.append({
                    "cve_id": rec["cve_id"],
                    "description": rec["description"],
                    "cvss": rec.get("cvss", 5.0),
                    "service": p.get("service", "unknown"),
                    "port": p.get("port"),
                    "published_date": rec.get("published_date"),
                })
    return list({(m["cve_id"], m["port"]): m for m in mapped}.values())
