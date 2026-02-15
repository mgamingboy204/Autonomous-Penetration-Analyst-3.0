import json
import re
from pathlib import Path
from typing import Any

DEFAULT_CVE_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "cve_database" / "cves_small.json"


def load_cve_db(path: str | Path = DEFAULT_CVE_DB_PATH) -> list[dict[str, Any]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _service_text(port: dict[str, Any]) -> str:
    return " ".join(
        [
            str(port.get("service", "")),
            str(port.get("product", "")),
            str(port.get("banner", "")),
        ]
    ).lower()


def _map_with_dataset(scan_json: dict[str, Any], cve_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []

    for port in scan_json.get("ports", []):
        service_text = _service_text(port)
        version = str(port.get("version", "")).strip()

        for record in cve_data:
            tags = [str(tag).lower() for tag in record.get("tags", [])]
            if "local" in tags:
                continue

            product = str(record.get("product", "")).strip().lower()
            if not product or product not in service_text:
                continue

            version_regex = str(record.get("version_regex", "")).strip()
            weak_match = False

            if version_regex:
                if version:
                    if not re.search(version_regex, version, flags=re.IGNORECASE):
                        continue
                else:
                    weak_match = True

            if weak_match:
                reason = (
                    f"Weak match: product '{product}' matched service/product text, "
                    "but detected version is unknown while CVE requires a version regex."
                )
            elif version_regex:
                reason = f"Matched product '{product}' and version '{version}' against regex '{version_regex}'."
            else:
                reason = f"Matched product '{product}' from normalized service fingerprint."

            matches.append(
                {
                    "cve_id": record["cve_id"],
                    "cvss": float(record.get("cvss", 0.0)),
                    "summary": record.get("summary", ""),
                    "matched_service": {
                        "port": port.get("port"),
                        "service": port.get("service", "unknown"),
                        "product": port.get("product", ""),
                        "version": version,
                    },
                    "match_reason": reason,
                }
            )

    deduped = {
        (m["cve_id"], m["matched_service"].get("port"), m["matched_service"].get("service")): m
        for m in matches
    }
    return sorted(deduped.values(), key=lambda item: item["cvss"], reverse=True)


def map_scan_to_cves(scan_json: dict[str, Any], cve_db_path: str | Path = DEFAULT_CVE_DB_PATH) -> list[dict[str, Any]]:
    return _map_with_dataset(scan_json, load_cve_db(cve_db_path))


# Backward-compatible aliases retained for Phase-1 callers.
def load_cve_dataset(path: str | Path) -> list[dict[str, Any]]:
    return load_cve_db(path)


def map_services_to_cves(normalized: dict[str, Any], cve_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _map_with_dataset(normalized, cve_data)
