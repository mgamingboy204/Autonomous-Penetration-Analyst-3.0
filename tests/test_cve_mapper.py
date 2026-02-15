import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ai_brain.cve_mapper import map_scan_to_cves


def test_vsftpd_234_maps_to_expected_cve():
    scan_json = {
        "target": "192.168.56.101",
        "ports": [
            {
                "port": 21,
                "proto": "tcp",
                "service": "ftp",
                "product": "vsftpd",
                "version": "2.3.4",
                "banner": "vsftpd 2.3.4",
            }
        ],
    }

    matches = map_scan_to_cves(scan_json)
    match_ids = {item["cve_id"] for item in matches}

    assert "CVE-2011-2523" in match_ids
