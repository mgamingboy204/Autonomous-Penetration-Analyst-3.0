import tempfile
from pathlib import Path

from src.ai_brain.ml_predictor import feature_vector, shannon_entropy
from src.learning_db.database import LearningDB
from src.orchestrator import is_target_allowed
from src.recon_engine.normalizer import parse_nmap_xml


def test_whitelist_validation():
    with tempfile.TemporaryDirectory() as td:
        w = Path(td) / "w.txt"
        w.write_text("192.168.56.0/24\n10.0.0.5\n")
        assert is_target_allowed("192.168.56.10", w)
        assert not is_target_allowed("8.8.8.8", w)


def test_nmap_xml_parsing_schema():
    xml = "<nmaprun><host><ports><port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH' version='7.2' extrainfo='Ubuntu'/></port></ports><os><osmatch name='Linux 3.X'/></os></host></nmaprun>"
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "nmap.xml"
        p.write_text(xml)
        out = parse_nmap_xml(p, "192.168.56.101")
        assert out["host_os_guess"] == "Linux 3.X"
        assert out["ports"][0]["service"] == "ssh"


def test_entropy_calc():
    assert round(shannon_entropy("aaaa"), 4) == 0.0
    assert shannon_entropy("abcd") > 1.0


def test_db_insert_fetch():
    with tempfile.TemporaryDirectory() as td:
        db = LearningDB(Path(td) / "x.db")
        db.insert_attempt({"run_id": "r1", "target_fingerprint": "linux", "cve_id": "CVE-1", "exploit_id": "aux", "features_json": [1], "success_bool": True, "evidence_paths": [], "created_at": "2024"})
        assert db.previous_success_rate("ssh", "CVE-1") == 1.0


def test_feature_vector_length_consistency():
    fv = feature_vector({"service": "ssh", "version": "7.2", "port": 22, "banner": "OpenSSH"}, "linux", 0.4, {"published_date": "2020-01-01T00:00:00Z"})
    assert len(fv) == 7
