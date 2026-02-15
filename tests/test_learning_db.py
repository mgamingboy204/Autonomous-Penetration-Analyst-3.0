import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.learning_db.database import get_success_rate, init_db, record_attempt


def test_success_rate_is_computed_per_service_and_cve(tmp_path: Path):
    db_path = tmp_path / "learning.db"
    init_db(db_path)

    record_attempt(
        run_id="run-1",
        target="192.168.56.101",
        service="http",
        cve_id="CVE-2021-41773",
        features={"prob": 0.8},
        success=1,
        evidence={"session": "a"},
        db_path=db_path,
    )
    record_attempt(
        run_id="run-1",
        target="192.168.56.101",
        service="http",
        cve_id="CVE-2021-41773",
        features={"prob": 0.6},
        success=0,
        evidence={"session": "b"},
        db_path=db_path,
    )
    record_attempt(
        run_id="run-1",
        target="192.168.56.101",
        service="ssh",
        cve_id="CVE-2021-41773",
        features={"prob": 0.9},
        success=1,
        evidence={"session": "c"},
        db_path=db_path,
    )

    assert get_success_rate("http", "CVE-2021-41773", db_path=db_path) == 0.5
    assert get_success_rate("ssh", "CVE-2021-41773", db_path=db_path) == 1.0
    assert get_success_rate("ftp", "CVE-2021-41773", db_path=db_path) == 0.0


def test_success_rate_ignores_null_success(tmp_path: Path):
    db_path = tmp_path / "learning.db"
    init_db(db_path)

    record_attempt(
        run_id="run-2",
        target="192.168.56.102",
        service="http",
        cve_id="CVE-2021-41773",
        success=None,
        db_path=db_path,
    )

    assert get_success_rate("http", "CVE-2021-41773", db_path=db_path) == 0.0
