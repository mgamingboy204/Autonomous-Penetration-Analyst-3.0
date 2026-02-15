import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = ROOT / "data" / "learning.db"


def _get_connection(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path)


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    with _get_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY,
                run_id TEXT,
                target TEXT,
                service TEXT,
                cve_id TEXT,
                features_json TEXT,
                success INTEGER,
                evidence_json TEXT,
                created_at TEXT
            )
            """
        )
        conn.commit()


def record_attempt(
    *,
    run_id: str,
    target: str,
    service: str,
    cve_id: str,
    features: dict[str, Any] | None = None,
    success: int | None = None,
    evidence: dict[str, Any] | list[Any] | None = None,
    attempt_id: str | None = None,
    created_at: str | None = None,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> str:
    init_db(db_path)
    attempt_id = attempt_id or str(uuid.uuid4())
    created_at = created_at or datetime.now(timezone.utc).isoformat()

    with _get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO attempts(
                attempt_id, run_id, target, service, cve_id, features_json, success, evidence_json, created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                attempt_id,
                run_id,
                target,
                service,
                cve_id,
                json.dumps(features or {}),
                success,
                json.dumps(evidence or {}),
                created_at,
            ),
        )
        conn.commit()

    return attempt_id


def get_success_rate(service: str, cve_id: str, db_path: str | Path = DEFAULT_DB_PATH) -> float:
    init_db(db_path)
    with _get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT success
            FROM attempts
            WHERE service = ? AND cve_id = ? AND success IS NOT NULL
            """,
            (service, cve_id),
        ).fetchall()

    if not rows:
        return 0.0
    successes = sum(int(row[0]) for row in rows)
    return successes / len(rows)


def update_attempt(
    attempt_id: str,
    *,
    success: int | None,
    evidence: dict[str, Any] | list[Any] | None = None,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> None:
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE attempts
            SET success = ?, evidence_json = ?
            WHERE attempt_id = ?
            """,
            (success, json.dumps(evidence or {}), attempt_id),
        )
        conn.commit()


class LearningDB:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        init_db(self.db_path)

    def previous_success_rate(self, service: str, cve_id: str) -> float:
        return get_success_rate(service, cve_id, db_path=self.db_path)

    def record_attempt(self, **kwargs: Any) -> str:
        return record_attempt(db_path=self.db_path, **kwargs)

    def update_attempt(self, attempt_id: str, *, success: int | None, evidence: Any = None) -> None:
        update_attempt(attempt_id, success=success, evidence=evidence, db_path=self.db_path)
