import json
import sqlite3
from pathlib import Path


class LearningDB:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self._init_schema()

    def _init_schema(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                target_fingerprint TEXT,
                cve_id TEXT,
                exploit_id TEXT,
                features_json TEXT,
                success_bool INTEGER,
                evidence_paths TEXT,
                created_at TEXT
            )
            """
        )
        self.conn.commit()

    def insert_attempt(self, record):
        self.conn.execute(
            """
            INSERT INTO attempts(run_id,target_fingerprint,cve_id,exploit_id,features_json,success_bool,evidence_paths,created_at)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                record.get("run_id"),
                record.get("target_fingerprint"),
                record.get("cve_id"),
                record.get("exploit_id"),
                json.dumps(record.get("features_json", {})),
                1 if record.get("success_bool") else 0,
                json.dumps(record.get("evidence_paths", [])),
                record.get("created_at"),
            ),
        )
        self.conn.commit()

    def previous_success_rate(self, service, cve_id):
        rows = self.conn.execute("SELECT success_bool FROM attempts WHERE cve_id=?", (cve_id,)).fetchall()
        if not rows:
            return 0.0
        return sum(r[0] for r in rows) / len(rows)

    def list_runs(self):
        rows = self.conn.execute("SELECT run_id, cve_id, success_bool, created_at FROM attempts ORDER BY attempt_id DESC").fetchall()
        return [dict(run_id=r[0], cve_id=r[1], success=bool(r[2]), created_at=r[3]) for r in rows]
