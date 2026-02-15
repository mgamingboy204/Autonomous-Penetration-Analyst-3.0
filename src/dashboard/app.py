import json
import sqlite3
from pathlib import Path

from flask import Flask, jsonify

app = Flask(__name__)
ROOT = Path(__file__).resolve().parents[2]
RUNS = ROOT / "runs"
DB_PATH = ROOT / "data" / "learning.db"


def _safe_load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _run_attempt_counts() -> dict[str, int]:
    if not DB_PATH.exists():
        return {}
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT run_id, COUNT(*) FROM attempts GROUP BY run_id").fetchall()
    return {str(run_id): int(count) for run_id, count in rows if run_id}


def _list_runs() -> list[dict]:
    if not RUNS.exists():
        return []

    attempt_counts = _run_attempt_counts()
    runs: list[dict] = []
    for run_dir in sorted([d for d in RUNS.iterdir() if d.is_dir()], reverse=True):
        status = _safe_load_json(run_dir / "status.json")
        runs.append(
            {
                "run_id": run_dir.name,
                "target": status.get("target", "unknown"),
                "created_at": status.get("created_at"),
                "current_step": status.get("current_step", "unknown"),
                "dry_run": status.get("dry_run", True),
                "full_run": status.get("full_run", False),
                "attempt_count": attempt_counts.get(run_dir.name, 0),
                "has_report": (run_dir / "report" / "report.html").exists(),
            }
        )
    return runs


def _run_summary(run_id: str) -> dict | None:
    run_dir = RUNS / run_id
    if not run_dir.exists() or not run_dir.is_dir():
        return None

    status = _safe_load_json(run_dir / "status.json")
    scan = _safe_load_json(run_dir / "normalized" / "scan.json")
    cves = _safe_load_json(run_dir / "normalized" / "cves.json")
    ranked = _safe_load_json(run_dir / "normalized" / "ranked.json")

    return {
        "run_id": run_id,
        "target": status.get("target", "unknown"),
        "created_at": status.get("created_at"),
        "current_step": status.get("current_step", "unknown"),
        "open_ports": len(scan.get("ports", [])),
        "mapped_cves": len(cves) if isinstance(cves, list) else 0,
        "ranked_candidates": len(ranked) if isinstance(ranked, list) else 0,
        "report_link": f"/runs/{run_id}/report/report.html",
    }


@app.get("/")
def home():
    runs = _list_runs()
    rows = "".join(
        (
            f"<tr>"
            f"<td><a href='/run/{r['run_id']}'>{r['run_id']}</a></td>"
            f"<td>{r['target']}</td>"
            f"<td>{r['current_step']}</td>"
            f"<td>{r['attempt_count']}</td>"
            f"<td>{'yes' if r['has_report'] else 'no'}</td>"
            f"</tr>"
        )
        for r in runs
    )

    return (
        "<h1>Autonomous Penetration Analyst 3.0 Dashboard</h1>"
        "<p>Run index and quick status overview.</p>"
        "<p><a href='/api/runs'>/api/runs</a></p>"
        "<table border='1' cellpadding='6' cellspacing='0'>"
        "<tr><th>Run ID</th><th>Target</th><th>Current step</th><th>Attempts</th><th>Report</th></tr>"
        f"{rows or '<tr><td colspan=5>No runs found.</td></tr>'}"
        "</table>"
    )


@app.get("/run/<run_id>")
def run_detail(run_id: str):
    summary = _run_summary(run_id)
    if not summary:
        return jsonify({"error": "run not found"}), 404

    return (
        f"<h1>Run {summary['run_id']}</h1>"
        f"<p><b>Target:</b> {summary['target']}</p>"
        f"<p><b>Created:</b> {summary['created_at']}</p>"
        f"<p><b>Current step:</b> {summary['current_step']}</p>"
        f"<p><b>Open ports:</b> {summary['open_ports']}</p>"
        f"<p><b>Mapped CVEs:</b> {summary['mapped_cves']}</p>"
        f"<p><b>Ranked candidates:</b> {summary['ranked_candidates']}</p>"
        f"<p><a href='{summary['report_link']}'>Open HTML report</a></p>"
        f"<p><a href='/'>Back to dashboard</a></p>"
    )


@app.get("/api/runs")
def api_runs():
    return jsonify(_list_runs())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
