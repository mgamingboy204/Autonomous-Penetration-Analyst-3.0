import json
from pathlib import Path

from flask import Flask, jsonify

from src.learning_db.database import LearningDB

app = Flask(__name__)
ROOT = Path(__file__).resolve().parents[2]
RUNS = ROOT / "runs"
DB = LearningDB(ROOT / "data" / "learning.db")


def _latest_run_dir():
    if not RUNS.exists():
        return None
    dirs = sorted([d for d in RUNS.iterdir() if d.is_dir()])
    return dirs[-1] if dirs else None


@app.get("/api/status")
def api_status():
    latest = _latest_run_dir()
    if not latest:
        return jsonify({"status": "no_runs"})
    p = latest / "status.json"
    return jsonify(json.loads(p.read_text()) if p.exists() else {"status": "unknown"})


@app.get("/api/runs")
def api_runs():
    return jsonify(DB.list_runs())


@app.get("/api/runs/<run_id>")
def api_run(run_id):
    p = RUNS / run_id / "status.json"
    if not p.exists():
        return jsonify({"error": "run not found"}), 404
    return jsonify(json.loads(p.read_text()))


@app.get("/")
def home():
    latest = _latest_run_dir()
    stage = "No runs yet"
    if latest and (latest / "status.json").exists():
        stage = json.loads((latest / "status.json").read_text()).get("stage", "unknown")
    return f"<h1>Autonomous Penetration Analyst 3.0 Dashboard</h1><p>Latest stage: {stage}</p>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
