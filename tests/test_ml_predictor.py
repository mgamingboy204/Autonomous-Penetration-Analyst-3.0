import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ai_brain.ml_predictor import load_or_train_model, shannon_entropy


def test_banner_entropy_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert round(shannon_entropy("ab"), 5) == 1.0


def test_model_trains_and_loads_when_missing(tmp_path: Path):
    training_csv = tmp_path / "attempts.csv"
    model_path = tmp_path / "model.joblib"

    with training_csv.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            "service",
            "version",
            "port",
            "os_guess",
            "banner",
            "exploit_age_days",
            "prev_success_rate",
            "label",
        ])
        writer.writerow(["ftp", "2.3.4", 21, "Linux", "vsftpd 2.3.4", 1000, 0.8, 1])
        writer.writerow(["http", "2.4.49", 80, "Linux", "Apache 2.4.49", 800, 0.6, 1])
        writer.writerow(["ssh", "8.2", 22, "Ubuntu", "OpenSSH_8.2", 2000, 0.1, 0])
        writer.writerow(["postgresql", "12.3", 5432, "Debian", "PostgreSQL 12.3", 900, 0.2, 0])

    model = load_or_train_model(model_path=model_path, training_csv_path=training_csv)
    assert model_path.exists()
    assert hasattr(model, "predict_proba")

    loaded_model = load_or_train_model(model_path=model_path, training_csv_path=training_csv)
    assert hasattr(loaded_model, "predict_proba")
