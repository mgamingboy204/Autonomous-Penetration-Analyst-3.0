from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ai_brain.ml_predictor import train_or_load_model

if __name__ == "__main__":
    model = train_or_load_model(ROOT / "data" / "models" / "model.joblib", ROOT / "data" / "training_data" / "sample_training.json")
    print("Model ready:", model)
