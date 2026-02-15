import csv
import hashlib
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = ROOT / "data" / "models" / "model.joblib"
DEFAULT_TRAINING_CSV = ROOT / "data" / "training_data" / "sample_attempts.csv"


def stable_hash(value: str, mod: int = 1000) -> int:
    return int(hashlib.sha256(str(value).encode("utf-8")).hexdigest(), 16) % mod


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [text.count(char) / len(text) for char in set(text)]
    return -sum(prob * math.log2(prob) for prob in probabilities)


def parse_version_tokens(version: str) -> tuple[int, int]:
    chunks = "".join(char if char.isdigit() else " " for char in str(version or "")).split()
    major = int(chunks[0]) if len(chunks) > 0 else 0
    minor = int(chunks[1]) if len(chunks) > 1 else 0
    return major, minor


def exploit_age_days(published_date: str | None) -> int:
    if not published_date:
        return 365

    candidates = [
        str(published_date).replace("Z", "+00:00"),
        str(published_date),
    ]
    parsers = [
        lambda value: datetime.fromisoformat(value),
        lambda value: datetime.strptime(value, "%Y-%m-%d"),
    ]

    for candidate in candidates:
        for parser in parsers:
            try:
                parsed = parser(candidate)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return max(1, (datetime.now(timezone.utc) - parsed).days)
            except ValueError:
                continue

    return 365


def _find_matching_port(scan_json: dict[str, Any], cve_record: dict[str, Any]) -> dict[str, Any] | None:
    ports = scan_json.get("ports", [])
    matched = cve_record.get("matched_service", {})
    matched_port = matched.get("port")
    if matched_port is not None:
        for port in ports:
            if int(port.get("port", 0)) == int(matched_port):
                return port

    matched_service = str(matched.get("service", "")).strip().lower()
    for port in ports:
        if str(port.get("service", "")).strip().lower() == matched_service:
            return port

    return ports[0] if ports else None


def _prev_success_rate(db: Any, service: str, cve_id: str) -> float:
    if db and hasattr(db, "previous_success_rate"):
        try:
            return float(db.previous_success_rate(service, cve_id))
        except Exception:
            return 0.0
    return 0.0


def build_feature_vector(scan_json: dict[str, Any], cve_record: dict[str, Any], db: Any = None) -> tuple[list[float], dict[str, Any]]:
    port_item = _find_matching_port(scan_json, cve_record)
    if not port_item:
        raise ValueError("No matching port/service found for CVE candidate")

    service = str(port_item.get("service", "unknown"))
    version = str(port_item.get("version", ""))
    major, minor = parse_version_tokens(version)
    port = int(port_item.get("port", 0))
    os_guess = str(scan_json.get("host_os_guess", "unknown"))
    banner = str(port_item.get("banner", ""))
    banner_entropy = shannon_entropy(banner)

    published = cve_record.get("published") or cve_record.get("published_date")
    age_days = exploit_age_days(published)
    prev_rate = _prev_success_rate(db, service, cve_record.get("cve_id", ""))

    features = [
        float(stable_hash(service)),
        float(major),
        float(minor),
        float(port),
        float(stable_hash(os_guess)),
        float(banner_entropy),
        float(age_days),
        float(prev_rate),
    ]

    context = {
        "service": service,
        "version": version,
        "port": port,
        "os_guess": os_guess,
        "banner_entropy": banner_entropy,
        "exploit_age_days": age_days,
        "prev_success_rate": prev_rate,
    }
    return features, context


def load_or_train_model(
    model_path: str | Path = DEFAULT_MODEL_PATH,
    training_csv_path: str | Path = DEFAULT_TRAINING_CSV,
):
    import joblib
    from sklearn.ensemble import RandomForestClassifier

    model_path = Path(model_path)
    training_csv_path = Path(training_csv_path)

    if model_path.exists():
        return joblib.load(model_path)

    X: list[list[float]] = []
    y: list[int] = []
    with training_csv_path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            major, minor = parse_version_tokens(row.get("version", ""))
            X.append(
                [
                    float(stable_hash(row.get("service", ""))),
                    float(major),
                    float(minor),
                    float(int(row.get("port", 0))),
                    float(stable_hash(row.get("os_guess", ""))),
                    float(shannon_entropy(row.get("banner", ""))),
                    float(row.get("exploit_age_days", 365) or 365),
                    float(row.get("prev_success_rate", 0.0) or 0.0),
                ]
            )
            y.append(int(row.get("label", 0)))

    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(np.array(X), np.array(y))
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    return model


def predict_and_rank(
    scan_json: dict[str, Any],
    cve_list: list[dict[str, Any]],
    db: Any = None,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    training_csv_path: str | Path = DEFAULT_TRAINING_CSV,
) -> list[dict[str, Any]]:
    model = load_or_train_model(model_path=model_path, training_csv_path=training_csv_path)

    ranked: list[dict[str, Any]] = []
    for cve in cve_list:
        features, context = build_feature_vector(scan_json, cve, db=db)
        prob = float(model.predict_proba([features])[0][1])
        cvss = float(cve.get("cvss", 0.0) or 0.0)
        utility = prob * cvss
        reasoning = (
            f"Features service={context['service']} version={context['version']} port={context['port']} "
            f"os={context['os_guess']}; cvss={cvss:.1f}; exploit_age_days={context['exploit_age_days']}; "
            f"prev_success_rate={context['prev_success_rate']:.2f}; "
            f"final_prob={prob:.4f}; utility=prob*cvss={prob:.4f}*{cvss:.1f}={utility:.4f}"
        )

        ranked.append(
            {
                "cve_id": cve.get("cve_id"),
                "prob": round(prob, 4),
                "utility": round(utility, 4),
                "reasoning": reasoning,
                "matched_service": cve.get("matched_service", {}),
                "cvss": cvss,
            }
        )

    ranked.sort(key=lambda item: (item["prob"], item["utility"]), reverse=True)
    return ranked
