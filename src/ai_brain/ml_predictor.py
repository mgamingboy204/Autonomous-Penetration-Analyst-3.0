import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path


def stable_hash(value, mod=1000):
    return int(hashlib.sha256(str(value).encode()).hexdigest(), 16) % mod


def shannon_entropy(text):
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def _version_token(version):
    nums = "".join(ch if ch.isdigit() else " " for ch in (version or "")).split()
    return int(nums[0]) if nums else 0


def exploit_age_days(pub_date):
    if not pub_date:
        return 365
    try:
        d = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
        return max(1, (datetime.now(timezone.utc) - d).days)
    except Exception:
        return 365


def feature_vector(port_item, os_guess, prev_success_rate, cve_record):
    return [
        stable_hash(port_item.get("service", "")),
        _version_token(port_item.get("version", "")),
        int(port_item.get("port", 0)),
        stable_hash(os_guess),
        shannon_entropy(port_item.get("banner", "")),
        float(prev_success_rate),
        float(exploit_age_days(cve_record.get("published_date"))),
    ]


class FallbackModel:
    def predict_proba(self, rows):
        probs = []
        for r in rows:
            base = min(0.95, max(0.05, (r[5] + (1000 - min(r[6], 1000)) / 1000 + r[4] / 8) / 3))
            probs.append([1 - base, base])
        return probs


def train_or_load_model(model_path, training_json_path):
    model_path = Path(model_path)
    try:
        import joblib
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
    except Exception:
        return FallbackModel()

    if model_path.exists():
        return joblib.load(model_path)

    training = json.loads(Path(training_json_path).read_text())
    X = np.array([row["features"] for row in training])
    y = np.array([row["label"] for row in training])
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X, y)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_path)
    return clf


def rank_candidates(normalized, mapped_cves, db, model):
    ranked = []
    for c in mapped_cves:
        port_item = next((p for p in normalized.get("ports", []) if p.get("port") == c.get("port")), None)
        if not port_item:
            continue
        prev = db.previous_success_rate(port_item.get("service", ""), c["cve_id"])
        fv = feature_vector(port_item, normalized.get("host_os_guess", "unknown"), prev, c)
        prob = float(model.predict_proba([fv])[0][1]) if hasattr(model, "predict_proba") else 0.5
        ranked.append({
            "cve_id": c["cve_id"],
            "service": c.get("service"),
            "port": c.get("port"),
            "cvss": c.get("cvss", 5.0),
            "success_probability": round(prob, 4),
            "features": fv,
            "reasoning": f"service_hash={fv[0]}, port={fv[2]}, prev_success_rate={round(prev,2)}, exploit_age_days={int(fv[6])}",
        })
    ranked.sort(key=lambda x: x["success_probability"], reverse=True)
    return ranked
