import os
import joblib
import json
import hashlib
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    brier_score_loss,
    precision_recall_fscore_support,
    accuracy_score
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize

CLASSES = [
    "benign",
    "phishing",
    "business_email_compromise",
    "malicious_attachment",
    "spam",
    "suspicious"
]

FEATURE_NAMES = sorted([
    "spf_failed",
    "dkim_failed",
    "dmarc_failed",
    "authentication_missing",
    "reply_to_mismatch",
    "return_path_mismatch",
    "sender_domain_mismatch",
    "display_name_impersonation_signal",
    "url_count",
    "suspicious_url_count",
    "ip_url_count",
    "shortened_url_count",
    "punycode_url_count",
    "domain_count",
    "lookalike_domain_count",
    "suspicious_tld_count",
    "domain_anomaly_score",
    "attachment_count",
    "suspicious_attachment_count",
    "executable_attachment_signal",
    "urgency_score",
    "credential_request_score",
    "financial_request_score",
    "impersonation_score",
    "received_hop_count",
    "header_anomaly_score",
])

def generate_synthetic_dataset(num_samples: int = 4000, random_seed: int = 42):
    """
    Generate synthetic DFIR forensic training dataset.
    NOTE: This is a synthetic-data baseline generator. Labels are generated from
    synthetic forensic feature spaces. Model evaluation on this dataset provides
    baseline consistency validation, not empirical real-world accuracy proof.
    """
    np.random.seed(random_seed)
    X = []
    y = []

    for _ in range(num_samples):
        cls_idx = np.random.choice(len(CLASSES), p=[0.24, 0.24, 0.22, 0.16, 0.07, 0.07])
        target_class = CLASSES[cls_idx]
        feat = {k: 0.0 for k in FEATURE_NAMES}

        # Baseline network hop count
        feat["received_hop_count"] = float(np.random.randint(1, 5))

        if target_class == "benign":
            feat["spf_failed"] = 0.0
            feat["dkim_failed"] = 0.0
            feat["dmarc_failed"] = 0.0
            feat["authentication_missing"] = float(np.random.choice([0.0, 1.0], p=[0.75, 0.25]))
            feat["url_count"] = float(np.random.choice([0, 1, 2], p=[0.6, 0.3, 0.1]))
            feat["domain_count"] = feat["url_count"]
            feat["urgency_score"] = float(np.random.uniform(0.0, 0.15))
            feat["credential_request_score"] = 0.0
            feat["financial_request_score"] = 0.0
            feat["impersonation_score"] = 0.0
            feat["display_name_impersonation_signal"] = 0.0
            feat["attachment_count"] = float(np.random.choice([0, 1], p=[0.8, 0.2]))

        elif target_class == "phishing":
            feat["url_count"] = float(np.random.randint(1, 4))
            feat["domain_count"] = feat["url_count"]
            feat["suspicious_url_count"] = float(np.random.choice([0.0, 1.0, 2.0], p=[0.2, 0.6, 0.2]))
            feat["lookalike_domain_count"] = float(np.random.choice([0.0, 1.0, 2.0], p=[0.3, 0.5, 0.2]))
            feat["credential_request_score"] = float(np.random.uniform(0.3, 1.0))
            feat["urgency_score"] = float(np.random.uniform(0.2, 1.0))
            feat["impersonation_score"] = float(np.random.uniform(0.0, 0.6))
            feat["spf_failed"] = float(np.random.choice([0.0, 1.0], p=[0.4, 0.6]))
            feat["dkim_failed"] = float(np.random.choice([0.0, 1.0], p=[0.4, 0.6]))

        elif target_class == "business_email_compromise":
            feat["financial_request_score"] = float(np.random.uniform(0.35, 1.0))
            feat["impersonation_score"] = float(np.random.uniform(0.35, 1.0))
            feat["display_name_impersonation_signal"] = float(np.random.uniform(0.5, 1.0))
            feat["urgency_score"] = float(np.random.uniform(0.25, 0.95))
            feat["reply_to_mismatch"] = float(np.random.choice([0.0, 1.0], p=[0.4, 0.6]))
            feat["sender_domain_mismatch"] = feat["reply_to_mismatch"]
            feat["url_count"] = float(np.random.choice([0, 1], p=[0.7, 0.3]))

        elif target_class == "malicious_attachment":
            feat["attachment_count"] = float(np.random.randint(1, 3))
            feat["suspicious_attachment_count"] = float(np.random.choice([1.0, 2.0], p=[0.7, 0.3]))
            feat["executable_attachment_signal"] = float(np.random.choice([0.0, 1.0], p=[0.2, 0.8]))
            feat["urgency_score"] = float(np.random.uniform(0.0, 0.7))
            feat["financial_request_score"] = float(np.random.uniform(0.0, 0.5))

        elif target_class == "spam":
            feat["url_count"] = float(np.random.randint(3, 8))
            feat["domain_count"] = feat["url_count"]
            feat["shortened_url_count"] = float(np.random.randint(0, 2))
            feat["urgency_score"] = float(np.random.uniform(0.1, 0.5))

        elif target_class == "suspicious":
            feat["spf_failed"] = float(np.random.choice([0.0, 1.0], p=[0.5, 0.5]))
            feat["urgency_score"] = float(np.random.uniform(0.3, 0.6))
            feat["suspicious_tld_count"] = float(np.random.choice([0.0, 1.0], p=[0.5, 0.5]))
            feat["header_anomaly_score"] = float(np.random.uniform(0.2, 0.6))

        vec = [round(feat[k], 4) for k in FEATURE_NAMES]
        X.append(vec)
        y.append(target_class)

    return np.array(X), np.array(y)

def audit_dataset(X, y):
    """Inspect dataset for duplicates, class counts, and leakage."""
    total_samples = len(X)
    unique_rows = set(tuple(row) for row in X)
    duplicate_count = total_samples - len(unique_rows)

    class_counts = {}
    for cls in CLASSES:
        class_counts[cls] = int(np.sum(y == cls))

    return {
        "total_samples": total_samples,
        "unique_samples": len(unique_rows),
        "duplicate_count": duplicate_count,
        "class_distribution": class_counts
    }

def train_and_calibrate_model():
    print("================================================================")
    print("AEGIS ML Classifier Training & Probability Calibration")
    print("================================================================")
    
    X, y = generate_synthetic_dataset(num_samples=4000, random_seed=42)
    audit = audit_dataset(X, y)
    print(f"Dataset Audit: Total={audit['total_samples']}, Unique={audit['unique_samples']}, Duplicates={audit['duplicate_count']}")
    print(f"Class Distribution: {audit['class_distribution']}")

    # Stratified Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Train Set: {len(X_train)} samples | Test Set: {len(X_test)} samples")

    # Base Random Forest Classifier
    base_rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=14,
        random_state=42,
        class_weight="balanced"
    )

    # Calibrate Probabilities with Sigmoid Calibration (3-fold CV)
    calibrated_clf = CalibratedClassifierCV(
        estimator=base_rf,
        method="sigmoid",
        cv=3
    )
    calibrated_clf.fit(X_train, y_train)

    # Predictions & Probabilities
    y_pred = calibrated_clf.predict(X_test)
    y_proba = calibrated_clf.predict_proba(X_test)

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="macro")

    # Multi-class Brier Score (mean squared error between one-hot labels and predicted probabilities)
    y_test_bin = label_binarize(y_test, classes=calibrated_clf.classes_)
    brier_scores = [brier_score_loss(y_test_bin[:, i], y_proba[:, i]) for i in range(len(calibrated_clf.classes_))]
    macro_brier = float(np.mean(brier_scores))

    conf_mat = confusion_matrix(y_test, y_pred, labels=CLASSES)

    print("\n--- Calibration & Performance Report ---")
    print(f"Accuracy:        {acc:.4f}")
    print(f"Macro Precision: {prec:.4f}")
    print(f"Macro Recall:    {rec:.4f}")
    print(f"Macro F1-Score:  {f1:.4f}")
    print(f"Macro Brier:     {macro_brier:.4f} (lower is better, 0=perfect calibration)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=CLASSES))
    print("Confusion Matrix:")
    print(conf_mat)

    # Save model artifact and metadata
    output_dir = Path(__file__).resolve().parent.parent / "models"
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "aegis_email_classifier.joblib"
    meta_path = output_dir / "model_metadata.json"

    joblib.dump(calibrated_clf, model_path)

    metadata = {
        "model_name": "aegis_email_classifier",
        "model_type": "synthetic-data baseline",
        "model_version": "1.0.0",
        "algorithm": "CalibratedClassifierCV(RandomForestClassifier, method='sigmoid', cv=3)",
        "feature_schema_version": "1.0",
        "rule_engine_version": "1.0",
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(acc, 4),
        "macro_precision": round(prec, 4),
        "macro_recall": round(rec, 4),
        "macro_f1": round(f1, 4),
        "macro_brier_score": round(macro_brier, 4),
        "feature_names": FEATURE_NAMES,
        "classes": list(calibrated_clf.classes_),
        "limitations": "Model trained on synthetic forensic vectors; confidence values represent model_confidence on engineered feature spaces rather than real-world prevalence."
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nTrained calibrated model successfully saved to: {model_path}")
    print(f"Metadata written to: {meta_path}")

    return metadata

if __name__ == "__main__":
    train_and_calibrate_model()
