"""
ScamShield VN - URL Malicious/Benign Classifier Training
========================================================
Trains an XGBoost model to classify URLs as malicious or benign
using URL-derived features from the ScamShield VN dataset.

Usage:
    python notebooks/train_url_classifier.py
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

# ─── Configuration ───────────────────────────────────────────────────────────

DATA_PATH = Path("data/public_kaggle/scamshield_vn_public.csv")
MODEL_DIR = Path("models")
MODEL_PATH = MODEL_DIR / "url_classifier_xgb.joblib"

FEATURES = [
    "url_length",
    "path_length",
    "query_length",
    "has_ip_address",
    "has_punycode",
    "has_url_shortener",
]

# Labels: 1 = malicious, 0 = benign
MALICIOUS_LABELS = {"malware_url", "phishing_url"}
BENIGN_LABELS = {"benign_url"}

RANDOM_STATE = 42
TEST_SIZE = 0.2


def main():
    print("=" * 60)
    print("ScamShield VN - URL Classifier Training")
    print("=" * 60)

    # ─── Load Data ───────────────────────────────────────────────────────
    if not DATA_PATH.exists():
        print(f"ERROR: Data file not found: {DATA_PATH}")
        print("Run the pipeline first: python -m src.main run")
        sys.exit(1)

    print(f"\n📂 Loading data from: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    print(f"   Total records: {len(df)}")

    # ─── Filter to URL/Domain records ────────────────────────────────────
    url_mask = df["record_type"].isin(["url", "domain"])
    df_urls = df[url_mask].copy()
    print(f"   URL/Domain records: {len(df_urls)}")

    # ─── Filter to records with known labels ─────────────────────────────
    known_labels = MALICIOUS_LABELS | BENIGN_LABELS
    df_labeled = df_urls[df_urls["label"].isin(known_labels)].copy()
    print(f"   Labeled (malicious/benign): {len(df_labeled)}")

    if len(df_labeled) < 100:
        print("ERROR: Not enough labeled records for training.")
        sys.exit(1)

    # ─── Create binary target ────────────────────────────────────────────
    df_labeled["is_malicious"] = df_labeled["label"].isin(MALICIOUS_LABELS).astype(int)

    print(f"\n📊 Class Distribution:")
    print(f"   Malicious: {df_labeled['is_malicious'].sum()}")
    print(f"   Benign:    {(~df_labeled['is_malicious'].astype(bool)).sum()}")

    # ─── Prepare Features ────────────────────────────────────────────────
    # Fill missing numeric features with 0
    for col in FEATURES:
        if col not in df_labeled.columns:
            df_labeled[col] = 0
        df_labeled[col] = pd.to_numeric(df_labeled[col], errors="coerce").fillna(0)

    # Convert boolean columns
    for col in ["has_ip_address", "has_punycode", "has_url_shortener"]:
        df_labeled[col] = df_labeled[col].map(
            {True: 1, False: 0, "True": 1, "False": 0}
        ).fillna(0).astype(int)

    X = df_labeled[FEATURES].values
    y = df_labeled["is_malicious"].values

    print(f"\n🔧 Features: {FEATURES}")
    print(f"   Feature matrix shape: {X.shape}")

    # ─── Train/Test Split ────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n📊 Split: {len(X_train)} train / {len(X_test)} test")

    # ─── Compute class weight ────────────────────────────────────────────
    n_benign = (y_train == 0).sum()
    n_malicious = (y_train == 1).sum()
    scale_pos_weight = n_benign / max(n_malicious, 1)
    print(f"   scale_pos_weight: {scale_pos_weight:.2f}")

    # ─── Train XGBoost ───────────────────────────────────────────────────
    print("\n🚀 Training XGBoost classifier...")
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        random_state=RANDOM_STATE,
        eval_metric="logloss",
    )
    model.fit(X_train, y_train, verbose=False)
    print("   Training complete!")

    # ─── Evaluate ────────────────────────────────────────────────────────
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("\n" + "=" * 60)
    print("📈 EVALUATION RESULTS")
    print("=" * 60)
    print(f"   Accuracy:  {accuracy:.4f}")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall:    {recall:.4f}")
    print(f"   F1 Score:  {f1:.4f}")

    print("\n📋 Classification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=["Benign", "Malicious"],
        digits=4,
    ))

    print("🔢 Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"   [[TN={cm[0][0]:>5}  FP={cm[0][1]:>5}]")
    print(f"    [FN={cm[1][0]:>5}  TP={cm[1][1]:>5}]]")

    # ─── Feature Importance ──────────────────────────────────────────────
    print("\n🏆 Feature Importance:")
    importances = model.feature_importances_
    for feat, imp in sorted(zip(FEATURES, importances), key=lambda x: -x[1]):
        bar = "█" * int(imp * 40)
        print(f"   {feat:<20} {imp:.4f} {bar}")

    # ─── Save Model ──────────────────────────────────────────────────────
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\n💾 Model saved to: {MODEL_PATH}")

    # ─── Save metadata ───────────────────────────────────────────────────
    metadata = {
        "model_type": "XGBClassifier",
        "features": FEATURES,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "scale_pos_weight": round(scale_pos_weight, 2),
        "class_distribution": {
            "malicious_train": int(y_train.sum()),
            "benign_train": int((y_train == 0).sum()),
            "malicious_test": int(y_test.sum()),
            "benign_test": int((y_test == 0).sum()),
        },
    }
    meta_path = MODEL_DIR / "url_classifier_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"📄 Metadata saved to: {meta_path}")

    print("\n✅ Training complete!")
    return model


if __name__ == "__main__":
    main()
