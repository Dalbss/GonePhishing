"""
GonePhishing - Phishing Detection System
model_trainer.py - Train the Random Forest model and save it as model.pkl

HOW TO USE:
  1. Place your dataset CSV in the /data folder
  2. Run this script ONCE from the Visual Studio terminal:
         python model_trainer.py
  3. It will save models/phishing_model.pkl
  4. You never need to run this again unless retraining
"""

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from feature_extractor import extract_features, URL_FEATURE_NAMES

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_PATH  = os.path.join("data", "phishing_data.csv")
MODEL_PATH = os.path.join("models", "phishing_model.pkl")


# ── Load and prepare UCI dataset ───────────────────────────────────────────────
def load_uci_dataset():
    """
    Load the UCI Phishing Website dataset.

    The UCI dataset has 30 feature columns + 1 label column (Result).
    Labels: 1 = phishing, -1 = legitimate (we convert to 1/0).

    Download from: https://archive.ics.uci.edu/ml/datasets/phishing+websites
    Save as: data/phishing_data.csv
    """
    print(f"[Trainer] Loading dataset from: {DATA_PATH}")

    if not os.path.exists(DATA_PATH):
        print("[Trainer] ERROR: Dataset not found!")
        print(f"[Trainer] Download the UCI Phishing dataset and save it to: {DATA_PATH}")
        print("[Trainer] URL: https://archive.ics.uci.edu/ml/datasets/phishing+websites")
        return None, None

    df = pd.read_csv(DATA_PATH)
    print(f"[Trainer] Loaded {len(df)} rows, {len(df.columns)} columns")
    print(f"[Trainer] Columns: {list(df.columns)}")

    # Handle UCI dataset format
    # The last column is typically the label (Result: 1 = phishing, -1 = legit)
    label_col = df.columns[-1]
    print(f"[Trainer] Label column: '{label_col}'")

    # Convert labels: 1 (phishing) → 1, -1 or 0 (legit) → 0
    y = df[label_col].apply(lambda x: 1 if x == 1 else 0)
    X = df.drop(columns=[label_col])

    print(f"[Trainer] Phishing samples:   {y.sum()}")
    print(f"[Trainer] Legitimate samples: {(y == 0).sum()}")

    return X.values, y.values


# ── Train model ────────────────────────────────────────────────────────────────
def train_model(X, y):
    """Train a Random Forest classifier."""

    print("\n[Trainer] Splitting data: 80% train, 20% test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[Trainer] Training samples: {len(X_train)}")
    print(f"[Trainer] Testing samples:  {len(X_test)}")

    print("\n[Trainer] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        class_weight="balanced",   # handles class imbalance
        random_state=42,
        n_jobs=-1                  # use all CPU cores
    )
    model.fit(X_train, y_train)
    print("[Trainer] Training complete.")

    return model, X_test, y_test


# ── Evaluate model ─────────────────────────────────────────────────────────────
def evaluate_model(model, X_test, y_test):
    """Print full evaluation metrics."""

    y_pred = model.predict(X_test)

    print("\n" + "="*50)
    print("  MODEL EVALUATION RESULTS")
    print("="*50)
    print(f"  Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"  Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"  Recall:    {recall_score(y_test, y_pred):.4f}  ← most important (catching phishing)")
    print(f"  F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print("="*50)

    print("\n  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  True Negatives  (legit,    predicted legit):    {cm[0][0]}")
    print(f"  False Positives (legit,    predicted phishing): {cm[0][1]}")
    print(f"  False Negatives (phishing, predicted legit):    {cm[1][0]}  ← want this LOW")
    print(f"  True Positives  (phishing, predicted phishing): {cm[1][1]}")

    print("\n  Full Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Feature importance (top 10)
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        n_features = len(importances)
        feature_names = [f"feature_{i}" for i in range(n_features)]

        pairs = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
        print("  Top 10 Most Important Features:")
        for name, importance in pairs[:10]:
            bar = "█" * int(importance * 100)
            print(f"    {name:<25} {importance:.4f}  {bar}")


# ── Save model ─────────────────────────────────────────────────────────────────
def save_model(model):
    """Save the trained model to disk."""
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"\n[Trainer] Model saved to: {MODEL_PATH}  ({size_kb:.1f} KB)")


# ── Test the saved model ────────────────────────────────────────────────────────
def test_saved_model():
    """Quick sanity check — load and run a prediction."""
    print("\n[Trainer] Testing saved model...")
    loaded_model = joblib.load(MODEL_PATH)

    # Test with a fake feature array (all zeros = very safe)
    n_features = loaded_model.n_features_in_
    test_safe     = [0] * n_features
    test_phishing = [1] * n_features   # all flags raised

    score_safe     = loaded_model.predict_proba([test_safe])[0][1] * 100
    score_phishing = loaded_model.predict_proba([test_phishing])[0][1] * 100

    print(f"[Trainer] All-safe features → score: {score_safe:.1f}/100")
    print(f"[Trainer] All-flagged features → score: {score_phishing:.1f}/100")
    print("[Trainer] Model loaded and working correctly ✅")


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  GonePhishing — Model Trainer")
    print("=" * 50)

    # 1. Load data
    X, y = load_uci_dataset()

    if X is None:
        print("\n[Trainer] Cannot train without data. Exiting.")
        exit(1)

    # 2. Train
    model, X_test, y_test = train_model(X, y)

    # 3. Evaluate
    evaluate_model(model, X_test, y_test)

    # 4. Save
    save_model(model)

    # 5. Verify
    test_saved_model()

    print("\n[Trainer] All done! You can now run main.py to launch GonePhishing.")
