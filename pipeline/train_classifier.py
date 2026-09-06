"""
train_classifier.py
-------------------
Phase 2 of the DPI-Engine ML pipeline.

Trains a RandomForestClassifier on the combined flow-feature CSV produced
by extract_real_features.py / generate_multiple_pcaps.py.  Only the five
genuine behavioural numeric features are used — flow_id and label are
excluded from the feature matrix.

Outputs
-------
  /pipeline/models/rf_classifier.pkl   — saved model (joblib)
  Console: full evaluation report with honesty flag for suspiciously
           high accuracy.

Usage
-----
    python pipeline/train_classifier.py
"""

import csv
import math
import sys
from pathlib import Path
from collections import Counter

# ── dependency check ──────────────────────────────────────────────────────────
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
    )
    from sklearn.preprocessing import LabelEncoder
    import joblib
except ImportError as e:
    sys.exit(
        f"ERROR: {e}\n"
        "Install dependencies first:  pip install scikit-learn joblib"
    )

# ── paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH     = PROJECT_ROOT / "pipeline" / "data" / "combined_flow_features.csv"
MODEL_DIR    = PROJECT_ROOT / "pipeline" / "models"
MODEL_PATH   = MODEL_DIR / "rf_classifier.pkl"

FEATURES = [
    "packet_count",
    "mean_packet_size",
    "std_packet_size",
    "flow_duration",
    "bytes_ratio",
]

LOW_COUNT_THRESHOLD = 20   # classes below this are flagged as a limitation
HIGH_ACCURACY_FLAG  = 0.98 # accuracy above this triggers an honesty warning


# ── helpers ───────────────────────────────────────────────────────────────────

def section(title: str):
    width = 72
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}")


def print_confusion_matrix(cm, labels):
    """Pretty-print a confusion matrix with class labels."""
    col_w = 12
    # Header
    header = " " * col_w + "".join(l[:col_w].ljust(col_w) for l in labels)
    print(header)
    print("-" * len(header))
    for i, row_label in enumerate(labels):
        row = row_label[:col_w].ljust(col_w)
        row += "".join(str(v).ljust(col_w) for v in cm[i])
        print(row)


# ── 1. LOAD & CLEAN DATA ──────────────────────────────────────────────────────

section("1. LOADING & CLEANING DATA")

if not CSV_PATH.exists():
    sys.exit(f"ERROR: CSV not found at {CSV_PATH}\nRun generate_multiple_pcaps.py first.")

raw_rows = list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))
print(f"Loaded {len(raw_rows)} rows from {CSV_PATH.name}")

# 1a. Missing / null check
null_count = 0
clean_rows = []
skipped_missing = 0
for r in raw_rows:
    missing = [k for k in FEATURES + ["label"] if r.get(k, "").strip() == ""]
    if missing:
        skipped_missing += 1
        null_count += len(missing)
    else:
        clean_rows.append(r)

print(f"Rows with missing values (dropped): {skipped_missing}"
      f"  (missing fields: {null_count})")

# 1b. Handle 'inf' bytes_ratio — replace with a large finite sentinel value
#     Rationale: 'inf' means no return traffic (one-directional flow), which
#     is itself a meaningful signal. Capping at a large value preserves that
#     signal while keeping numeric compatibility with sklearn.
INF_REPLACEMENT = 999.0
inf_rows = sum(1 for r in clean_rows if r["bytes_ratio"].strip().lower() == "inf")
print(f"Rows with bytes_ratio='inf' (one-directional flows): {inf_rows}"
      f"  -> replaced with sentinel {INF_REPLACEMENT}")
for r in clean_rows:
    if r["bytes_ratio"].strip().lower() == "inf":
        r["bytes_ratio"] = str(INF_REPLACEMENT)

# 1c. Duplicate check (exact match on all feature columns + label, ignoring flow_id)
seen = set()
dupes = 0
deduped = []
for r in clean_rows:
    key = tuple(r[k] for k in FEATURES + ["label"])
    if key in seen:
        dupes += 1
    else:
        seen.add(key)
        deduped.append(r)

print(f"Duplicate rows (same features + label, excluding flow_id): {dupes}")
print(f"Rows remaining after cleaning: {len(deduped)}")

# 1d. Per-class counts & low-count warning
label_counts = Counter(r["label"] for r in deduped)
print(f"\nClass distribution ({len(label_counts)} classes):")
for lbl, cnt in sorted(label_counts.items(), key=lambda x: x[1], reverse=True):
    flag = "  *** LOW COUNT ***" if cnt < LOW_COUNT_THRESHOLD else ""
    print(f"  {lbl:<20s} {cnt:>4d}{flag}")

low_classes = [lbl for lbl, cnt in label_counts.items() if cnt < LOW_COUNT_THRESHOLD]
if low_classes:
    print(f"\n[LIMITATION] The following classes have <{LOW_COUNT_THRESHOLD} examples"
          f" and may not train well:")
    for lbl in low_classes:
        print(f"  - {lbl}: {label_counts[lbl]}")
    print("  These are retained in training (not discarded) but should be noted"
          " in the project report.")


# -- 2. PREPARE FEATURE MATRIX -------------------------------------------------

section("2. PREPARING FEATURE MATRIX")

X = []
y = []
for r in deduped:
    try:
        feats = [float(r[f]) for f in FEATURES]
    except ValueError as e:
        print(f"  [WARN] Skipping row with unparseable feature: {e}")
        continue
    X.append(feats)
    y.append(r["label"])

print(f"Feature matrix shape: {len(X)} rows × {len(FEATURES)} features")
print(f"Feature names: {FEATURES}")

# Encode labels to integers (sklearn RF can handle string labels directly,
# but we encode explicitly for the confusion matrix)
le = LabelEncoder()
y_enc = le.fit_transform(y)
class_names = list(le.classes_)
print(f"Classes ({len(class_names)}): {class_names}")


# -- 3. TRAIN / TEST SPLIT (stratified 80/20) ---------------------------------

section("3. TRAIN / TEST SPLIT  (80/20 stratified)")

X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc,
    test_size=0.20,
    random_state=42,
    stratify=y_enc,
)

print(f"Training set : {len(X_train)} rows")
print(f"Test set     : {len(X_test)} rows")

# Report per-class counts in each split
train_counts = Counter(le.inverse_transform(y_train))
test_counts  = Counter(le.inverse_transform(y_test))
print(f"\n{'Class':<22s} {'Train':>7s}  {'Test':>6s}")
print("-" * 40)
for cls in class_names:
    print(f"  {cls:<20s} {train_counts.get(cls, 0):>7d}  {test_counts.get(cls, 0):>6d}")


# -- 4. TRAIN RANDOM FOREST ----------------------------------------------------

section("4. TRAINING RandomForestClassifier")

rf = RandomForestClassifier(
    n_estimators=200,         # 200 trees
    max_depth=None,           # grow until all leaves are pure (or min_samples_leaf)
    min_samples_leaf=1,
    class_weight="balanced",  # compensates for unequal class sizes
    random_state=42,
    n_jobs=-1,                # use all available CPU cores
)

print("Training RandomForestClassifier (n_estimators=200, class_weight='balanced')...")
rf.fit(X_train, y_train)
print("Training complete.")


# -- 5. EVALUATION -------------------------------------------------------------

section("5. EVALUATION ON HELD-OUT TEST SET")

y_pred = rf.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

# 5a. Overall accuracy
print(f"\nOverall Accuracy: {accuracy * 100:.2f}%")

# 5b. Per-class precision / recall / F1
print("\nClassification Report:")
print(classification_report(
    y_test, y_pred,
    target_names=class_names,
    zero_division=0,
))

# 5c. Confusion matrix
print("Confusion Matrix (rows = actual, cols = predicted):")
cm = confusion_matrix(y_test, y_pred)
print_confusion_matrix(cm, class_names)

# 5d. Feature importances
section("5d. FEATURE IMPORTANCE RANKING")
importances = rf.feature_importances_
ranked = sorted(zip(FEATURES, importances), key=lambda x: x[1], reverse=True)
print(f"\n{'Rank':<6s} {'Feature':<22s} {'Importance':>12s}  {'Bar'}")
print("-" * 60)
for rank, (feat, imp) in enumerate(ranked, 1):
    bar = "#" * int(imp * 50)
    print(f"  {rank:<4d} {feat:<22s} {imp:>12.6f}  {bar}")


# -- 6. SAVE MODEL -------------------------------------------------------------

section("6. SAVING MODEL")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
joblib.dump({"model": rf, "label_encoder": le, "features": FEATURES}, MODEL_PATH)
print(f"Model saved to: {MODEL_PATH}")
print(f"Saved objects:  RandomForestClassifier, LabelEncoder, feature list")


# -- 7. SUMMARY & HONESTY CHECK ------------------------------------------------

section("7. FINAL SUMMARY")

print(f"\n  Dataset rows used      : {len(deduped)}")
print(f"  Training rows          : {len(X_train)}")
print(f"  Test rows              : {len(X_test)}")
print(f"  Number of classes      : {len(class_names)}")
print(f"  Features used          : {', '.join(FEATURES)}")
print(f"  Model                  : RandomForestClassifier (200 trees, balanced)")
print(f"  Overall Test Accuracy  : {accuracy * 100:.2f}%")
print(f"  Best feature           : {ranked[0][0]} (importance={ranked[0][1]:.4f})")
print(f"  Model saved to         : {MODEL_PATH}")

# Honesty flag
print()
if accuracy >= HIGH_ACCURACY_FLAG:
    print("  [!] HONESTY FLAG: Accuracy is suspiciously high (>=98%).")
    print("     This dataset was generated from synthetic PCAPs where traffic")
    print("     patterns per SNI are structurally regular (fixed server IPs,")
    print("     fixed packet sequences). The model may be exploiting deterministic")
    print("     artifacts (e.g. server IP embedded in flow_id, or packet-size")
    print("     patterns that are exact per app) rather than learning generalizable")
    print("     behaviour. This must be clearly noted in the project report.")
    print("     To obtain more honest results: use real-world diverse PCAP captures,")
    print("     or deliberately withhold server IP / port from feature engineering.")
else:
    print("  [OK] Accuracy is within a plausible range -- no suspicious overfitting flag.")

print()
