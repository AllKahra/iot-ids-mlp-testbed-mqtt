from pathlib import Path
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
    ConfusionMatrixDisplay,
)

TRAIN_DATASET = Path("cicflowmeter/processed_csv_v7/dataset_v7_rodadas_01_16_reforcos.csv")
FEATURES_FILE = Path("cicflowmeter/processed_csv_v7/feature_columns_no_ports_v7.txt")

BLIND_OPTIONS = [
    Path("results/blind17_v7/dataset_blind17_labeled.csv"),
    Path("results/blind17_v7/dataset_blind09_labeled.csv"),
]

OUT_DIR = Path("results/macroclass_v7_blind17")
OUT_DIR.mkdir(parents=True, exist_ok=True)

macro_map = {
    "benign": "benign",
    "scan": "recon_scan",
    "bruteforce": "auth_control_repetition",
    "c2_beacon": "auth_control_repetition",
    "dos_flood": "availability_abuse",
    "slow_dos": "availability_abuse",
    "mqtt_abuse": "availability_abuse",
}

print("========== TREINO MACROCLASSES V7 ==========")

if not TRAIN_DATASET.exists():
    raise FileNotFoundError(f"Dataset de treino não encontrado: {TRAIN_DATASET}")

if not FEATURES_FILE.exists():
    raise FileNotFoundError(f"Arquivo de features não encontrado: {FEATURES_FILE}")

blind_path = None
for p in BLIND_OPTIONS:
    if p.exists():
        blind_path = p
        break

if blind_path is None:
    raise FileNotFoundError("Dataset Blind17 rotulado não encontrado em results/blind17_v7.")

train = pd.read_csv(TRAIN_DATASET, low_memory=False)
blind = pd.read_csv(blind_path, low_memory=False)

features = [
    line.strip()
    for line in FEATURES_FILE.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

features = [f for f in features if f in train.columns and f in blind.columns]

train = train.replace([np.inf, -np.inf], np.nan)
blind = blind.replace([np.inf, -np.inf], np.nan)

train["Macro_Class"] = train["Attack_Type"].map(macro_map)
blind["Macro_Class"] = blind["Attack_Type"].map(macro_map)

X_train = train[features].apply(pd.to_numeric, errors="coerce")
y_train = train["Macro_Class"].astype(str)

X_test = blind[features].apply(pd.to_numeric, errors="coerce")
y_test = blind["Macro_Class"].astype(str)

print(f"[INFO] Linhas treino: {len(train)}")
print(f"[INFO] Linhas Blind17: {len(blind)}")
print(f"[INFO] Features usadas: {len(features)}")

print("\n[INFO] Distribuição treino:")
print(y_train.value_counts())

print("\n[INFO] Distribuição Blind17:")
print(y_test.value_counts())

model = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("clf", RandomForestClassifier(
        n_estimators=800,
        max_depth=12,
        min_samples_leaf=3,
        min_samples_split=8,
        max_features="sqrt",
        class_weight="balanced",
        random_state=77,
        n_jobs=-1,
    ))
])

print("\n[INFO] Treinando modelo macroclasse...")
model.fit(X_train, y_train)

print("[INFO] Avaliando no Blind17...")
y_pred = model.predict(X_test)

labels = sorted(y_test.unique())

acc = accuracy_score(y_test, y_pred)
f1m = f1_score(y_test, y_pred, average="macro", zero_division=0)

report = classification_report(y_test, y_pred, labels=labels, zero_division=0)

metrics = f"""========== MACROCLASSES — MODELO TREINADO V7 / BLIND17 ==========

Macroclasses:
- benign
- recon_scan
- auth_control_repetition = bruteforce + c2_beacon
- availability_abuse = dos_flood + slow_dos + mqtt_abuse

Accuracy: {acc:.4f}
F1 macro: {f1m:.4f}

========== CLASSIFICATION REPORT ==========
{report}
"""

print(metrics)

(OUT_DIR / "metrics_macroclass_model_v7_blind17.txt").write_text(metrics, encoding="utf-8")

pred_df = blind[["capture_id", "Attack_Type", "Macro_Class"]].copy()
pred_df["prediction_macro"] = y_pred
pred_df["correct"] = pred_df["Macro_Class"] == pred_df["prediction_macro"]
pred_df.to_csv(OUT_DIR / "predictions_macroclass_model_v7_blind17.csv", index=False)

cm = confusion_matrix(y_test, y_pred, labels=labels)

fig, ax = plt.subplots(figsize=(9, 7))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
disp.plot(ax=ax, xticks_rotation=45)
plt.title("Matriz de Confusão — Macroclasses V7 / Blind17")
plt.tight_layout()
plt.savefig(OUT_DIR / "confusion_matrix_macroclass_model_v7_blind17.png", dpi=200)
plt.close()

pd.crosstab(
    pd.Series(y_test, name="Real"),
    pd.Series(y_pred, name="Previsto")
).to_csv(OUT_DIR / "confusion_table_macroclass_model_v7_blind17.csv")

joblib.dump(model, OUT_DIR / "macroclass_model_v7.pkl")

print("\n[OK] Arquivos gerados em:", OUT_DIR)
for f in sorted(OUT_DIR.glob("*")):
    print(" -", f)
