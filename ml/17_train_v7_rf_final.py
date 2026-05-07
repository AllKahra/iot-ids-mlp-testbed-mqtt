from pathlib import Path
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    f1_score,
    ConfusionMatrixDisplay,
)

BASE_V6 = Path("cicflowmeter/processed_csv_v6/dataset_v6_rodadas_01_15.csv")
FEATURES_V6 = Path("cicflowmeter/processed_csv_v6/feature_columns_no_ports_v6.txt")

BLIND16_OPTIONS = [
    Path("results/blind16_v6/dataset_blind16_labeled.csv"),
    Path("results/blind16_v6/dataset_blind09_labeled.csv"),
]

REFORCO_DIR = Path("cicflowmeter/raw_csv_reforco_v7")
REFORCO_LABELS = Path("capture/pcaps/reforco_v7/pcap_labels_reforco_v7.csv")

OUT_DIR = Path("results/modelo_v7_reforco")
OUT_DATA = Path("cicflowmeter/processed_csv_v7")

OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_DATA.mkdir(parents=True, exist_ok=True)

print("========== TREINO V7 FINAL — RANDOM FOREST SEM MLP ==========")

def first_existing(paths, name):
    for p in paths:
        if p.exists():
            print(f"[INFO] {name}: {p}")
            return p
    raise FileNotFoundError(f"Nenhum arquivo encontrado para {name}: {paths}")

BLIND16 = first_existing(BLIND16_OPTIONS, "Blind16")

v6 = pd.read_csv(BASE_V6, low_memory=False)
blind16 = pd.read_csv(BLIND16, low_memory=False)

v6["dataset_source"] = "v6_base"
blind16["dataset_source"] = "blind16_hardcase"

labels_df = pd.read_csv(REFORCO_LABELS)

reforcos = []

for _, row in labels_df.iterrows():
    pcap_name = row["filename"]
    csv_name = pcap_name.replace(".pcap", ".csv")
    csv_path = REFORCO_DIR / csv_name

    if not csv_path.exists():
        print(f"[ALERTA] CSV não encontrado, pulando: {csv_path}")
        continue

    tmp = pd.read_csv(csv_path, low_memory=False)
    tmp["Label"] = int(row["label"])
    tmp["Attack_Type"] = str(row["attack_type"])
    tmp["capture_id"] = pcap_name.replace(".pcap", "")
    tmp["dataset_source"] = "reforco_v7"
    reforcos.append(tmp)

if not reforcos:
    raise ValueError("Nenhum CSV de reforço foi carregado.")

reforco = pd.concat(reforcos, ignore_index=True)

df = pd.concat([v6, blind16, reforco], ignore_index=True)

features = [
    line.strip()
    for line in FEATURES_V6.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

features = [f for f in features if f in df.columns]

df = df.replace([np.inf, -np.inf], np.nan)

X = df[features].apply(pd.to_numeric, errors="coerce")
y = df["Attack_Type"].astype(str)
groups = df["capture_id"].astype(str)

print(f"[INFO] Linhas V6: {len(v6)}")
print(f"[INFO] Linhas Blind16: {len(blind16)}")
print(f"[INFO] Linhas Reforço V7: {len(reforco)}")
print(f"[INFO] Total V7: {len(df)}")
print(f"[INFO] Features usadas: {len(features)}")

print("\n[INFO] Distribuição por classe:")
print(y.value_counts())

labels = sorted(y.unique())

model = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("clf", RandomForestClassifier(
        n_estimators=800,
        max_depth=12,
        min_samples_leaf=3,
        min_samples_split=8,
        max_features="sqrt",
        class_weight="balanced",
        random_state=44,
        n_jobs=-1,
    ))
])

n_splits = min(5, groups.nunique())
cv = GroupKFold(n_splits=n_splits)

print(f"\n[INFO] Rodando GroupKFold com {n_splits} splits...")

y_pred = cross_val_predict(
    model,
    X,
    y,
    groups=groups,
    cv=cv,
    n_jobs=-1,
)

report_txt = classification_report(
    y,
    y_pred,
    labels=labels,
    zero_division=0,
)

report_dict = classification_report(
    y,
    y_pred,
    labels=labels,
    output_dict=True,
    zero_division=0,
)

acc = accuracy_score(y, y_pred)
f1_macro = f1_score(y, y_pred, average="macro", zero_division=0)
f1_weighted = f1_score(y, y_pred, average="weighted", zero_division=0)
precision_macro = precision_score(y, y_pred, average="macro", zero_division=0)

recalls = {label: report_dict[label]["recall"] for label in labels}
precisions = {label: report_dict[label]["precision"] for label in labels}
min_recall = min(recalls.values())
bruteforce_precision = precisions.get("bruteforce", 0.0)

metrics_text = f"""========== MODELO V7 FINAL — RANDOM FOREST ==========

Observação metodológica:
Blind16 deixou de ser teste cego final e foi incorporado como hard case.
Os PCAPs de reforço V7 foram usados para melhorar a diferenciação entre classes confundidas.
O próximo teste realmente cego deverá ser o Blind17.

Modelo escolhido:
RandomForestClassifier regularizado
- n_estimators=800
- max_depth=12
- min_samples_leaf=3
- min_samples_split=8
- max_features=sqrt
- class_weight=balanced

Validação:
GroupKFold por capture_id
Splits: {n_splits}

Métricas GroupCV:
Accuracy: {acc:.4f}
Precision macro: {precision_macro:.4f}
F1 macro: {f1_macro:.4f}
F1 weighted: {f1_weighted:.4f}
Menor recall por classe: {min_recall:.4f}
Precision bruteforce: {bruteforce_precision:.4f}

Recall por classe:
"""

for label in labels:
    metrics_text += f"- {label}: {recalls[label]:.4f}\n"

metrics_text += "\nPrecision por classe:\n"
for label in labels:
    metrics_text += f"- {label}: {precisions[label]:.4f}\n"

metrics_text += "\n========== CLASSIFICATION REPORT ==========\n"
metrics_text += report_txt

metrics_text += "\n\n========== GATE V7 ==========\n"
if f1_macro >= 0.70 and min_recall >= 0.50:
    metrics_text += "STATUS: V7 BOM EM GROUPCV.\n"
    metrics_text += "Próximo passo: testar em Blind17 realmente cego.\n"
elif f1_macro >= 0.60:
    metrics_text += "STATUS: V7 ACEITÁVEL EM GROUPCV.\n"
    metrics_text += "Próximo passo: testar em Blind17 e analisar limitações.\n"
else:
    metrics_text += "STATUS: V7 FRACO EM GROUPCV.\n"

print(metrics_text)

(OUT_DIR / "metrics_groupcv_v7.txt").write_text(metrics_text, encoding="utf-8")

recall_df = pd.DataFrame([
    {
        "classe": label,
        "recall": recalls[label],
        "precision": precisions[label],
    }
    for label in labels
])
recall_df.to_csv(OUT_DIR / "recall_precision_por_classe_groupcv_v7.csv", index=False)

pred_df = df[["capture_id", "Attack_Type", "Label", "dataset_source"]].copy()
pred_df["prediction"] = y_pred
pred_df["correct"] = pred_df["Attack_Type"] == pred_df["prediction"]
pred_df.to_csv(OUT_DIR / "predictions_groupcv_v7.csv", index=False)

cm = confusion_matrix(y, y_pred, labels=labels)

fig, ax = plt.subplots(figsize=(11, 8))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
disp.plot(ax=ax, xticks_rotation=45)
plt.title("Matriz de Confusão — GroupCV V7")
plt.tight_layout()
plt.savefig(OUT_DIR / "confusion_matrix_groupcv_v7.png", dpi=200)
plt.close()

print("\n[INFO] Treinando modelo final V7 com todo o dataset V7...")
model.fit(X, y)

joblib.dump(model, OUT_DIR / "best_model_v7_reforco.pkl")

df.to_csv(OUT_DATA / "dataset_v7_rodadas_01_16_reforcos.csv", index=False)
(OUT_DATA / "feature_columns_no_ports_v7.txt").write_text(
    "\n".join(features),
    encoding="utf-8",
)

print("\n[OK] Arquivos gerados:")
for path in [
    OUT_DIR / "best_model_v7_reforco.pkl",
    OUT_DIR / "metrics_groupcv_v7.txt",
    OUT_DIR / "recall_precision_por_classe_groupcv_v7.csv",
    OUT_DIR / "predictions_groupcv_v7.csv",
    OUT_DIR / "confusion_matrix_groupcv_v7.png",
    OUT_DATA / "dataset_v7_rodadas_01_16_reforcos.csv",
    OUT_DATA / "feature_columns_no_ports_v7.txt",
]:
    print(" -", path)
