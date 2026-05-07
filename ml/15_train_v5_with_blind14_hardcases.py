from pathlib import Path
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.ensemble import ExtraTreesClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    ConfusionMatrixDisplay,
)

BASE_V4 = Path("cicflowmeter/processed_csv_v4/dataset_v4_rodadas_01_12.csv")
FEATURES_V4 = Path("cicflowmeter/processed_csv_v4/feature_columns_no_ports_v4.txt")

BLIND14_A = Path("results/blind14_v4/dataset_blind14_labeled.csv")
BLIND14_B = Path("results/blind14_v4/dataset_blind09_labeled.csv")

OUT_DIR = Path("results/modelo_v5_blind14_hardcases")
OUT_DATA = Path("cicflowmeter/processed_csv_v5")

OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_DATA.mkdir(parents=True, exist_ok=True)

print("========== TREINO V5 — V4 + BLIND14 HARD CASES ==========")

if not BASE_V4.exists():
    raise FileNotFoundError(f"Dataset V4 não encontrado: {BASE_V4}")

if not FEATURES_V4.exists():
    raise FileNotFoundError(f"Arquivo de features V4 não encontrado: {FEATURES_V4}")

if BLIND14_A.exists():
    BLIND14 = BLIND14_A
elif BLIND14_B.exists():
    BLIND14 = BLIND14_B
else:
    raise FileNotFoundError(
        "Dataset Blind14 rotulado não encontrado. Esperado:\n"
        "- results/blind14_v4/dataset_blind14_labeled.csv\n"
        "ou\n"
        "- results/blind14_v4/dataset_blind09_labeled.csv"
    )

print(f"[INFO] Dataset base V4: {BASE_V4}")
print(f"[INFO] Blind14 usado como hard case: {BLIND14}")

v4 = pd.read_csv(BASE_V4, low_memory=False)
blind14 = pd.read_csv(BLIND14, low_memory=False)

v4["dataset_source"] = "v4_base"
blind14["dataset_source"] = "blind14_hardcase"

required_cols = ["Attack_Type", "capture_id"]
for col in required_cols:
    if col not in v4.columns:
        raise ValueError(f"Coluna ausente no V4: {col}")
    if col not in blind14.columns:
        raise ValueError(f"Coluna ausente no Blind14: {col}")

df = pd.concat([v4, blind14], ignore_index=True)

features = [
    line.strip()
    for line in FEATURES_V4.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

features = [f for f in features if f in df.columns]

if not features:
    raise ValueError("Nenhuma feature válida encontrada.")

print(f"[INFO] Total de linhas V4: {len(v4)}")
print(f"[INFO] Total de linhas Blind14: {len(blind14)}")
print(f"[INFO] Total combinado V5: {len(df)}")
print(f"[INFO] Total de features usadas: {len(features)}")

# Limpeza básica
df = df.replace([np.inf, -np.inf], np.nan)

X = df[features].apply(pd.to_numeric, errors="coerce")
y = df["Attack_Type"].astype(str)
groups = df["capture_id"].astype(str)

print("\n[INFO] Distribuição por classe:")
print(y.value_counts())

print("\n[INFO] Distribuição por capture_id:")
print(groups.value_counts().sort_index())

# Modelo oficial candidato V5
model = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("clf", ExtraTreesClassifier(
        n_estimators=800,
        max_depth=10,
        min_samples_leaf=3,
        min_samples_split=8,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    ))
])

n_groups = groups.nunique()
n_splits = min(5, n_groups)

if n_splits < 2:
    raise ValueError("Não há grupos suficientes para GroupKFold.")

print(f"\n[INFO] Rodando GroupKFold com {n_splits} splits...")

cv = GroupKFold(n_splits=n_splits)

y_pred_cv = cross_val_predict(
    model,
    X,
    y,
    groups=groups,
    cv=cv,
    n_jobs=-1
)

labels = sorted(y.unique())

acc = accuracy_score(y, y_pred_cv)
prec_w = precision_score(y, y_pred_cv, average="weighted", zero_division=0)
rec_w = recall_score(y, y_pred_cv, average="weighted", zero_division=0)
f1_w = f1_score(y, y_pred_cv, average="weighted", zero_division=0)

prec_m = precision_score(y, y_pred_cv, average="macro", zero_division=0)
rec_m = recall_score(y, y_pred_cv, average="macro", zero_division=0)
f1_m = f1_score(y, y_pred_cv, average="macro", zero_division=0)

report_dict = classification_report(
    y,
    y_pred_cv,
    labels=labels,
    output_dict=True,
    zero_division=0
)

report_txt = classification_report(
    y,
    y_pred_cv,
    labels=labels,
    zero_division=0
)

recalls = {
    label: report_dict[label]["recall"]
    for label in labels
}

min_recall = min(recalls.values())

metrics_text = f"""========== MODELO V5 — V4 + BLIND14 HARD CASES ==========

Base:
- V4: {BASE_V4}
- Blind14 usado como hard case: {BLIND14}

Observação:
O Blind14 deixou de ser teste cego e foi incorporado como reforço de treino/validação.
O próximo teste realmente cego deverá ser o Blind15.

Modelo:
ExtraTreesClassifier regularizado
- n_estimators=800
- max_depth=10
- min_samples_leaf=3
- min_samples_split=8
- max_features=sqrt
- class_weight=balanced

Validação:
GroupKFold por capture_id
Splits: {n_splits}

Métricas GroupCV:
Accuracy: {acc:.4f}
Precision weighted: {prec_w:.4f}
Recall weighted: {rec_w:.4f}
F1 weighted: {f1_w:.4f}

Precision macro: {prec_m:.4f}
Recall macro: {rec_m:.4f}
F1 macro: {f1_m:.4f}

Menor recall por classe: {min_recall:.4f}

Recall por classe:
"""

for label, value in recalls.items():
    metrics_text += f"- {label}: {value:.4f}\n"

metrics_text += "\n========== CLASSIFICATION REPORT ==========\n"
metrics_text += report_txt

metrics_text += "\n\n========== GATE V5 ==========\n"
if min_recall >= 0.70 and f1_m >= 0.80:
    metrics_text += "STATUS: V5 APROVADO EM GROUPCV.\n"
    metrics_text += "Próximo passo: testar em Blind15 realmente cego.\n"
else:
    metrics_text += "STATUS: V5 AINDA FRACO EM GROUPCV.\n"
    metrics_text += "Ação: analisar classes com recall baixo antes de criar Blind15.\n"

print(metrics_text)

(OUT_DIR / "metrics_groupcv_v5.txt").write_text(metrics_text, encoding="utf-8")

# Salvar recall por classe
recall_df = pd.DataFrame([
    {"classe": label, "recall": recalls[label]}
    for label in labels
])
recall_df.to_csv(OUT_DIR / "recall_por_classe_groupcv_v5.csv", index=False)

# Salvar previsões CV
pred_df = df[["capture_id", "Attack_Type", "dataset_source"]].copy()
pred_df["predicted"] = y_pred_cv
pred_df["correct"] = pred_df["Attack_Type"] == pred_df["predicted"]
pred_df.to_csv(OUT_DIR / "predictions_groupcv_v5.csv", index=False)

# Matriz de confusão
cm = confusion_matrix(y, y_pred_cv, labels=labels)

fig, ax = plt.subplots(figsize=(10, 8))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
disp.plot(ax=ax, xticks_rotation=45)
plt.title("Matriz de Confusão — GroupCV V5")
plt.tight_layout()
plt.savefig(OUT_DIR / "confusion_matrix_groupcv_v5.png", dpi=200)
plt.close()

# Treinar modelo final em tudo que agora é treino V5
print("\n[INFO] Treinando modelo final V5 com todo o dataset V5...")
model.fit(X, y)

joblib.dump(model, OUT_DIR / "best_model_v5_blind14_hardcases.pkl")

# Salvar dataset e features V5
df.to_csv(OUT_DATA / "dataset_v5_rodadas_01_14.csv", index=False)
(OUT_DATA / "feature_columns_no_ports_v5.txt").write_text(
    "\n".join(features),
    encoding="utf-8"
)

print("\n[OK] Arquivos gerados:")
for path in [
    OUT_DIR / "best_model_v5_blind14_hardcases.pkl",
    OUT_DIR / "metrics_groupcv_v5.txt",
    OUT_DIR / "recall_por_classe_groupcv_v5.csv",
    OUT_DIR / "predictions_groupcv_v5.csv",
    OUT_DIR / "confusion_matrix_groupcv_v5.png",
    OUT_DATA / "dataset_v5_rodadas_01_14.csv",
    OUT_DATA / "feature_columns_no_ports_v5.txt",
]:
    print(" -", path)
