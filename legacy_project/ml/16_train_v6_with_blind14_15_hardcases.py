from pathlib import Path
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
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

BLIND14_OPTIONS = [
    Path("results/blind14_v4/dataset_blind14_labeled.csv"),
    Path("results/blind14_v4/dataset_blind09_labeled.csv"),
]

BLIND15_OPTIONS = [
    Path("results/blind15_v5/dataset_blind15_labeled.csv"),
    Path("results/blind15_v5/dataset_blind09_labeled.csv"),
]

OUT_DIR = Path("results/modelo_v6_blind14_15_hardcases")
OUT_DATA = Path("cicflowmeter/processed_csv_v6")

OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_DATA.mkdir(parents=True, exist_ok=True)

print("========== TREINO V6 — V4 + BLIND14 + BLIND15 HARD CASES ==========")

def first_existing(paths, name):
    for p in paths:
        if p.exists():
            print(f"[INFO] {name}: {p}")
            return p
    raise FileNotFoundError(f"Nenhum arquivo encontrado para {name}: {paths}")

if not BASE_V4.exists():
    raise FileNotFoundError(f"Dataset V4 não encontrado: {BASE_V4}")

if not FEATURES_V4.exists():
    raise FileNotFoundError(f"Features V4 não encontradas: {FEATURES_V4}")

BLIND14 = first_existing(BLIND14_OPTIONS, "Blind14")
BLIND15 = first_existing(BLIND15_OPTIONS, "Blind15")

v4 = pd.read_csv(BASE_V4, low_memory=False)
blind14 = pd.read_csv(BLIND14, low_memory=False)
blind15 = pd.read_csv(BLIND15, low_memory=False)

v4["dataset_source"] = "v4_base"
blind14["dataset_source"] = "blind14_hardcase"
blind15["dataset_source"] = "blind15_hardcase"

required_cols = ["Attack_Type", "capture_id"]
for name, data in [("V4", v4), ("Blind14", blind14), ("Blind15", blind15)]:
    for col in required_cols:
        if col not in data.columns:
            raise ValueError(f"Coluna ausente em {name}: {col}")

df = pd.concat([v4, blind14, blind15], ignore_index=True)

features = [
    line.strip()
    for line in FEATURES_V4.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

features = [f for f in features if f in df.columns]

if not features:
    raise ValueError("Nenhuma feature válida encontrada.")

df = df.replace([np.inf, -np.inf], np.nan)

X = df[features].apply(pd.to_numeric, errors="coerce")
y = df["Attack_Type"].astype(str)
groups = df["capture_id"].astype(str)

print(f"\n[INFO] Linhas V4: {len(v4)}")
print(f"[INFO] Linhas Blind14: {len(blind14)}")
print(f"[INFO] Linhas Blind15: {len(blind15)}")
print(f"[INFO] Total V6: {len(df)}")
print(f"[INFO] Features usadas: {len(features)}")

print("\n[INFO] Distribuição por classe:")
print(y.value_counts())

print("\n[INFO] Distribuição por source:")
print(df["dataset_source"].value_counts())

print("\n[INFO] Distribuição por capture_id:")
print(groups.value_counts().sort_index())

labels = sorted(y.unique())

candidates = {
    "extratrees_depth10_leaf3_balanced": Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", ExtraTreesClassifier(
            n_estimators=900,
            max_depth=10,
            min_samples_leaf=3,
            min_samples_split=8,
            max_features="sqrt",
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ))
    ]),
    "extratrees_depth12_leaf3_balanced": Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", ExtraTreesClassifier(
            n_estimators=900,
            max_depth=12,
            min_samples_leaf=3,
            min_samples_split=8,
            max_features="sqrt",
            class_weight="balanced",
            random_state=43,
            n_jobs=-1,
        ))
    ]),
    "extratrees_depth10_leaf5_none": Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", ExtraTreesClassifier(
            n_estimators=900,
            max_depth=10,
            min_samples_leaf=5,
            min_samples_split=10,
            max_features="sqrt",
            class_weight=None,
            random_state=44,
            n_jobs=-1,
        ))
    ]),
    "randomforest_depth12_leaf3_balanced": Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", RandomForestClassifier(
            n_estimators=700,
            max_depth=12,
            min_samples_leaf=3,
            min_samples_split=8,
            max_features="sqrt",
            class_weight="balanced",
            random_state=45,
            n_jobs=-1,
        ))
    ]),
    "randomforest_depth10_leaf5_none": Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", RandomForestClassifier(
            n_estimators=700,
            max_depth=10,
            min_samples_leaf=5,
            min_samples_split=10,
            max_features="sqrt",
            class_weight=None,
            random_state=46,
            n_jobs=-1,
        ))
    ]),
}

n_groups = groups.nunique()
n_splits = min(5, n_groups)

if n_splits < 2:
    raise ValueError("Não há grupos suficientes para GroupKFold.")

cv = GroupKFold(n_splits=n_splits)

rows = []
all_predictions = {}

print(f"\n[INFO] Rodando GroupKFold com {n_splits} splits...")

for name, model in candidates.items():
    print(f"\n========== AVALIANDO CANDIDATO: {name} ==========")

    y_pred = cross_val_predict(
        model,
        X,
        y,
        groups=groups,
        cv=cv,
        n_jobs=-1,
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
    recall_macro = recall_score(y, y_pred, average="macro", zero_division=0)

    recalls = {label: report_dict[label]["recall"] for label in labels}
    precisions = {label: report_dict[label]["precision"] for label in labels}

    min_recall = min(recalls.values())
    bruteforce_precision = precisions.get("bruteforce", 0.0)
    dos_recall = recalls.get("dos_flood", 0.0)
    c2_recall = recalls.get("c2_beacon", 0.0)
    mqtt_recall = recalls.get("mqtt_abuse", 0.0)
    slow_recall = recalls.get("slow_dos", 0.0)

    score = (
        0.40 * min_recall
        + 0.30 * f1_macro
        + 0.15 * bruteforce_precision
        + 0.15 * min(dos_recall, c2_recall, mqtt_recall, slow_recall)
    )

    row = {
        "model": name,
        "accuracy": acc,
        "precision_macro": precision_macro,
        "recall_macro": recall_macro,
        "f1_macro": f1_macro,
        "f1_weighted": f1_weighted,
        "min_recall": min_recall,
        "bruteforce_precision": bruteforce_precision,
        "dos_flood_recall": dos_recall,
        "c2_beacon_recall": c2_recall,
        "mqtt_abuse_recall": mqtt_recall,
        "slow_dos_recall": slow_recall,
        "selection_score": score,
    }

    for label in labels:
        row[f"recall_{label}"] = recalls[label]
        row[f"precision_{label}"] = precisions[label]

    rows.append(row)
    all_predictions[name] = y_pred

    print(f"Accuracy: {acc:.4f}")
    print(f"F1 macro: {f1_macro:.4f}")
    print(f"Min recall: {min_recall:.4f}")
    print(f"Precision bruteforce: {bruteforce_precision:.4f}")
    print(f"Score seleção: {score:.4f}")

comparison = pd.DataFrame(rows).sort_values(
    by=["selection_score", "min_recall", "f1_macro", "bruteforce_precision"],
    ascending=False,
)

comparison.to_csv(OUT_DIR / "comparison_groupcv_models_v6.csv", index=False)

best_name = comparison.iloc[0]["model"]
best_model = candidates[best_name]
best_pred = all_predictions[best_name]

print("\n========== MELHOR MODELO V6 ==========")
print(comparison[[
    "model",
    "f1_macro",
    "min_recall",
    "bruteforce_precision",
    "dos_flood_recall",
    "c2_beacon_recall",
    "mqtt_abuse_recall",
    "slow_dos_recall",
    "selection_score",
]].to_string(index=False))

print(f"\n[INFO] Modelo escolhido: {best_name}")

report_txt = classification_report(
    y,
    best_pred,
    labels=labels,
    zero_division=0,
)

report_dict = classification_report(
    y,
    best_pred,
    labels=labels,
    output_dict=True,
    zero_division=0,
)

recalls = {label: report_dict[label]["recall"] for label in labels}
precisions = {label: report_dict[label]["precision"] for label in labels}

min_recall = min(recalls.values())
f1_macro = f1_score(y, best_pred, average="macro", zero_division=0)
f1_weighted = f1_score(y, best_pred, average="weighted", zero_division=0)
accuracy = accuracy_score(y, best_pred)
bruteforce_precision = precisions.get("bruteforce", 0.0)

metrics_text = f"""========== MODELO V6 — V4 + BLIND14 + BLIND15 HARD CASES ==========

Observação metodológica:
Blind14 e Blind15 deixaram de ser testes cegos finais e foram incorporados como hard cases.
O próximo teste realmente cego deverá ser o Blind16.

Modelo escolhido:
{best_name}

Validação:
GroupKFold por capture_id
Splits: {n_splits}

Métricas GroupCV do melhor modelo:
Accuracy: {accuracy:.4f}
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

metrics_text += "\n\n========== GATE V6 ==========\n"
if f1_macro >= 0.80 and min_recall >= 0.70 and bruteforce_precision >= 0.60:
    metrics_text += "STATUS: V6 APROVADO EM GROUPCV.\n"
    metrics_text += "Próximo passo: testar em Blind16 realmente cego.\n"
else:
    metrics_text += "STATUS: V6 AINDA NÃO IDEAL EM GROUPCV.\n"
    metrics_text += "Mesmo assim, prossiga para Blind16 se o objetivo for medir generalização real.\n"

print("\n" + metrics_text)

(OUT_DIR / "metrics_groupcv_v6.txt").write_text(metrics_text, encoding="utf-8")

recall_df = pd.DataFrame([
    {
        "classe": label,
        "recall": recalls[label],
        "precision": precisions[label],
    }
    for label in labels
])
recall_df.to_csv(OUT_DIR / "recall_precision_por_classe_groupcv_v6.csv", index=False)

pred_df = df[["capture_id", "Attack_Type", "Label", "dataset_source"]].copy()
pred_df["prediction"] = best_pred
pred_df["correct"] = pred_df["Attack_Type"] == pred_df["prediction"]
pred_df.to_csv(OUT_DIR / "predictions_groupcv_v6.csv", index=False)

cm = confusion_matrix(y, best_pred, labels=labels)

fig, ax = plt.subplots(figsize=(11, 8))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
disp.plot(ax=ax, xticks_rotation=45)
plt.title("Matriz de Confusão — GroupCV V6")
plt.tight_layout()
plt.savefig(OUT_DIR / "confusion_matrix_groupcv_v6.png", dpi=200)
plt.close()

print("\n[INFO] Treinando modelo final V6 com todo o dataset V6...")
best_model.fit(X, y)

joblib.dump(best_model, OUT_DIR / "best_model_v6_blind14_15_hardcases.pkl")

df.to_csv(OUT_DATA / "dataset_v6_rodadas_01_15.csv", index=False)
(OUT_DATA / "feature_columns_no_ports_v6.txt").write_text(
    "\n".join(features),
    encoding="utf-8",
)

print("\n[OK] Arquivos gerados:")
for path in [
    OUT_DIR / "best_model_v6_blind14_15_hardcases.pkl",
    OUT_DIR / "metrics_groupcv_v6.txt",
    OUT_DIR / "comparison_groupcv_models_v6.csv",
    OUT_DIR / "recall_precision_por_classe_groupcv_v6.csv",
    OUT_DIR / "predictions_groupcv_v6.csv",
    OUT_DIR / "confusion_matrix_groupcv_v6.png",
    OUT_DATA / "dataset_v6_rodadas_01_15.csv",
    OUT_DATA / "feature_columns_no_ports_v6.txt",
]:
    print(" -", path)
