from pathlib import Path
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
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

print("========== TREINO V7 — V6 + BLIND16 + REFORÇOS DIRECIONADOS ==========")

def first_existing(paths, name):
    for p in paths:
        if p.exists():
            print(f"[INFO] {name}: {p}")
            return p
    raise FileNotFoundError(f"Nenhum arquivo encontrado para {name}: {paths}")

if not BASE_V6.exists():
    raise FileNotFoundError(f"Dataset V6 não encontrado: {BASE_V6}")

if not FEATURES_V6.exists():
    raise FileNotFoundError(f"Features V6 não encontradas: {FEATURES_V6}")

if not REFORCO_LABELS.exists():
    raise FileNotFoundError(f"Labels dos reforços não encontrados: {REFORCO_LABELS}")

if not REFORCO_DIR.exists():
    raise FileNotFoundError(f"Pasta CSV dos reforços não encontrada: {REFORCO_DIR}")

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

required_cols = ["Attack_Type", "capture_id"]
for name, data in [("V6", v6), ("Blind16", blind16), ("Reforco", reforco)]:
    for col in required_cols:
        if col not in data.columns:
            raise ValueError(f"Coluna ausente em {name}: {col}")

df = pd.concat([v6, blind16, reforco], ignore_index=True)

features = [
    line.strip()
    for line in FEATURES_V6.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

features = [f for f in features if f in df.columns]

if not features:
    raise ValueError("Nenhuma feature válida encontrada.")

df = df.replace([np.inf, -np.inf], np.nan)

X = df[features].apply(pd.to_numeric, errors="coerce")
y = df["Attack_Type"].astype(str)
groups = df["capture_id"].astype(str)

print(f"\n[INFO] Linhas V6: {len(v6)}")
print(f"[INFO] Linhas Blind16: {len(blind16)}")
print(f"[INFO] Linhas Reforço V7: {len(reforco)}")
print(f"[INFO] Total V7: {len(df)}")
print(f"[INFO] Features usadas: {len(features)}")

print("\n[INFO] Distribuição por classe:")
print(y.value_counts())

print("\n[INFO] Distribuição por source:")
print(df["dataset_source"].value_counts())

labels = sorted(y.unique())

candidates = {
    "extratrees_depth10_leaf3_balanced": Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", ExtraTreesClassifier(
            n_estimators=1000,
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
            n_estimators=1000,
            max_depth=12,
            min_samples_leaf=3,
            min_samples_split=8,
            max_features="sqrt",
            class_weight="balanced",
            random_state=43,
            n_jobs=-1,
        ))
    ]),
    "randomforest_depth12_leaf3_balanced": Pipeline([
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
    ]),
    "mlp_scaled_128_64_32": Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("clf", MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation="relu",
            alpha=0.001,
            max_iter=500,
            early_stopping=True,
            random_state=45,
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
        n_jobs=-1 if not name.startswith("mlp") else None,
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
        0.35 * min_recall
        + 0.35 * f1_macro
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

comparison.to_csv(OUT_DIR / "comparison_groupcv_models_v7.csv", index=False)

best_name = comparison.iloc[0]["model"]
best_model = candidates[best_name]
best_pred = all_predictions[best_name]

print("\n========== MELHOR MODELO V7 ==========")
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

metrics_text = f"""========== MODELO V7 — V6 + BLIND16 + REFORÇOS DIRECIONADOS ==========

Observação metodológica:
Blind16 deixou de ser teste cego final e foi incorporado como hard case.
Os PCAPs de reforço V7 foram gerados especificamente para diferenciar classes confundidas.
O próximo teste realmente cego deverá ser o Blind17.

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

metrics_text += "\n\n========== GATE V7 ==========\n"
if f1_macro >= 0.70 and min_recall >= 0.50:
    metrics_text += "STATUS: V7 BOM EM GROUPCV.\n"
    metrics_text += "Próximo passo: testar em Blind17 realmente cego.\n"
elif f1_macro >= 0.60:
    metrics_text += "STATUS: V7 ACEITÁVEL EM GROUPCV.\n"
    metrics_text += "Próximo passo: testar em Blind17 e analisar limitações.\n"
else:
    metrics_text += "STATUS: V7 FRACO EM GROUPCV.\n"
    metrics_text += "Ação: revisar reforços e classes confundidas.\n"

print("\n" + metrics_text)

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
pred_df["prediction"] = best_pred
pred_df["correct"] = pred_df["Attack_Type"] == pred_df["prediction"]
pred_df.to_csv(OUT_DIR / "predictions_groupcv_v7.csv", index=False)

cm = confusion_matrix(y, best_pred, labels=labels)

fig, ax = plt.subplots(figsize=(11, 8))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
disp.plot(ax=ax, xticks_rotation=45)
plt.title("Matriz de Confusão — GroupCV V7")
plt.tight_layout()
plt.savefig(OUT_DIR / "confusion_matrix_groupcv_v7.png", dpi=200)
plt.close()

print("\n[INFO] Treinando modelo final V7 com todo o dataset V7...")
best_model.fit(X, y)

joblib.dump(best_model, OUT_DIR / "best_model_v7_reforco.pkl")

df.to_csv(OUT_DATA / "dataset_v7_rodadas_01_16_reforcos.csv", index=False)
(OUT_DATA / "feature_columns_no_ports_v7.txt").write_text(
    "\n".join(features),
    encoding="utf-8",
)

print("\n[OK] Arquivos gerados:")
for path in [
    OUT_DIR / "best_model_v7_reforco.pkl",
    OUT_DIR / "metrics_groupcv_v7.txt",
    OUT_DIR / "comparison_groupcv_models_v7.csv",
    OUT_DIR / "recall_precision_por_classe_groupcv_v7.csv",
    OUT_DIR / "predictions_groupcv_v7.csv",
    OUT_DIR / "confusion_matrix_groupcv_v7.png",
    OUT_DATA / "dataset_v7_rodadas_01_16_reforcos.csv",
    OUT_DATA / "feature_columns_no_ports_v7.txt",
]:
    print(" -", path)
