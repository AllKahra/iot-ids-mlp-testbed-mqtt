from pathlib import Path
import argparse
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

parser = argparse.ArgumentParser()
parser.add_argument("--csv-dir", required=True)
parser.add_argument("--labels", required=True)
parser.add_argument("--out-dir", required=True)
parser.add_argument("--model", required=True)
parser.add_argument("--features", required=True)
args = parser.parse_args()

CSV_DIR = Path(args.csv_dir)
LABELS_FILE = Path(args.labels)
OUT_DIR = Path(args.out_dir)
MODEL_FILE = Path(args.model)
FEATURES_FILE = Path(args.features)

OUT_DIR.mkdir(parents=True, exist_ok=True)

def fail(msg):
    print(f"[ERRO] {msg}")
    raise SystemExit(1)

print("========== AVALIAÇÃO CEGA V3 ==========")
print("[REGRA] Este script NÃO treina modelo.")
print("[REGRA] Ele apenas carrega modelo treinado e testa nova rodada cega.")

if not CSV_DIR.exists():
    fail(f"Pasta CSV não encontrada: {CSV_DIR}")

if not LABELS_FILE.exists():
    fail(f"Labels não encontrados: {LABELS_FILE}")

if not MODEL_FILE.exists():
    fail(f"Modelo não encontrado: {MODEL_FILE}")

if not FEATURES_FILE.exists():
    fail(f"Features não encontradas: {FEATURES_FILE}")

features = [
    line.strip()
    for line in FEATURES_FILE.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

labels = pd.read_csv(LABELS_FILE)
labels["stem"] = labels["filename"].str.replace(".pcap", "", regex=False)

csvs = sorted(CSV_DIR.glob("*.csv"))
print(f"[INFO] CSVs encontrados: {len(csvs)}")

if len(csvs) != 7:
    print("[ALERTA] O esperado são 7 CSVs, um por classe.")

dfs = []

for csv_file in csvs:
    stem = csv_file.stem
    match = labels[labels["stem"] == stem]

    if len(match) != 1:
        fail(f"Não encontrei label para {csv_file.name}")

    meta = match.iloc[0]

    df = pd.read_csv(csv_file, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]

    for col in list(df.columns):
        if col.lower() in ["label", "attack_type", "capture_id", "usage", "source_csv"]:
            df = df.drop(columns=[col])

    df["Label"] = int(meta["label"])
    df["Attack_Type"] = str(meta["attack_type"])
    df["capture_id"] = stem
    df["usage"] = "blind"
    df["source_csv"] = csv_file.name

    print(f"[INFO] {csv_file.name} -> {meta['attack_type']} | linhas: {len(df)}")
    dfs.append(df)

if not dfs:
    fail("Nenhum CSV carregado.")

dataset = pd.concat(dfs, ignore_index=True)
dataset = dataset.replace(
    [np.inf, -np.inf, "Infinity", "-Infinity", "inf", "-inf", "NaN", "nan", ""],
    np.nan
)

missing_features = [f for f in features if f not in dataset.columns]
if missing_features:
    fail(f"Features ausentes no blind: {missing_features}")

for f in features:
    dataset[f] = pd.to_numeric(dataset[f], errors="coerce")

dataset = dataset.dropna(subset=features, how="all")

print("\n[INFO] Shape blind:")
print(dataset.shape)

print("\n[INFO] Distribuição por classe:")
print(dataset["Attack_Type"].value_counts().sort_index())

model = joblib.load(MODEL_FILE)

X = dataset[features]
y_true = dataset["Attack_Type"]
y_pred = model.predict(X)

classes = sorted(y_true.unique())

acc = accuracy_score(y_true, y_pred)

precision_w, recall_w, f1_w, _ = precision_recall_fscore_support(
    y_true,
    y_pred,
    average="weighted",
    zero_division=0
)

precision_m, recall_m, f1_m, _ = precision_recall_fscore_support(
    y_true,
    y_pred,
    average="macro",
    zero_division=0
)

report_dict = classification_report(
    y_true,
    y_pred,
    labels=classes,
    output_dict=True,
    zero_division=0
)

report_text = classification_report(
    y_true,
    y_pred,
    labels=classes,
    zero_division=0
)

per_class_recall = {c: report_dict[c]["recall"] for c in classes}
min_recall = min(per_class_recall.values())

metrics = []
metrics.append("========== RESULTADO TESTE CEGO V3 ==========")
metrics.append(f"Accuracy: {acc:.4f}")
metrics.append(f"Precision weighted: {precision_w:.4f}")
metrics.append(f"Recall weighted: {recall_w:.4f}")
metrics.append(f"F1 weighted: {f1_w:.4f}")
metrics.append(f"Precision macro: {precision_m:.4f}")
metrics.append(f"Recall macro: {recall_m:.4f}")
metrics.append(f"F1 macro: {f1_m:.4f}")
metrics.append(f"Menor recall por classe: {min_recall:.4f}")

metrics.append("\nRecall por classe:")
for c in classes:
    metrics.append(f"- {c}: {per_class_recall[c]:.4f}")

metrics.append("\n========== CLASSIFICATION REPORT ==========")
metrics.append(report_text)

issues = []

if min_recall < 0.70:
    issues.append("Há classe abaixo de 70% no teste cego.")

if f1_m < 0.70:
    issues.append("F1 macro abaixo de 70%.")

metrics.append("\n========== GATE TESTE CEGO ==========")

if issues:
    for i in issues:
        metrics.append(f"- {i}")
    metrics.append("STATUS: REPROVADO NO TESTE CEGO.")
    metrics.append("Ação: esta rodada deve virar dado de treino/validação, e uma nova rodada cega deve ser criada.")
else:
    metrics.append("- Nenhum problema crítico.")
    metrics.append("STATUS: APROVADO NO TESTE CEGO.")

metrics_text = "\n".join(metrics)
print(metrics_text)

(OUT_DIR / "metrics_blind_v3.txt").write_text(metrics_text, encoding="utf-8")

predictions = dataset[["capture_id", "Attack_Type", "Label"]].copy()
predictions["prediction"] = y_pred
predictions.to_csv(OUT_DIR / "predictions_blind_v3.csv", index=False)

cm = confusion_matrix(y_true, y_pred, labels=classes)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=classes)
disp.plot(xticks_rotation=45, values_format="d")
plt.title("Matriz de Confusão — Teste Cego V3")
plt.tight_layout()
plt.savefig(OUT_DIR / "confusion_matrix_blind_v3.png", dpi=300)
plt.close()

summary = pd.DataFrame({
    "classe": classes,
    "recall": [per_class_recall[c] for c in classes]
})
summary.to_csv(OUT_DIR / "recall_por_classe_blind_v3.csv", index=False)

dataset.to_csv(OUT_DIR / "dataset_blind09_labeled.csv", index=False)

print("\n[OK] Arquivos gerados em:", OUT_DIR)
for f in sorted(OUT_DIR.glob("*")):
    print(" -", f)
