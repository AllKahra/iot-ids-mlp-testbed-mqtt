from pathlib import Path
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

RAW_DIR = Path("cicflowmeter/raw_csv_blind05")
PROCESSED_DIR = Path("cicflowmeter/processed_csv_blind05")
RESULTS_DIR = Path("results/blind05")
ORANGE_DIR = Path("orange/blind05")

LABELS_FILE = Path("capture/pcaps/blind05/pcap_labels_blind05.csv")
FEATURES_FILE = Path("cicflowmeter/processed_csv/feature_columns_no_ports.txt")

MODEL_MULTI = Path("results/prova_precisao/rf_multiclasse_sem_portas_model.pkl")
MODEL_BINARY = Path("results/prova_precisao/rf_binario_sem_portas_model.pkl")

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
ORANGE_DIR.mkdir(parents=True, exist_ok=True)

print("========== AVALIAÇÃO CEGA — RODADA 05 ==========")
print("[REGRA] Este script NÃO treina modelo.")
print("[REGRA] Ele apenas carrega modelos já treinados e testa os CSVs da rodada 05.")

for path, desc in [
    (RAW_DIR, "pasta de CSVs blind05"),
    (LABELS_FILE, "labels blind05"),
    (FEATURES_FILE, "features oficiais sem portas"),
    (MODEL_MULTI, "modelo RF multiclasse sem portas"),
    (MODEL_BINARY, "modelo RF binário sem portas"),
]:
    if not path.exists():
        raise SystemExit(f"[ERRO] Não encontrado: {desc} -> {path}")

labels = pd.read_csv(LABELS_FILE)
labels["stem"] = labels["filename"].str.replace(".pcap", "", regex=False)

features = [
    x.strip()
    for x in FEATURES_FILE.read_text(encoding="utf-8").splitlines()
    if x.strip()
]

csvs = sorted(RAW_DIR.glob("*.csv"))
print(f"\n[INFO] CSVs blind05 encontrados: {len(csvs)}")
for c in csvs:
    print(f" - {c.name}")

if len(csvs) != 7:
    print("[ALERTA] O esperado são 7 CSVs, um por classe.")

all_dfs = []

for csv_file in csvs:
    stem = csv_file.stem
    match = labels[labels["stem"] == stem]

    if len(match) != 1:
        raise SystemExit(f"[ERRO] Não achei label para {csv_file.name}")

    meta = match.iloc[0]

    print(f"[INFO] Processando {csv_file.name} -> {meta['attack_type']}")

    df = pd.read_csv(csv_file, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]

    if df.empty:
        print(f"[ALERTA] CSV vazio ignorado: {csv_file.name}")
        continue

    if "Label" in df.columns:
        df = df.drop(columns=["Label"])

    df["Label"] = int(meta["label"])
    df["Attack_Type"] = str(meta["attack_type"])
    df["capture_id"] = str(meta["stem"])
    df["usage"] = "blind05"
    df["source_csv"] = csv_file.name

    all_dfs.append(df)

if not all_dfs:
    raise SystemExit("[ERRO] Nenhum CSV foi processado.")

dataset = pd.concat(all_dfs, ignore_index=True)

problem_values = [
    np.inf,
    -np.inf,
    "Infinity",
    "-Infinity",
    "inf",
    "-inf",
    "NaN",
    "nan",
    ""
]
dataset = dataset.replace(problem_values, np.nan)

missing_features = [f for f in features if f not in dataset.columns]

if missing_features:
    print("\n[ERRO] Features do modelo não encontradas no dataset blind05:")
    for f in missing_features:
        print(" -", f)
    raise SystemExit("[ERRO] O CSV blind05 não tem as mesmas features usadas na Rodada 3.")

for f in features:
    dataset[f] = pd.to_numeric(dataset[f], errors="coerce")

dataset.to_csv(PROCESSED_DIR / "dataset_blind05.csv", index=False)

print("\n[INFO] Shape dataset blind05:")
print(dataset.shape)

print("\n[INFO] Distribuição blind05 por classe:")
print(dataset["Attack_Type"].value_counts().sort_index())

print("\n[INFO] Distribuição blind05 por capture_id:")
print(dataset["capture_id"].value_counts().sort_index())

X = dataset[features]
y_multi = dataset["Attack_Type"]
y_binary = dataset["Label"].astype(int)

model_multi = joblib.load(MODEL_MULTI)
model_binary = joblib.load(MODEL_BINARY)

pred_multi = model_multi.predict(X)
pred_binary = model_binary.predict(X)

def evaluate(name, y_true, y_pred, labels_list, display_labels):
    print(f"\n========== {name} ==========")

    acc = accuracy_score(y_true, y_pred)
    p_w, r_w, f1_w, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )
    p_m, r_m, f1_m, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )

    report = classification_report(y_true, y_pred, zero_division=0)

    text = []
    text.append(f"========== {name} ==========")
    text.append(f"Accuracy: {acc:.6f}")
    text.append(f"Precision weighted: {p_w:.6f}")
    text.append(f"Recall weighted: {r_w:.6f}")
    text.append(f"F1 weighted: {f1_w:.6f}")
    text.append(f"Precision macro: {p_m:.6f}")
    text.append(f"Recall macro: {r_m:.6f}")
    text.append(f"F1 macro: {f1_m:.6f}")
    text.append("")
    text.append("========== CLASSIFICATION REPORT ==========")
    text.append(report)

    output = "\n".join(text)
    print(output)

    safe = (
        name.lower()
        .replace(" ", "_")
        .replace("—", "-")
        .replace("á", "a")
        .replace("í", "i")
        .replace("ã", "a")
        .replace("ç", "c")
    )

    (RESULTS_DIR / f"{safe}_metrics.txt").write_text(output, encoding="utf-8")

    cm = confusion_matrix(y_true, y_pred, labels=labels_list)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=display_labels)
    disp.plot(xticks_rotation=45, values_format="d")
    plt.title(name)
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / f"{safe}_confusion_matrix.png", dpi=300)
    plt.close()

    return {
        "experimento": name,
        "accuracy": acc,
        "precision_weighted": p_w,
        "recall_weighted": r_w,
        "f1_weighted": f1_w,
        "precision_macro": p_m,
        "recall_macro": r_m,
        "f1_macro": f1_m
    }

classes = sorted(y_multi.unique())

results = []
results.append(evaluate(
    "RF multiclasse blind05 sem retreino",
    y_multi,
    pred_multi,
    classes,
    classes
))

results.append(evaluate(
    "RF binario blind05 sem retreino",
    y_binary,
    pred_binary,
    [0, 1],
    ["benign", "malicious"]
))

comparison = pd.DataFrame(results)
comparison.to_csv(RESULTS_DIR / "comparison_blind05.csv", index=False)

predictions = pd.DataFrame({
    "capture_id": dataset["capture_id"].values,
    "attack_type_true": dataset["Attack_Type"].values,
    "label_true": dataset["Label"].values,
    "prediction_multiclass": pred_multi,
    "prediction_binary": pred_binary
})

predictions.to_csv(RESULTS_DIR / "predictions_blind05.csv", index=False)

# Export para Orange, se quiser visualizar depois
multi_orange = dataset[features + ["Attack_Type", "capture_id", "Label"]].copy()
multi_orange.to_csv(ORANGE_DIR / "rodada5_multiclass_blind_no_ports.csv", index=False)

bin_orange = dataset[features + ["Label", "Attack_Type", "capture_id"]].copy()
bin_orange["Binary_Class"] = bin_orange["Label"].astype(int).map({0: "benign", 1: "malicious"})
bin_orange = bin_orange[features + ["Binary_Class", "Label", "Attack_Type", "capture_id"]]
bin_orange.to_csv(ORANGE_DIR / "rodada5_binary_blind_no_ports.csv", index=False)

summary = []
summary.append("# Avaliação cega — Rodada 05\n")
summary.append("## Regra metodológica\n")
summary.append("Os PCAPs da rodada 05 foram utilizados apenas como teste cego. O modelo não foi treinado novamente.\n")
summary.append("## Distribuição por classe\n")
summary.append(dataset["Attack_Type"].value_counts().sort_index().to_string())
summary.append("\n\n## Resultados\n")
summary.append(comparison.to_string(index=False))
summary.append("\n\n## Interpretação\n")
summary.append("Se o desempenho se mantiver alto na rodada 05, isso reforça que o modelo generaliza para novas capturas dentro do testbed.")
summary.append("Se houver queda, a matriz de confusão deve ser usada para identificar quais classes precisam de mais variação.")
summary.append("Esse teste ainda é interno ao ambiente simulado, portanto não representa validação em rede IoT real.")

(RESULTS_DIR / "resumo_blind05.md").write_text("\n".join(summary), encoding="utf-8")

print("\n========== COMPARAÇÃO BLIND05 ==========")
print(comparison.to_string(index=False))

print("\n[OK] Arquivos gerados:")
for f in sorted(RESULTS_DIR.glob("*")):
    print(" -", f)

print("\n[OK] Export Orange:")
for f in sorted(ORANGE_DIR.glob("*")):
    print(" -", f)
