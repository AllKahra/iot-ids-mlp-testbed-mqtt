from pathlib import Path
import pandas as pd
import numpy as np
import re
import sys

OLD_DATASET = Path("cicflowmeter/processed_csv/dataset_full.csv")
OLD_FEATURES = Path("cicflowmeter/processed_csv/feature_columns_no_ports.txt")

BLIND05_CSV_DIR = Path("cicflowmeter/raw_csv_blind05")
BLIND05_LABELS = Path("capture/pcaps/blind05/pcap_labels_blind05.csv")

OUT_DIR = Path("cicflowmeter/processed_csv_v2")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def fail(msg):
    print(f"[ERRO] {msg}")
    sys.exit(1)

def clean_columns(df):
    df.columns = [str(c).strip() for c in df.columns]
    return df

def capture_round(capture_id):
    m = re.search(r"_(\d+)$", str(capture_id))
    if not m:
        return "unknown"
    return m.group(1)

print("========== BUILD DATASET V2 — RODADAS 01 A 05 ==========")

if not OLD_DATASET.exists():
    fail(f"Dataset antigo não encontrado: {OLD_DATASET}")

if not OLD_FEATURES.exists():
    fail(f"Features antigas não encontradas: {OLD_FEATURES}")

if not BLIND05_CSV_DIR.exists():
    fail(f"Pasta da Rodada 05 não encontrada: {BLIND05_CSV_DIR}")

if not BLIND05_LABELS.exists():
    fail(f"Labels da Rodada 05 não encontrados: {BLIND05_LABELS}")

old = pd.read_csv(OLD_DATASET, low_memory=False)
old = clean_columns(old)

features_no_ports = [
    line.strip()
    for line in OLD_FEATURES.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

required_old = {"Label", "Attack_Type", "capture_id"}
missing_old = required_old - set(old.columns)
if missing_old:
    fail(f"Dataset antigo sem colunas obrigatórias: {missing_old}")

print(f"[INFO] Dataset antigo carregado: {old.shape}")
print("[INFO] Distribuição antiga:")
print(old["Attack_Type"].value_counts().sort_index())

labels05 = pd.read_csv(BLIND05_LABELS)
labels05["stem"] = labels05["filename"].str.replace(".pcap", "", regex=False)

csvs05 = sorted(BLIND05_CSV_DIR.glob("*.csv"))
print(f"\n[INFO] CSVs Rodada 05 encontrados: {len(csvs05)}")

if len(csvs05) != 7:
    print("[ALERTA] Esperado: 7 CSVs da Rodada 05.")

dfs05 = []

for csv_file in csvs05:
    stem = csv_file.stem
    match = labels05[labels05["stem"] == stem]

    if len(match) != 1:
        fail(f"Não encontrei label para {csv_file.name}")

    meta = match.iloc[0]
    df = pd.read_csv(csv_file, low_memory=False)
    df = clean_columns(df)

    # Remove metadados antigos caso existam
    for col in list(df.columns):
        if col.lower() in ["label", "attack_type", "capture_id", "usage", "source_csv"]:
            df = df.drop(columns=[col])

    df["Label"] = int(meta["label"])
    df["Attack_Type"] = str(meta["attack_type"])
    df["capture_id"] = stem
    df["usage"] = "train_v2"
    df["source_csv"] = csv_file.name

    print(f"[INFO] {csv_file.name} -> {meta['attack_type']} | linhas: {len(df)}")
    dfs05.append(df)

if not dfs05:
    fail("Nenhum CSV da Rodada 05 foi carregado.")

round05 = pd.concat(dfs05, ignore_index=True)
print(f"\n[INFO] Rodada 05 carregada: {round05.shape}")
print("[INFO] Distribuição Rodada 05:")
print(round05["Attack_Type"].value_counts().sort_index())

# Garante que todos tenham as mesmas colunas
combined = pd.concat([old, round05], ignore_index=True, sort=False)

# Limpeza básica
combined = combined.replace([np.inf, -np.inf, "Infinity", "-Infinity", "inf", "-inf", "NaN", "nan", ""], np.nan)

# Converte features para numérico
valid_features = []
for f in features_no_ports:
    if f in combined.columns:
        combined[f] = pd.to_numeric(combined[f], errors="coerce")
        valid_features.append(f)
    else:
        print(f"[ALERTA] Feature ausente no dataset combinado: {f}")

if not valid_features:
    fail("Nenhuma feature válida encontrada.")

combined["round_id"] = combined["capture_id"].apply(capture_round)

# Remove linhas sem nenhuma feature útil
before = len(combined)
combined = combined.dropna(subset=valid_features, how="all")
after = len(combined)

print(f"\n[INFO] Linhas removidas por ausência total de features: {before - after}")

# Salva
out_dataset = OUT_DIR / "dataset_rodadas_01_05.csv"
out_features = OUT_DIR / "feature_columns_no_ports_v2.txt"

combined.to_csv(out_dataset, index=False)

with open(out_features, "w", encoding="utf-8") as f:
    for col in valid_features:
        f.write(col + "\n")

print("\n========== DISTRIBUIÇÃO FINAL V2 ==========")
print(combined["Attack_Type"].value_counts().sort_index())

print("\n========== DISTRIBUIÇÃO POR RODADA ==========")
print(combined.groupby(["round_id", "Attack_Type"]).size().to_string())

print("\n========== CHECAGEM DE FEATURES PROIBIDAS ==========")
forbidden_patterns = ["port", "src_ip", "dst_ip", "timestamp", "flow_id", "capture_id", "attack_type", "label", "usage", "source_csv"]
bad = []
for f in valid_features:
    fl = f.lower()
    if any(p in fl for p in forbidden_patterns):
        bad.append(f)

if bad:
    print("[ERRO] Features proibidas encontradas:")
    for b in bad:
        print(" -", b)
    fail("Remova as features proibidas antes de treinar.")
else:
    print("[OK] Nenhuma feature proibida na versão oficial sem portas.")

print("\n[OK] Dataset V2 gerado:")
print(f" - {out_dataset}")
print(f" - {out_features}")
