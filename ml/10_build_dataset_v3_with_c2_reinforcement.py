from pathlib import Path
import pandas as pd
import numpy as np
import re
import sys

BASE_DATASET = Path("cicflowmeter/processed_csv_v2/dataset_rodadas_01_05.csv")
BASE_FEATURES = Path("cicflowmeter/processed_csv_v2/feature_columns_no_ports_v2.txt")

C2_CSV_DIR = Path("cicflowmeter/raw_csv_reinforce_c2")
C2_LABELS = Path("capture/pcaps/reinforce_c2/pcap_labels_reinforce_c2.csv")

OUT_DIR = Path("cicflowmeter/processed_csv_v3")
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

print("========== BUILD DATASET V3 — REFORÇO C2 ==========")

if not BASE_DATASET.exists():
    fail(f"Dataset V2 não encontrado: {BASE_DATASET}")

if not BASE_FEATURES.exists():
    fail(f"Features V2 não encontradas: {BASE_FEATURES}")

if not C2_CSV_DIR.exists():
    fail(f"Pasta CSV reforço C2 não encontrada: {C2_CSV_DIR}")

if not C2_LABELS.exists():
    fail(f"Labels reforço C2 não encontrados: {C2_LABELS}")

base = pd.read_csv(BASE_DATASET, low_memory=False)
base = clean_columns(base)

features = [
    line.strip()
    for line in BASE_FEATURES.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

print(f"[INFO] Dataset base V2: {base.shape}")
print("[INFO] Distribuição base:")
print(base["Attack_Type"].value_counts().sort_index())

labels = pd.read_csv(C2_LABELS)
labels["stem"] = labels["filename"].str.replace(".pcap", "", regex=False)

csvs = sorted(C2_CSV_DIR.glob("*.csv"))
print(f"\n[INFO] CSVs reforço C2 encontrados: {len(csvs)}")

dfs = []

for csv_file in csvs:
    stem = csv_file.stem
    match = labels[labels["stem"] == stem]

    if len(match) != 1:
        fail(f"Não achei label para {csv_file.name}")

    meta = match.iloc[0]

    df = pd.read_csv(csv_file, low_memory=False)
    df = clean_columns(df)

    for col in list(df.columns):
        if col.lower() in ["label", "attack_type", "capture_id", "usage", "source_csv", "round_id"]:
            df = df.drop(columns=[col])

    df["Label"] = int(meta["label"])
    df["Attack_Type"] = str(meta["attack_type"])
    df["capture_id"] = stem
    df["usage"] = str(meta["usage"])
    df["source_csv"] = csv_file.name

    print(f"[INFO] {csv_file.name} -> {meta['attack_type']} | linhas: {len(df)}")
    dfs.append(df)

if not dfs:
    fail("Nenhum CSV de reforço carregado.")

reinforce = pd.concat(dfs, ignore_index=True)

combined = pd.concat([base, reinforce], ignore_index=True, sort=False)
combined = combined.replace([np.inf, -np.inf, "Infinity", "-Infinity", "inf", "-inf", "NaN", "nan", ""], np.nan)

valid_features = []
for f in features:
    if f in combined.columns:
        combined[f] = pd.to_numeric(combined[f], errors="coerce")
        valid_features.append(f)
    else:
        print(f"[ALERTA] Feature ausente: {f}")

combined["round_id"] = combined["capture_id"].apply(capture_round)

before = len(combined)
combined = combined.dropna(subset=valid_features, how="all")
after = len(combined)

print(f"\n[INFO] Linhas removidas por ausência total de features: {before - after}")

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
    fail("Remova features proibidas.")
else:
    print("[OK] Nenhuma feature proibida na versão oficial.")

out_dataset = OUT_DIR / "dataset_rodadas_01_08_c2reforco.csv"
out_features = OUT_DIR / "feature_columns_no_ports_v3.txt"

combined.to_csv(out_dataset, index=False)

with open(out_features, "w", encoding="utf-8") as f:
    for col in valid_features:
        f.write(col + "\n")

print("\n========== DISTRIBUIÇÃO FINAL V3 ==========")
print(combined["Attack_Type"].value_counts().sort_index())

print("\n========== DISTRIBUIÇÃO POR RODADA ==========")
print(combined.groupby(["round_id", "Attack_Type"]).size().to_string())

print("\n[OK] Dataset V3 gerado:")
print(f" - {out_dataset}")
print(f" - {out_features}")
