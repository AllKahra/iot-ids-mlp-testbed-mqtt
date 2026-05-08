from pathlib import Path
import pandas as pd
import numpy as np
import re
import sys

BASE_DATASET = Path("cicflowmeter/processed_csv_v3/dataset_rodadas_01_08_c2reforco.csv")
BASE_FEATURES = Path("cicflowmeter/processed_csv_v3/feature_columns_no_ports_v3.txt")

BLIND09_DATASET = Path("results/blind09_v3/dataset_blind09_labeled.csv")

FLOOD_CSV_DIR = Path("cicflowmeter/raw_csv_reinforce_flood")
FLOOD_LABELS = Path("capture/pcaps/reinforce_flood/pcap_labels_reinforce_flood.csv")

OUT_DIR = Path("cicflowmeter/processed_csv_v4")
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

print("========== BUILD DATASET V4 — BLIND09 + REFORÇO FLOOD ==========")

for p in [BASE_DATASET, BASE_FEATURES, BLIND09_DATASET, FLOOD_CSV_DIR, FLOOD_LABELS]:
    if not p.exists():
        fail(f"Arquivo/pasta não encontrado: {p}")

base = clean_columns(pd.read_csv(BASE_DATASET, low_memory=False))
blind09 = clean_columns(pd.read_csv(BLIND09_DATASET, low_memory=False))

features = [x.strip() for x in BASE_FEATURES.read_text(encoding="utf-8").splitlines() if x.strip()]

print("[INFO] Base V3:")
print(base["Attack_Type"].value_counts().sort_index())

print("\n[INFO] Blind09:")
print(blind09["Attack_Type"].value_counts().sort_index())

labels = pd.read_csv(FLOOD_LABELS)
labels["stem"] = labels["filename"].str.replace(".pcap", "", regex=False)

dfs = []

for csv_file in sorted(FLOOD_CSV_DIR.glob("*.csv")):
    stem = csv_file.stem
    match = labels[labels["stem"] == stem]

    if len(match) != 1:
        fail(f"Sem label para {csv_file.name}")

    meta = match.iloc[0]

    df = clean_columns(pd.read_csv(csv_file, low_memory=False))

    for col in list(df.columns):
        if col.lower() in ["label", "attack_type", "capture_id", "usage", "source_csv", "round_id"]:
            df = df.drop(columns=[col])

    df["Label"] = int(meta["label"])
    df["Attack_Type"] = str(meta["attack_type"])
    df["capture_id"] = stem
    df["usage"] = str(meta["usage"])
    df["source_csv"] = csv_file.name

    print(f"[INFO] Reforço flood: {csv_file.name} -> {len(df)} linhas")
    dfs.append(df)

if not dfs:
    fail("Nenhum CSV de reforço flood carregado.")

reinforce_flood = pd.concat(dfs, ignore_index=True)

combined = pd.concat([base, blind09, reinforce_flood], ignore_index=True, sort=False)
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

print(f"\n[INFO] Linhas removidas sem features: {before - after}")

bad = []
for f in valid_features:
    fl = f.lower()
    if any(p in fl for p in ["port", "src_ip", "dst_ip", "timestamp", "flow_id", "capture_id", "attack_type", "label", "usage", "source_csv"]):
        bad.append(f)

if bad:
    print("[ERRO] Features proibidas:")
    for b in bad:
        print(" -", b)
    fail("Remova features proibidas.")
else:
    print("[OK] Sem features proibidas.")

out_dataset = OUT_DIR / "dataset_v4_rodadas_01_12.csv"
out_features = OUT_DIR / "feature_columns_no_ports_v4.txt"

combined.to_csv(out_dataset, index=False)

with open(out_features, "w", encoding="utf-8") as f:
    for col in valid_features:
        f.write(col + "\n")

print("\n========== DISTRIBUIÇÃO FINAL V4 ==========")
print(combined["Attack_Type"].value_counts().sort_index())

print("\n========== DISTRIBUIÇÃO POR RODADA ==========")
print(combined.groupby(["round_id", "Attack_Type"]).size().to_string())

print("\n[OK] Dataset V4 gerado:")
print(out_dataset)
print(out_features)
