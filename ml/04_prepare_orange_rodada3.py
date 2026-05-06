from pathlib import Path
import pandas as pd

DATA_DIR = Path("cicflowmeter/processed_csv")
ORANGE_DIR = Path("orange")
ORANGE_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_FILE = DATA_DIR / "dataset_train.csv"
TEST_FILE = DATA_DIR / "dataset_test.csv"
FEATURES_FILE = DATA_DIR / "feature_columns_no_ports.txt"

print("========== PREPARANDO ARQUIVOS DA RODADA 3 PARA ORANGE ==========")

if not TRAIN_FILE.exists():
    raise SystemExit(f"[ERRO] Não encontrado: {TRAIN_FILE}")
if not TEST_FILE.exists():
    raise SystemExit(f"[ERRO] Não encontrado: {TEST_FILE}")
if not FEATURES_FILE.exists():
    raise SystemExit(f"[ERRO] Não encontrado: {FEATURES_FILE}")

train = pd.read_csv(TRAIN_FILE, low_memory=False)
test = pd.read_csv(TEST_FILE, low_memory=False)

features = [
    line.strip()
    for line in FEATURES_FILE.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

features = [f for f in features if f in train.columns and f in test.columns]

top10 = [
    "fwd_seg_size_avg",
    "pkt_len_std",
    "pkt_len_max",
    "fwd_pkt_len_std",
    "subflow_fwd_byts",
    "pkt_len_var",
    "pkt_size_avg",
    "totlen_fwd_pkts",
    "pkt_len_mean",
    "fwd_pkt_len_mean",
]

top10 = [f for f in top10 if f in features]

print(f"[INFO] Features sem portas: {len(features)}")
print(f"[INFO] Top 10 atributos disponíveis: {len(top10)}")

def make_binary_class(df):
    return df["Label"].astype(int).map({0: "benign", 1: "malicious"})

# Multiclasse sem portas
train_multi = train[features + ["capture_id", "Label", "Attack_Type"]].copy()
test_multi = test[features + ["capture_id", "Label", "Attack_Type"]].copy()

train_multi.to_csv(ORANGE_DIR / "rodada3_multiclass_train_no_ports.csv", index=False)
test_multi.to_csv(ORANGE_DIR / "rodada3_multiclass_test_no_ports.csv", index=False)

# Binário sem portas
train_bin = train[features + ["capture_id", "Attack_Type", "Label"]].copy()
test_bin = test[features + ["capture_id", "Attack_Type", "Label"]].copy()

train_bin["Binary_Class"] = make_binary_class(train_bin)
test_bin["Binary_Class"] = make_binary_class(test_bin)

train_bin = train_bin[features + ["capture_id", "Attack_Type", "Label", "Binary_Class"]]
test_bin = test_bin[features + ["capture_id", "Attack_Type", "Label", "Binary_Class"]]

train_bin.to_csv(ORANGE_DIR / "rodada3_binary_train_no_ports.csv", index=False)
test_bin.to_csv(ORANGE_DIR / "rodada3_binary_test_no_ports.csv", index=False)

# Multiclasse Top 10
train_multi_top10 = train[top10 + ["capture_id", "Label", "Attack_Type"]].copy()
test_multi_top10 = test[top10 + ["capture_id", "Label", "Attack_Type"]].copy()

train_multi_top10.to_csv(ORANGE_DIR / "rodada3_multiclass_train_top10.csv", index=False)
test_multi_top10.to_csv(ORANGE_DIR / "rodada3_multiclass_test_top10.csv", index=False)

readme = """
# Orange — Rodada 3

Estes arquivos representam a Rodada 3, considerada o dataset final consolidado.

## Uso recomendado

Os resultados oficiais foram gerados em Python. O Orange deve ser usado como apoio visual.

## Multiclasse

Treino:
- rodada3_multiclass_train_no_ports.csv

Teste:
- rodada3_multiclass_test_no_ports.csv

Target:
- Attack_Type

Meta:
- capture_id
- Label

## Binário

Treino:
- rodada3_binary_train_no_ports.csv

Teste:
- rodada3_binary_test_no_ports.csv

Target:
- Binary_Class

Meta:
- capture_id
- Attack_Type
- Label

## Top 10 atributos

Treino:
- rodada3_multiclass_train_top10.csv

Teste:
- rodada3_multiclass_test_top10.csv

Target:
- Attack_Type

Meta:
- capture_id
- Label

## Regra metodológica

Não usar split aleatório como resultado principal.

Usar:
- treino = capturas 01, 02 e 03;
- teste = capturas 04.

A versão oficial não usa portas, IP, Timestamp, Flow ID ou capture_id como feature.
"""

(ORANGE_DIR / "README_ORANGE_RODADA3.md").write_text(readme, encoding="utf-8")

print("\n[OK] Arquivos gerados:")
for f in sorted(ORANGE_DIR.glob("rodada3_*.csv")):
    print(f" - {f} | {f.stat().st_size} bytes")
print(f" - {ORANGE_DIR / 'README_ORANGE_RODADA3.md'}")
