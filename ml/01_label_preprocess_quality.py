from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import hashlib
import sys

PCAP_DIR = Path("capture/pcaps/final")
RAW_CSV_DIR = Path("cicflowmeter/raw_csv")
PROCESSED_DIR = Path("cicflowmeter/processed_csv")
LABELED_DIR = PROCESSED_DIR / "labeled_individual"
RESULTS_DIR = Path("results")

LABELS_FILE = PCAP_DIR / "pcap_labels.csv"
HASH_FILE = PCAP_DIR / "SHA256SUMS.txt"

EXPECTED_CLASSES = {
    "benign",
    "scan",
    "bruteforce",
    "c2_beacon",
    "dos_flood",
    "slow_dos",
    "mqtt_abuse",
}

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
LABELED_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def fail(msg):
    print(f"[ERRO] {msg}")
    sys.exit(1)

def norm_col(c):
    return str(c).strip().lower().replace(" ", "_").replace("-", "_")

print("========== DIA 3 — ROTULAGEM, PRÉ-PROCESSAMENTO E GATE DO DATASET ==========")

# 1. Auditoria dos PCAPs
if not PCAP_DIR.exists():
    fail(f"Pasta não encontrada: {PCAP_DIR}")

pcaps = sorted(PCAP_DIR.glob("*.pcap"))
print(f"\n[INFO] PCAPs encontrados: {len(pcaps)}")
for p in pcaps:
    print(f" - {p.name}")

if len(pcaps) != 28:
    fail("A quantidade de PCAPs oficiais precisa ser 28.")

# 2. Labels
if not LABELS_FILE.exists():
    fail("pcap_labels.csv não encontrado.")

labels = pd.read_csv(LABELS_FILE)
labels.columns = [str(c).strip() for c in labels.columns]

required_cols = {"filename", "usage", "label", "attack_type"}
if not required_cols.issubset(labels.columns):
    fail(f"pcap_labels.csv precisa conter: {required_cols}")

if len(labels) != 28:
    fail("pcap_labels.csv precisa ter 28 linhas.")

classes = set(labels["attack_type"].unique())
if classes != EXPECTED_CLASSES:
    fail(f"Classes incorretas. Esperado {EXPECTED_CLASSES}, encontrado {classes}")

print("\n[INFO] Labels por usage:")
print(labels["usage"].value_counts())

print("\n[INFO] Labels por attack_type:")
print(labels["attack_type"].value_counts().sort_index())

# 3. Hashes
if HASH_FILE.exists():
    print("\n[INFO] SHA256SUMS.txt encontrado. Validando hashes...")
    errors = []
    with open(HASH_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            expected_hash = line.split()[0]
            file_path = line.split()[-1]
            candidate = Path(file_path)
            if not candidate.exists():
                candidate = PCAP_DIR / Path(file_path).name
            if not candidate.exists():
                errors.append(f"Arquivo não encontrado no hash: {file_path}")
                continue
            h = hashlib.sha256()
            with open(candidate, "rb") as pf:
                for chunk in iter(lambda: pf.read(8192), b""):
                    h.update(chunk)
            if h.hexdigest() != expected_hash:
                errors.append(f"Hash diferente: {candidate.name}")
    if errors:
        for e in errors:
            print(f"[ERRO] {e}")
        fail("Falha na validação de SHA256.")
    print("[OK] Hashes validados.")
else:
    print("[ALERTA] SHA256SUMS.txt não encontrado.")

# 4. CSVs brutos
csvs = sorted(RAW_CSV_DIR.glob("*.csv"))
print(f"\n[INFO] CSVs brutos encontrados: {len(csvs)}")
for c in csvs:
    print(f" - {c.name}")

if len(csvs) != 28:
    fail("Esperado: 28 CSVs brutos em cicflowmeter/raw_csv.")

# 5. Rotulagem
labels["stem"] = labels["filename"].str.replace(".pcap", "", regex=False)

all_dfs = []
unmatched = []

print("\n========== ROTULAGEM DOS CSVs ==========")

for csv_file in csvs:
    csv_name_lower = csv_file.name.lower()
    matches = labels[labels["stem"].apply(lambda s: str(s).lower() in csv_name_lower)]

    if len(matches) != 1:
        unmatched.append(csv_file.name)
        print(f"[ALERTA] Não foi possível mapear automaticamente: {csv_file.name}")
        continue

    meta = matches.iloc[0]
    print(f"[INFO] {csv_file.name} -> {meta['attack_type']} / {meta['usage']}")

    try:
        df = pd.read_csv(csv_file, low_memory=False)
    except Exception as e:
        fail(f"Erro lendo {csv_file.name}: {e}")

    if df.empty:
        fail(f"CSV vazio: {csv_file.name}")

    df.columns = [str(c).strip() for c in df.columns]

    # Remove label própria do CICFlowMeter, se existir
    for possible_label in ["Label", "label"]:
        if possible_label in df.columns:
            df = df.drop(columns=[possible_label])

    df["Label"] = int(meta["label"])
    df["Attack_Type"] = str(meta["attack_type"])
    df["capture_id"] = str(meta["stem"])
    df["usage"] = str(meta["usage"])
    df["source_csv"] = csv_file.name

    out_individual = LABELED_DIR / f"{meta['stem']}_labeled.csv"
    df.to_csv(out_individual, index=False)

    all_dfs.append(df)

if unmatched:
    print("\n[ERRO] CSVs sem mapeamento:")
    for u in unmatched:
        print(f" - {u}")
    fail("Renomeie os CSVs para conter o nome do PCAP. Exemplo: benign_01.csv")

dataset = pd.concat(all_dfs, ignore_index=True)
raw_out = PROCESSED_DIR / "dataset_full_raw_labeled.csv"
dataset.to_csv(raw_out, index=False)

print(f"\n[OK] Dataset bruto rotulado criado: {raw_out}")
print(f"[INFO] Shape bruto: {dataset.shape}")

# 6. Pré-processamento
print("\n========== PRÉ-PROCESSAMENTO ==========")

df = dataset.copy()
df.columns = [str(c).strip() for c in df.columns]

required = {"Label", "Attack_Type", "capture_id", "usage"}
missing = required - set(df.columns)
if missing:
    fail(f"Colunas obrigatórias ausentes: {missing}")

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
df = df.replace(problem_values, np.nan)

before_dup = len(df)
df = df.drop_duplicates()
after_dup = len(df)
print(f"[INFO] Duplicados removidos: {before_dup - after_dup}")

base_forbidden_norm = {
    "flow_id",
    "src_ip",
    "dst_ip",
    "timestamp",
    "label",
    "attack_type",
    "capture_id",
    "usage",
    "source_csv",
    "source_ip",
    "destination_ip",
    "source",
    "destination",
    "protocolname",
    "protocol_name",
}

# Converte colunas candidatas para numérico
for col in df.columns:
    n = norm_col(col)
    if n not in base_forbidden_norm:
        df[col] = pd.to_numeric(df[col], errors="coerce")

# Remove colunas totalmente vazias
empty_cols = [c for c in df.columns if df[c].isna().all()]
if empty_cols:
    print("\n[INFO] Colunas totalmente vazias removidas:")
    for c in empty_cols:
        print(f" - {c}")
    df = df.drop(columns=empty_cols)

features_no_ports = []
features_with_ports = []

for col in df.columns:
    n = norm_col(col)

    if n in base_forbidden_norm:
        continue

    if not pd.api.types.is_numeric_dtype(df[col]):
        continue

    # Versão com portas: mantém portas, mas sem IP/timestamp/capture_id/etc.
    features_with_ports.append(col)

    # Versão oficial sem portas: bloqueia qualquer coluna contendo "port"
    if "port" not in n:
        features_no_ports.append(col)

if not features_no_ports:
    fail("Nenhuma feature oficial sem portas encontrada.")

if not features_with_ports:
    fail("Nenhuma feature complementar com portas encontrada.")

# Auditoria forte: versão oficial não pode conter port
official_port_leaks = [f for f in features_no_ports if "port" in norm_col(f)]
if official_port_leaks:
    print("[ERRO] Features oficiais ainda possuem porta:")
    for f in official_port_leaks:
        print(f" - {f}")
    fail("Remoção de portas falhou.")

print(f"\n[INFO] Features oficiais SEM portas: {len(features_no_ports)}")
for f in features_no_ports:
    print(f" - {f}")

print(f"\n[INFO] Features complementares COM portas: {len(features_with_ports)}")
for f in features_with_ports:
    print(f" - {f}")

before_empty_rows = len(df)
df = df.dropna(subset=features_no_ports, how="all")
after_empty_rows = len(df)
print(f"\n[INFO] Linhas sem features úteis removidas: {before_empty_rows - after_empty_rows}")

train_df = df[df["usage"] == "train"].copy()
test_df = df[df["usage"] == "test"].copy()

if train_df.empty:
    fail("dataset_train ficou vazio.")
if test_df.empty:
    fail("dataset_test ficou vazio.")

df.to_csv(PROCESSED_DIR / "dataset_full.csv", index=False)
train_df.to_csv(PROCESSED_DIR / "dataset_train.csv", index=False)
test_df.to_csv(PROCESSED_DIR / "dataset_test.csv", index=False)

(PROCESSED_DIR / "feature_columns_no_ports.txt").write_text(
    "\n".join(features_no_ports) + "\n",
    encoding="utf-8"
)

(PROCESSED_DIR / "feature_columns_with_ports.txt").write_text(
    "\n".join(features_with_ports) + "\n",
    encoding="utf-8"
)

(PROCESSED_DIR / "feature_columns.txt").write_text(
    "\n".join(features_no_ports) + "\n",
    encoding="utf-8"
)

dist = df.groupby(["usage", "Attack_Type"]).size().reset_index(name="rows")
dist.to_csv(PROCESSED_DIR / "class_distribution.csv", index=False)

plt.figure(figsize=(10, 6))
counts = df["Attack_Type"].value_counts().sort_index()
plt.bar(counts.index, counts.values)
plt.title("Distribuição de classes no dataset")
plt.xlabel("Classe")
plt.ylabel("Quantidade de fluxos")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig(RESULTS_DIR / "class_distribution.png", dpi=300)
plt.close()

# 7. Gate do dataset
print("\n========== GATE DE QUALIDADE DO DATASET ==========")

train_counts = train_df["Attack_Type"].value_counts().sort_index()
test_counts = test_df["Attack_Type"].value_counts().sort_index()

print("\n[INFO] Distribuição treino:")
print(train_counts)

print("\n[INFO] Distribuição teste:")
print(test_counts)

dataset_gate = []
dataset_gate.append("========== GATE DE QUALIDADE DO DATASET ==========")
dataset_gate.append("\nDistribuição treino:")
dataset_gate.append(train_counts.to_string())
dataset_gate.append("\nDistribuição teste:")
dataset_gate.append(test_counts.to_string())

severe_issues = []
warnings = []

for cls in sorted(EXPECTED_CLASSES):
    tr = int(train_counts.get(cls, 0))
    te = int(test_counts.get(cls, 0))

    if tr < 20:
        severe_issues.append(f"{cls}: treino com apenas {tr} fluxos. Mínimo crítico recomendado: 20.")
    elif tr < 50:
        warnings.append(f"{cls}: treino com {tr} fluxos. Ideal: 50 ou mais.")

    if te < 5:
        severe_issues.append(f"{cls}: teste com apenas {te} fluxos. Mínimo crítico recomendado: 5.")
    elif te < 15:
        warnings.append(f"{cls}: teste com {te} fluxos. Ideal: 15 ou mais.")

dataset_gate.append("\nProblemas críticos:")
if severe_issues:
    for item in severe_issues:
        dataset_gate.append(f"- {item}")
else:
    dataset_gate.append("- Nenhum problema crítico.")

dataset_gate.append("\nAlertas:")
if warnings:
    for item in warnings:
        dataset_gate.append(f"- {item}")
else:
    dataset_gate.append("- Nenhum alerta.")

if severe_issues:
    dataset_gate.append("\nSTATUS: REPROVADO PARA RESULTADO FINAL APRESENTÁVEL.")
    dataset_gate.append("Ação: gere mais tráfego/PCAPs para as classes com poucos fluxos antes de considerar o modelo final.")
else:
    dataset_gate.append("\nSTATUS: APROVADO PARA TREINAMENTO INICIAL.")

gate_text = "\n".join(dataset_gate)
print(gate_text)

(RESULTS_DIR / "quality_gate_dataset.txt").write_text(gate_text, encoding="utf-8")

print("\n[OK] Arquivos gerados:")
print(f" - {PROCESSED_DIR / 'dataset_full_raw_labeled.csv'}")
print(f" - {PROCESSED_DIR / 'dataset_full.csv'}")
print(f" - {PROCESSED_DIR / 'dataset_train.csv'}")
print(f" - {PROCESSED_DIR / 'dataset_test.csv'}")
print(f" - {PROCESSED_DIR / 'feature_columns_no_ports.txt'}")
print(f" - {PROCESSED_DIR / 'feature_columns_with_ports.txt'}")
print(f" - {PROCESSED_DIR / 'class_distribution.csv'}")
print(f" - {RESULTS_DIR / 'class_distribution.png'}")
print(f" - {RESULTS_DIR / 'quality_gate_dataset.txt'}")
