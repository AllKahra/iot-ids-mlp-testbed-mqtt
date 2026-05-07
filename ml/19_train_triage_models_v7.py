from pathlib import Path
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, accuracy_score, f1_score

DATASET = Path("cicflowmeter/processed_csv_v7/dataset_v7_rodadas_01_16_reforcos.csv")
FEATURES_FILE = Path("cicflowmeter/processed_csv_v7/feature_columns_no_ports_v7.txt")
OUT_DIR = Path("results/triage_models_v7")

OUT_DIR.mkdir(parents=True, exist_ok=True)

macro_map = {
    "benign": "benign",
    "scan": "recon_scan",
    "bruteforce": "auth_control_repetition",
    "c2_beacon": "auth_control_repetition",
    "dos_flood": "availability_abuse",
    "slow_dos": "availability_abuse",
    "mqtt_abuse": "availability_abuse",
}

print("========== TREINO DOS MODELOS DE TRIAGEM V7 ==========")

if not DATASET.exists():
    raise FileNotFoundError(f"Dataset V7 não encontrado: {DATASET}")

if not FEATURES_FILE.exists():
    raise FileNotFoundError(f"Arquivo de features não encontrado: {FEATURES_FILE}")

df = pd.read_csv(DATASET, low_memory=False)
df = df.replace([np.inf, -np.inf], np.nan)

features = [
    line.strip()
    for line in FEATURES_FILE.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

features = [f for f in features if f in df.columns]

if not features:
    raise ValueError("Nenhuma feature válida encontrada.")

X = df[features].apply(pd.to_numeric, errors="coerce")

def make_rf(random_state=100):
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("clf", RandomForestClassifier(
            n_estimators=800,
            max_depth=12,
            min_samples_leaf=3,
            min_samples_split=8,
            max_features="sqrt",
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
        ))
    ])

def train_and_save(name, X_train, y_train, model_path):
    print(f"\n========== TREINANDO: {name} ==========")
    print("Distribuição:")
    print(pd.Series(y_train).value_counts())

    model = make_rf(random_state=abs(hash(name)) % 100000)
    model.fit(X_train, y_train)

    pred = model.predict(X_train)

    acc = accuracy_score(y_train, pred)
    f1m = f1_score(y_train, pred, average="macro", zero_division=0)

    txt = []
    txt.append(f"========== {name} ==========")
    txt.append(f"Accuracy treino: {acc:.4f}")
    txt.append(f"F1 macro treino: {f1m:.4f}")
    txt.append("")
    txt.append(classification_report(y_train, pred, zero_division=0))

    report = "\n".join(txt)
    print(report)

    model_path = Path(model_path)
    joblib.dump(model, model_path)
    (OUT_DIR / f"metrics_{name}.txt").write_text(report, encoding="utf-8")

    print(f"[OK] Modelo salvo: {model_path}")
    return model

# 1) Binário
y_binary = df["Attack_Type"].apply(lambda x: "benign" if x == "benign" else "malicious")
train_and_save(
    "binary_benign_vs_malicious",
    X,
    y_binary,
    OUT_DIR / "binary_model_v7.pkl"
)

# 2) Macroclasses
df["Macro_Class"] = df["Attack_Type"].map(macro_map)
y_macro = df["Macro_Class"].astype(str)
train_and_save(
    "macroclass",
    X,
    y_macro,
    OUT_DIR / "macroclass_model_v7.pkl"
)

# 3) Especialista auth/control/repetition
auth_classes = ["bruteforce", "c2_beacon"]
auth_df = df[df["Attack_Type"].isin(auth_classes)].copy()
X_auth = auth_df[features].apply(pd.to_numeric, errors="coerce")
y_auth = auth_df["Attack_Type"].astype(str)

train_and_save(
    "specialist_auth_control_repetition",
    X_auth,
    y_auth,
    OUT_DIR / "specialist_auth_control_repetition_v7.pkl"
)

# 4) Especialista availability abuse
availability_classes = ["dos_flood", "slow_dos", "mqtt_abuse"]
avail_df = df[df["Attack_Type"].isin(availability_classes)].copy()
X_avail = avail_df[features].apply(pd.to_numeric, errors="coerce")
y_avail = avail_df["Attack_Type"].astype(str)

train_and_save(
    "specialist_availability_abuse",
    X_avail,
    y_avail,
    OUT_DIR / "specialist_availability_abuse_v7.pkl"
)

# salvar metadados
meta = f"""# Modelos de triagem V7

Dataset:
{DATASET}

Features:
{FEATURES_FILE}

Modelos gerados:
- binary_model_v7.pkl
- macroclass_model_v7.pkl
- specialist_auth_control_repetition_v7.pkl
- specialist_availability_abuse_v7.pkl

Mapeamento de macroclasses:
- benign -> benign
- scan -> recon_scan
- bruteforce + c2_beacon -> auth_control_repetition
- dos_flood + slow_dos + mqtt_abuse -> availability_abuse
"""

(OUT_DIR / "README_TRIAGE_MODELS_V7.md").write_text(meta, encoding="utf-8")
(OUT_DIR / "feature_columns_no_ports_v7.txt").write_text("\n".join(features), encoding="utf-8")

print("\n========== FINALIZADO ==========")
print("[OK] Modelos de triagem salvos em:", OUT_DIR)
for f in sorted(OUT_DIR.glob("*")):
    print(" -", f)
