from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

DATA_DIR = Path("cicflowmeter/processed_csv")
OUT_DIR = Path("results/prova_precisao")
OUT_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_FILE = DATA_DIR / "dataset_train.csv"
TEST_FILE = DATA_DIR / "dataset_test.csv"
NO_PORTS_FILE = DATA_DIR / "feature_columns_no_ports.txt"
WITH_PORTS_FILE = DATA_DIR / "feature_columns_with_ports.txt"

print("========== PROVA DE PRECISÃO — RANDOM FOREST ==========")

train = pd.read_csv(TRAIN_FILE, low_memory=False)
test = pd.read_csv(TEST_FILE, low_memory=False)

features_no_ports = [x.strip() for x in NO_PORTS_FILE.read_text(encoding="utf-8").splitlines() if x.strip()]
features_with_ports = [x.strip() for x in WITH_PORTS_FILE.read_text(encoding="utf-8").splitlines() if x.strip()]

features_no_ports = [f for f in features_no_ports if f in train.columns and f in test.columns]
features_with_ports = [f for f in features_with_ports if f in train.columns and f in test.columns]

print(f"[INFO] Linhas treino: {len(train)}")
print(f"[INFO] Linhas teste: {len(test)}")
print(f"[INFO] Features sem portas: {len(features_no_ports)}")
print(f"[INFO] Features com portas: {len(features_with_ports)}")

def build_rf(random_state=42):
    return Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("variance", VarianceThreshold(threshold=0.0)),
        ("rf", RandomForestClassifier(
            n_estimators=200,
            random_state=random_state,
            class_weight=None,
            n_jobs=-1
        ))
    ])

def evaluate_model(name, features, target_col, labels=None, shuffled=False):
    print(f"\n========== {name} ==========")

    X_train = train[features]
    X_test = test[features]

    y_train = train[target_col].copy()
    y_test = test[target_col].copy()

    if shuffled:
        rng = np.random.default_rng(42)
        y_train = pd.Series(rng.permutation(y_train.values), index=y_train.index)

    model = build_rf()
    model.fit(X_train, y_train)

    pred_train = model.predict(X_train)
    pred_test = model.predict(X_test)

    acc_train = accuracy_score(y_train, pred_train)
    acc_test = accuracy_score(y_test, pred_test)

    p_w, r_w, f1_w, _ = precision_recall_fscore_support(
        y_test, pred_test, average="weighted", zero_division=0
    )
    p_m, r_m, f1_m, _ = precision_recall_fscore_support(
        y_test, pred_test, average="macro", zero_division=0
    )

    result = {
        "experimento": name,
        "target": target_col,
        "features": len(features),
        "accuracy_train": acc_train,
        "accuracy_test": acc_test,
        "precision_weighted": p_w,
        "recall_weighted": r_w,
        "f1_weighted": f1_w,
        "precision_macro": p_m,
        "recall_macro": r_m,
        "f1_macro": f1_m,
        "gap_train_test": acc_train - acc_test
    }

    print(pd.DataFrame([result]).to_string(index=False))

    report = classification_report(y_test, pred_test, zero_division=0)
    print("\n========== CLASSIFICATION REPORT ==========")
    print(report)

    safe_name = name.lower().replace(" ", "_").replace("—", "-").replace("/", "_")
    (OUT_DIR / f"{safe_name}_report.txt").write_text(report, encoding="utf-8")

    if labels is None:
        labels = sorted(pd.Series(y_test).unique())

    cm = confusion_matrix(y_test, pred_test, labels=labels)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    disp.plot(xticks_rotation=45, values_format="d")
    plt.title(name)
    plt.tight_layout()
    plt.savefig(OUT_DIR / f"{safe_name}_confusion_matrix.png", dpi=300)
    plt.close()

    # Feature importance somente para RF com target real
    try:
        rf = model.named_steps["rf"]
        kept_mask = model.named_steps["variance"].get_support()
        kept_features = np.array(features)[kept_mask]
        importances = pd.DataFrame({
            "feature": kept_features,
            "importance": rf.feature_importances_
        }).sort_values("importance", ascending=False)

        importances.to_csv(OUT_DIR / f"{safe_name}_feature_importance.csv", index=False)

        top = importances.head(15)
        plt.figure(figsize=(10, 6))
        plt.barh(top["feature"][::-1], top["importance"][::-1])
        plt.title(f"Top atributos — {name}")
        plt.xlabel("Importância")
        plt.tight_layout()
        plt.savefig(OUT_DIR / f"{safe_name}_feature_importance.png", dpi=300)
        plt.close()
    except Exception as e:
        print(f"[ALERTA] Não foi possível gerar importância de atributos: {e}")

    joblib.dump(model, OUT_DIR / f"{safe_name}_model.pkl")

    predictions = pd.DataFrame({
        "capture_id": test["capture_id"].values,
        "y_true": y_test.values,
        "y_pred": pred_test
    })
    if "Attack_Type" in test.columns:
        predictions["attack_type_original"] = test["Attack_Type"].values
    predictions.to_csv(OUT_DIR / f"{safe_name}_predictions.csv", index=False)

    return result

results = []

class_labels = sorted(test["Attack_Type"].unique())

# 1. Resultado oficial multiclasse sem portas
results.append(evaluate_model(
    name="RF multiclasse sem portas",
    features=features_no_ports,
    target_col="Attack_Type",
    labels=class_labels
))

# 2. Resultado binário sem portas
results.append(evaluate_model(
    name="RF binario sem portas",
    features=features_no_ports,
    target_col="Label",
    labels=[0, 1]
))

# 3. Comparação com portas
results.append(evaluate_model(
    name="RF multiclasse com portas",
    features=features_with_ports,
    target_col="Attack_Type",
    labels=class_labels
))

# 4. Top 10 atributos a partir da importância do RF oficial
importance_file = OUT_DIR / "rf_multiclasse_sem_portas_feature_importance.csv"
if importance_file.exists():
    imp = pd.read_csv(importance_file)
    top10_features = imp["feature"].head(10).tolist()
else:
    top10_features = features_no_ports[:10]

(OUT_DIR / "top10_features.txt").write_text("\n".join(top10_features), encoding="utf-8")

results.append(evaluate_model(
    name="RF multiclasse Top 10 atributos",
    features=top10_features,
    target_col="Attack_Type",
    labels=class_labels
))

# 5. Teste de sanidade: labels embaralhados
results.append(evaluate_model(
    name="RF multiclasse labels embaralhados",
    features=features_no_ports,
    target_col="Attack_Type",
    labels=class_labels,
    shuffled=True
))

comparison = pd.DataFrame(results)
comparison.to_csv(OUT_DIR / "comparacao_prova_precisao.csv", index=False)

print("\n========== TABELA COMPARATIVA FINAL ==========")
print(comparison.to_string(index=False))

summary = []
summary.append("# Prova de precisão — Random Forest\n")
summary.append("## Objetivo\n")
summary.append("Validar se o desempenho perfeito da Rodada 3 é coerente com a metodologia e não depende de atalhos óbvios como portas, IPs, Timestamp, Flow ID ou capture_id.\n")

summary.append("## Separação treino/teste\n")
summary.append("- Treino: capturas 01, 02 e 03.")
summary.append("- Teste: capturas 04.")
summary.append("- O teste foi separado do treino por capture_id.\n")

summary.append("## Experimentos\n")
summary.append(comparison.to_markdown(index=False))

summary.append("\n## Top 10 atributos\n")
for f in top10_features:
    summary.append(f"- {f}")

summary.append("\n## Interpretação\n")
summary.append("- Se o modelo sem portas mantém desempenho alto, não há evidência de dependência direta de portas.")
summary.append("- Se Top 10 mantém desempenho próximo ao conjunto completo, poucos atributos comportamentais concentram poder discriminativo.")
summary.append("- Se labels embaralhados derrubam desempenho, o pipeline não está acertando por vazamento estrutural óbvio.")
summary.append("- O resultado deve ser interpretado dentro do escopo do testbed simulado, não como IDS universal.")

(OUT_DIR / "resumo_prova_precisao.md").write_text("\n".join(summary), encoding="utf-8")

print("\n[OK] Arquivos gerados em:", OUT_DIR)
for f in sorted(OUT_DIR.glob("*")):
    print(" -", f)
