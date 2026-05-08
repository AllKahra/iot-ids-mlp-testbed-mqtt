from pathlib import Path
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.base import clone
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import VarianceThreshold
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

DATASET = Path("cicflowmeter/processed_csv_v4/dataset_v4_rodadas_01_12.csv")
FEATURES_FILE = Path("cicflowmeter/processed_csv_v4/feature_columns_no_ports_v4.txt")
OUT_DIR = Path("results/modelo_v4_groupcv")
OUT_DIR.mkdir(parents=True, exist_ok=True)

TARGET = "Attack_Type"

print("========== TREINO V2 — GROUP CV POR RODADA ==========")

df = pd.read_csv(DATASET, low_memory=False)
features = [
    line.strip()
    for line in FEATURES_FILE.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

classes = sorted(df[TARGET].dropna().unique())

X = df[features].copy()
y = df[TARGET].copy()
groups = df["round_id"].astype(str).copy()

print(f"[INFO] Linhas totais: {len(df)}")
print(f"[INFO] Features: {len(features)}")
print(f"[INFO] Rodadas: {sorted(groups.unique())}")
print("\n[INFO] Distribuição por classe:")
print(y.value_counts().sort_index())

print("\n[INFO] Distribuição por rodada/classe:")
print(df.groupby(["round_id", TARGET]).size().to_string())

candidate_models = {
    "rf_regularizado_depth6_leaf10": RandomForestClassifier(
        n_estimators=600,
        max_depth=6,
        min_samples_leaf=10,
        min_samples_split=20,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    ),
    "rf_regularizado_depth8_leaf5": RandomForestClassifier(
        n_estimators=700,
        max_depth=8,
        min_samples_leaf=5,
        min_samples_split=10,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    ),
    "rf_regularizado_depth10_leaf3": RandomForestClassifier(
        n_estimators=700,
        max_depth=10,
        min_samples_leaf=3,
        min_samples_split=8,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    ),
    "rf_regularizado_depth12_leaf3": RandomForestClassifier(
        n_estimators=800,
        max_depth=12,
        min_samples_leaf=3,
        min_samples_split=8,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    ),
    "extratrees_regularizado_depth10_leaf3": ExtraTreesClassifier(
        n_estimators=800,
        max_depth=10,
        min_samples_leaf=3,
        min_samples_split=8,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
}

def make_pipeline(base_model):
    return Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("variance", VarianceThreshold(threshold=0.0)),
        ("model", base_model)
    ])

def evaluate_candidate(name, base_model):
    print(f"\n========== AVALIANDO: {name} ==========")

    all_true = []
    all_pred = []
    fold_rows = []
    train_accs = []
    val_accs = []

    for round_id in sorted(groups.unique()):
        train_idx = groups != round_id
        val_idx = groups == round_id

        X_train, X_val = X.loc[train_idx], X.loc[val_idx]
        y_train, y_val = y.loc[train_idx], y.loc[val_idx]

        model = make_pipeline(clone(base_model))
        model.fit(X_train, y_train)

        pred_train = model.predict(X_train)
        pred_val = model.predict(X_val)

        train_acc = accuracy_score(y_train, pred_train)
        val_acc = accuracy_score(y_val, pred_val)

        train_accs.append(train_acc)
        val_accs.append(val_acc)

        all_true.extend(y_val.tolist())
        all_pred.extend(pred_val.tolist())

        report_fold = classification_report(
            y_val,
            pred_val,
            labels=classes,
            output_dict=True,
            zero_division=0
        )

        min_recall_fold = min(report_fold[c]["recall"] for c in classes)

        fold_rows.append({
            "modelo": name,
            "rodada_validacao": round_id,
            "train_acc": train_acc,
            "val_acc": val_acc,
            "gap": train_acc - val_acc,
            "min_recall_fold": min_recall_fold,
            "macro_f1_fold": report_fold["macro avg"]["f1-score"],
            "weighted_f1_fold": report_fold["weighted avg"]["f1-score"]
        })

        print(f"[FOLD rodada {round_id}] train_acc={train_acc:.4f} | val_acc={val_acc:.4f} | gap={train_acc - val_acc:.4f} | min_recall={min_recall_fold:.4f}")

    report = classification_report(
        all_true,
        all_pred,
        labels=classes,
        output_dict=True,
        zero_division=0
    )

    per_class_recall = {c: report[c]["recall"] for c in classes}
    min_recall = min(per_class_recall.values())
    macro_f1 = report["macro avg"]["f1-score"]
    weighted_f1 = report["weighted avg"]["f1-score"]
    acc = accuracy_score(all_true, all_pred)
    mean_gap = float(np.mean(train_accs) - np.mean(val_accs))

    row = {
        "modelo": name,
        "accuracy_groupcv": acc,
        "f1_macro_groupcv": macro_f1,
        "f1_weighted_groupcv": weighted_f1,
        "min_recall_groupcv": min_recall,
        "mean_train_acc": float(np.mean(train_accs)),
        "mean_val_acc": float(np.mean(val_accs)),
        "mean_gap": mean_gap
    }

    for c in classes:
        row[f"recall_{c}"] = per_class_recall[c]

    # Score de escolha: prioriza recall mínimo e macro F1, penaliza gap
    row["selection_score"] = (min_recall * 2.0) + macro_f1 - max(mean_gap, 0) * 0.5

    print("\n[RESULTADO GROUPCV]")
    print(f"Accuracy: {acc:.4f}")
    print(f"F1 macro: {macro_f1:.4f}")
    print(f"F1 weighted: {weighted_f1:.4f}")
    print(f"Menor recall por classe: {min_recall:.4f}")
    print(f"Gap médio treino-validação: {mean_gap:.4f}")

    print("\n[RECALL POR CLASSE]")
    for c in classes:
        print(f" - {c}: {per_class_recall[c]:.4f}")

    report_text = classification_report(
        all_true,
        all_pred,
        labels=classes,
        zero_division=0
    )

    (OUT_DIR / f"{name}_classification_report_groupcv.txt").write_text(report_text, encoding="utf-8")

    cm = confusion_matrix(all_true, all_pred, labels=classes)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=classes)
    disp.plot(xticks_rotation=45, values_format="d")
    plt.title(f"Matriz GroupCV — {name}")
    plt.tight_layout()
    plt.savefig(OUT_DIR / f"{name}_confusion_matrix_groupcv.png", dpi=300)
    plt.close()

    return row, fold_rows

all_rows = []
all_folds = []

for name, base_model in candidate_models.items():
    row, fold_rows = evaluate_candidate(name, base_model)
    all_rows.append(row)
    all_folds.extend(fold_rows)

comparison = pd.DataFrame(all_rows).sort_values(
    ["min_recall_groupcv", "f1_macro_groupcv", "mean_gap"],
    ascending=[False, False, True]
)

folds = pd.DataFrame(all_folds)

comparison.to_csv(OUT_DIR / "comparison_groupcv_models.csv", index=False)
folds.to_csv(OUT_DIR / "folds_groupcv_models.csv", index=False)

print("\n========== COMPARAÇÃO FINAL DOS MODELOS ==========")
print(comparison.to_string(index=False))

best = comparison.iloc[0]
best_name = best["modelo"]
best_model_base = candidate_models[best_name]

print(f"\n[INFO] Melhor modelo escolhido: {best_name}")

final_model = make_pipeline(clone(best_model_base))
final_model.fit(X, y)

joblib.dump(final_model, OUT_DIR / "best_model_v2_groupcv.pkl")

with open(OUT_DIR / "feature_columns_no_ports_v2.txt", "w", encoding="utf-8") as f:
    for col in features:
        f.write(col + "\n")

gate = []
gate.append("========== GATE MODELO V2 — GROUP CV POR RODADA ==========")
gate.append(f"Melhor modelo: {best_name}")
gate.append(f"Accuracy GroupCV: {best['accuracy_groupcv']:.4f}")
gate.append(f"F1 macro GroupCV: {best['f1_macro_groupcv']:.4f}")
gate.append(f"F1 weighted GroupCV: {best['f1_weighted_groupcv']:.4f}")
gate.append(f"Menor recall por classe: {best['min_recall_groupcv']:.4f}")
gate.append(f"Gap médio treino-validação: {best['mean_gap']:.4f}")

gate.append("\nRecall por classe:")
for c in classes:
    gate.append(f"- {c}: {best[f'recall_{c}']:.4f}")

issues = []

if best["min_recall_groupcv"] < 0.70:
    issues.append("Há classe com recall abaixo de 70% na validação por rodada.")

if best["f1_macro_groupcv"] < 0.70:
    issues.append("F1 macro abaixo de 70%.")

if best["mean_gap"] > 0.20:
    issues.append("Gap médio treino-validação acima de 20%. Possível overfitting.")

gate.append("\nProblemas:")
if issues:
    for i in issues:
        gate.append(f"- {i}")
    gate.append("\nSTATUS: AINDA NÃO LIBERADO PARA RESULTADO FINAL.")
    gate.append("Ação: gerar mais variações das classes com menor recall e treinar novamente.")
else:
    gate.append("- Nenhum problema crítico.")
    gate.append("\nSTATUS: LIBERADO PARA TESTE CEGO NOVO.")

gate_text = "\n".join(gate)
print("\n" + gate_text)

(OUT_DIR / "gate_modelo_v2_groupcv.txt").write_text(gate_text, encoding="utf-8")

print("\n[OK] Arquivos gerados:")
for f in sorted(OUT_DIR.glob("*")):
    print(" -", f)
