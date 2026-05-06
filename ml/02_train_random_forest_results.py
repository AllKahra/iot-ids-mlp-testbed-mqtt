from pathlib import Path
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import joblib

from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import VarianceThreshold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

DATA_DIR = Path("cicflowmeter/processed_csv")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_FILE = DATA_DIR / "dataset_train.csv"
TEST_FILE = DATA_DIR / "dataset_test.csv"
FEATURES_NO_PORTS = DATA_DIR / "feature_columns_no_ports.txt"
FEATURES_WITH_PORTS = DATA_DIR / "feature_columns_with_ports.txt"

def read_features(path):
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]

def build_rf():
    return Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("variance", VarianceThreshold(threshold=0.0)),
        ("rf", RandomForestClassifier(
            n_estimators=300,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1
        ))
    ])

def evaluate_model(model, X_train, y_train, X_test, y_test, labels=None):
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)

    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)

    p_w, r_w, f1_w, _ = precision_recall_fscore_support(
        y_test, y_pred_test, average="weighted", zero_division=0
    )

    p_m, r_m, f1_m, _ = precision_recall_fscore_support(
        y_test, y_pred_test, average="macro", zero_division=0
    )

    report_text = classification_report(y_test, y_pred_test, labels=labels, zero_division=0)
    report_dict = classification_report(y_test, y_pred_test, labels=labels, zero_division=0, output_dict=True)

    return {
        "y_pred_train": y_pred_train,
        "y_pred_test": y_pred_test,
        "accuracy_train": train_acc,
        "accuracy_test": test_acc,
        "precision_weighted": p_w,
        "recall_weighted": r_w,
        "f1_weighted": f1_w,
        "precision_macro": p_m,
        "recall_macro": r_m,
        "f1_macro": f1_m,
        "gap_train_test": train_acc - test_acc,
        "report_text": report_text,
        "report_dict": report_dict,
    }

print("========== TREINAMENTO RANDOM FOREST — DIA 3 ==========")

train = pd.read_csv(TRAIN_FILE, low_memory=False)
test = pd.read_csv(TEST_FILE, low_memory=False)

features_no_ports = read_features(FEATURES_NO_PORTS)
features_with_ports = read_features(FEATURES_WITH_PORTS)

print(f"[INFO] Features sem portas: {len(features_no_ports)}")
print(f"[INFO] Features com portas: {len(features_with_ports)}")

# =========================================================
# 1. MULTICLASSE OFICIAL SEM PORTAS
# =========================================================

print("\n========== RESULTADO OFICIAL 1 — RF MULTICLASSE SEM PORTAS ==========")

X_train = train[features_no_ports]
y_train = train["Attack_Type"]

X_test = test[features_no_ports]
y_test = test["Attack_Type"]

class_labels = sorted(y_test.unique())

rf_multi = build_rf()
rf_multi.fit(X_train, y_train)

res_multi = evaluate_model(rf_multi, X_train, y_train, X_test, y_test, labels=class_labels)

metrics_multi = []
metrics_multi.append("========== RESULTADO OFICIAL 1 — RANDOM FOREST MULTICLASSE SEM PORTAS ==========")
metrics_multi.append(f"Features: {len(features_no_ports)}")
metrics_multi.append(f"Accuracy treino: {res_multi['accuracy_train']:.4f}")
metrics_multi.append(f"Accuracy teste:  {res_multi['accuracy_test']:.4f}")
metrics_multi.append(f"Precision weighted: {res_multi['precision_weighted']:.4f}")
metrics_multi.append(f"Recall weighted:    {res_multi['recall_weighted']:.4f}")
metrics_multi.append(f"F1 weighted:        {res_multi['f1_weighted']:.4f}")
metrics_multi.append(f"Precision macro:    {res_multi['precision_macro']:.4f}")
metrics_multi.append(f"Recall macro:       {res_multi['recall_macro']:.4f}")
metrics_multi.append(f"F1 macro:           {res_multi['f1_macro']:.4f}")
metrics_multi.append(f"Gap treino-teste:   {res_multi['gap_train_test']:.4f}")
metrics_multi.append("\n========== CLASSIFICATION REPORT ==========")
metrics_multi.append(res_multi["report_text"])

metrics_multi_text = "\n".join(metrics_multi)
print(metrics_multi_text)

(RESULTS_DIR / "metrics_rf_multiclass_no_ports.txt").write_text(metrics_multi_text, encoding="utf-8")
(RESULTS_DIR / "classification_report_rf_multiclass_no_ports.txt").write_text(res_multi["report_text"], encoding="utf-8")

# Matriz de confusão multiclasse
cm = confusion_matrix(y_test, res_multi["y_pred_test"], labels=class_labels)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=class_labels)
disp.plot(xticks_rotation=45, values_format="d")
plt.title("Matriz de Confusão — RF Multiclasse Sem Portas")
plt.tight_layout()
plt.savefig(RESULTS_DIR / "confusion_matrix_rf_multiclass_no_ports.png", dpi=300)
plt.close()

pd.DataFrame({
    "capture_id": test["capture_id"].values,
    "y_true": y_test.values,
    "y_pred": res_multi["y_pred_test"]
}).to_csv(RESULTS_DIR / "predictions_rf_multiclass_no_ports.csv", index=False)

joblib.dump(rf_multi, RESULTS_DIR / "model_rf_multiclass_no_ports.pkl")

# Feature importance
variance_step = rf_multi.named_steps["variance"]
rf_step = rf_multi.named_steps["rf"]

selected_features = [
    feat for feat, keep in zip(features_no_ports, variance_step.get_support())
    if keep
]

importance_df = pd.DataFrame({
    "feature": selected_features,
    "importance": rf_step.feature_importances_
}).sort_values("importance", ascending=False)

importance_df.to_csv(RESULTS_DIR / "feature_importance_rf_multiclass_no_ports.csv", index=False)

top_n = min(20, len(importance_df))
plt.figure(figsize=(10, 7))
plt.barh(
    importance_df.head(top_n)["feature"][::-1],
    importance_df.head(top_n)["importance"][::-1]
)
plt.title("Top atributos — RF Multiclasse Sem Portas")
plt.xlabel("Importância")
plt.ylabel("Atributo")
plt.tight_layout()
plt.savefig(RESULTS_DIR / "feature_importance_rf_multiclass_no_ports.png", dpi=300)
plt.close()

# =========================================================
# 2. BINÁRIO OFICIAL SEM PORTAS
# =========================================================

print("\n========== RESULTADO OFICIAL 2 — RF BINÁRIO SEM PORTAS ==========")

X_train_b = train[features_no_ports]
y_train_b = train["Label"].astype(int)

X_test_b = test[features_no_ports]
y_test_b = test["Label"].astype(int)

rf_bin = build_rf()
rf_bin.fit(X_train_b, y_train_b)

res_bin = evaluate_model(rf_bin, X_train_b, y_train_b, X_test_b, y_test_b, labels=[0, 1])

report_bin_text = classification_report(
    y_test_b,
    res_bin["y_pred_test"],
    labels=[0, 1],
    target_names=["benign", "malicious"],
    zero_division=0
)

metrics_bin = []
metrics_bin.append("========== RESULTADO OFICIAL 2 — RANDOM FOREST BINÁRIO SEM PORTAS ==========")
metrics_bin.append(f"Features: {len(features_no_ports)}")
metrics_bin.append(f"Accuracy treino: {res_bin['accuracy_train']:.4f}")
metrics_bin.append(f"Accuracy teste:  {res_bin['accuracy_test']:.4f}")
metrics_bin.append(f"Precision weighted: {res_bin['precision_weighted']:.4f}")
metrics_bin.append(f"Recall weighted:    {res_bin['recall_weighted']:.4f}")
metrics_bin.append(f"F1 weighted:        {res_bin['f1_weighted']:.4f}")
metrics_bin.append(f"F1 macro:           {res_bin['f1_macro']:.4f}")
metrics_bin.append(f"Gap treino-teste:   {res_bin['gap_train_test']:.4f}")
metrics_bin.append("\n========== CLASSIFICATION REPORT ==========")
metrics_bin.append(report_bin_text)

metrics_bin_text = "\n".join(metrics_bin)
print(metrics_bin_text)

(RESULTS_DIR / "metrics_rf_binary_no_ports.txt").write_text(metrics_bin_text, encoding="utf-8")
(RESULTS_DIR / "classification_report_rf_binary_no_ports.txt").write_text(report_bin_text, encoding="utf-8")

cm_bin = confusion_matrix(y_test_b, res_bin["y_pred_test"], labels=[0, 1])
disp_bin = ConfusionMatrixDisplay(confusion_matrix=cm_bin, display_labels=["benign", "malicious"])
disp_bin.plot(values_format="d")
plt.title("Matriz de Confusão — RF Binário Sem Portas")
plt.tight_layout()
plt.savefig(RESULTS_DIR / "confusion_matrix_rf_binary_no_ports.png", dpi=300)
plt.close()

pd.DataFrame({
    "capture_id": test["capture_id"].values,
    "attack_type": test["Attack_Type"].values,
    "y_true": y_test_b.values,
    "y_pred": res_bin["y_pred_test"]
}).to_csv(RESULTS_DIR / "predictions_rf_binary_no_ports.csv", index=False)

joblib.dump(rf_bin, RESULTS_DIR / "model_rf_binary_no_ports.pkl")

# =========================================================
# 3. COMPARAÇÃO COM PORTAS VS SEM PORTAS
# =========================================================

print("\n========== COMPARAÇÃO — RF MULTICLASSE COM PORTAS VS SEM PORTAS ==========")

feature_sets = {
    "sem_portas": features_no_ports,
    "com_portas": features_with_ports
}

rows_ports = []

for name, features in feature_sets.items():
    model = build_rf()
    Xtr = train[features]
    Xte = test[features]
    ytr = train["Attack_Type"]
    yte = test["Attack_Type"]

    model.fit(Xtr, ytr)
    res = evaluate_model(model, Xtr, ytr, Xte, yte, labels=class_labels)

    rows_ports.append({
        "experimento": name,
        "features": len(features),
        "accuracy_train": res["accuracy_train"],
        "accuracy_test": res["accuracy_test"],
        "f1_weighted": res["f1_weighted"],
        "f1_macro": res["f1_macro"],
        "gap_train_test": res["gap_train_test"]
    })

comparison_ports = pd.DataFrame(rows_ports)
comparison_ports.to_csv(RESULTS_DIR / "comparison_ports_rf_multiclass.csv", index=False)

no_ports = comparison_ports[comparison_ports["experimento"] == "sem_portas"].iloc[0]
with_ports = comparison_ports[comparison_ports["experimento"] == "com_portas"].iloc[0]
diff_ports = with_ports["f1_weighted"] - no_ports["f1_weighted"]

ports_text = []
ports_text.append("========== COMPARAÇÃO RF MULTICLASSE: SEM PORTAS VS COM PORTAS ==========")
ports_text.append(comparison_ports.to_string(index=False))
ports_text.append("")
ports_text.append(f"Diferença F1 weighted com portas - sem portas: {diff_ports:.4f}")

if diff_ports > 0.10:
    ports_text.append("Interpretação: portas aumentaram muito o desempenho. Risco de atalho artificial.")
elif diff_ports > 0.03:
    ports_text.append("Interpretação: portas melhoraram moderadamente. Discutir influência.")
else:
    ports_text.append("Interpretação: portas não alteraram muito o desempenho. Isso fortalece a versão sem portas.")

ports_text = "\n".join(ports_text)
print(ports_text)
(RESULTS_DIR / "comparison_ports_rf_multiclass.txt").write_text(ports_text, encoding="utf-8")

plt.figure(figsize=(8, 5))
plt.bar(comparison_ports["experimento"], comparison_ports["f1_weighted"])
plt.title("RF Multiclasse — Sem Portas vs Com Portas")
plt.xlabel("Experimento")
plt.ylabel("F1-score weighted")
plt.tight_layout()
plt.savefig(RESULTS_DIR / "comparison_ports_rf_multiclass.png", dpi=300)
plt.close()

# =========================================================
# 4. TODOS OS ATRIBUTOS VS TOP 10
# =========================================================

print("\n========== COMPARAÇÃO — TODOS OS ATRIBUTOS VS TOP 10 ==========")

top_10_features = importance_df.head(10)["feature"].tolist()

feature_sets_top = {
    "todos_atributos_seguros": features_no_ports,
    "top_10_atributos": top_10_features
}

rows_top = []

for name, features in feature_sets_top.items():
    model = build_rf()
    Xtr = train[features]
    Xte = test[features]
    ytr = train["Attack_Type"]
    yte = test["Attack_Type"]

    model.fit(Xtr, ytr)
    res = evaluate_model(model, Xtr, ytr, Xte, yte, labels=class_labels)

    rows_top.append({
        "experimento": name,
        "features": len(features),
        "accuracy_train": res["accuracy_train"],
        "accuracy_test": res["accuracy_test"],
        "f1_weighted": res["f1_weighted"],
        "f1_macro": res["f1_macro"],
        "gap_train_test": res["gap_train_test"]
    })

comparison_top = pd.DataFrame(rows_top)
comparison_top.to_csv(RESULTS_DIR / "comparison_top_features_rf.csv", index=False)

full = comparison_top[comparison_top["experimento"] == "todos_atributos_seguros"].iloc[0]
top = comparison_top[comparison_top["experimento"] == "top_10_atributos"].iloc[0]
diff_top = full["f1_weighted"] - top["f1_weighted"]

top_text = []
top_text.append("========== COMPARAÇÃO RF: TODOS OS ATRIBUTOS VS TOP 10 ==========")
top_text.append(comparison_top.to_string(index=False))
top_text.append("")
top_text.append("Top 10 atributos:")
for f in top_10_features:
    top_text.append(f"- {f}")
top_text.append("")
top_text.append(f"Diferença F1 weighted todos - Top 10: {diff_top:.4f}")

if diff_top <= 0.03:
    top_text.append("Interpretação: Top 10 manteve desempenho próximo. Poucos atributos concentram poder discriminativo.")
elif diff_top <= 0.10:
    top_text.append("Interpretação: Top 10 perdeu desempenho moderado. Pode ser útil para redução, mas conjunto completo é mais forte.")
else:
    top_text.append("Interpretação: Top 10 perdeu muito desempenho. Conjunto completo representa melhor as classes.")

top_text = "\n".join(top_text)
print(top_text)
(RESULTS_DIR / "comparison_top_features_rf.txt").write_text(top_text, encoding="utf-8")

plt.figure(figsize=(8, 5))
plt.bar(comparison_top["experimento"], comparison_top["f1_weighted"])
plt.title("RF — Todos os Atributos vs Top 10")
plt.xlabel("Experimento")
plt.ylabel("F1-score weighted")
plt.xticks(rotation=15, ha="right")
plt.tight_layout()
plt.savefig(RESULTS_DIR / "comparison_top_features_rf.png", dpi=300)
plt.close()

# =========================================================
# 5. GATE DE RESULTADO APRESENTÁVEL
# =========================================================

print("\n========== GATE DE RESULTADO APRESENTÁVEL ==========")

report_dict = res_multi["report_dict"]

per_class_recalls = {}
zero_recall_classes = []

for cls in class_labels:
    recall = report_dict.get(cls, {}).get("recall", 0.0)
    per_class_recalls[cls] = recall
    if recall == 0.0:
        zero_recall_classes.append(cls)

gate = []
gate.append("========== GATE DE RESULTADO APRESENTÁVEL ==========")
gate.append(f"F1 weighted multiclasse: {res_multi['f1_weighted']:.4f}")
gate.append(f"F1 macro multiclasse:    {res_multi['f1_macro']:.4f}")
gate.append(f"Gap treino-teste:        {res_multi['gap_train_test']:.4f}")

gate.append("\nRecall por classe:")
for cls, rec in per_class_recalls.items():
    gate.append(f"- {cls}: {rec:.4f}")

issues = []

if res_multi["f1_weighted"] < 0.75:
    issues.append("F1 weighted multiclasse abaixo de 0.75.")

if res_multi["f1_macro"] < 0.70:
    issues.append("F1 macro multiclasse abaixo de 0.70.")

if res_multi["gap_train_test"] > 0.20:
    issues.append("Gap treino-teste acima de 0.20. Possível overfitting.")

if zero_recall_classes:
    issues.append("Há classe com recall 0.00: " + ", ".join(zero_recall_classes))

gate.append("\nProblemas:")
if issues:
    for item in issues:
        gate.append(f"- {item}")
    gate.append("\nSTATUS: AINDA NÃO ESTÁ IDEAL PARA RESULTADO FINAL.")
    gate.append("Ação recomendada: corrigir dataset das classes problemáticas e reexecutar o pipeline.")
else:
    gate.append("- Nenhum problema crítico.")
    gate.append("\nSTATUS: RESULTADO APRESENTÁVEL.")

gate_text = "\n".join(gate)
print(gate_text)
(RESULTS_DIR / "quality_gate_results.txt").write_text(gate_text, encoding="utf-8")

print("\n[OK] Treinamento e avaliação finalizados.")
