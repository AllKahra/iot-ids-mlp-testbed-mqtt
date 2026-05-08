from pathlib import Path
import pandas as pd
import joblib
from sklearn.metrics import classification_report, accuracy_score, f1_score

OUT = Path("orange/tabelas_resultados")
OUT.mkdir(parents=True, exist_ok=True)

pred_path = Path("results/blind17_v7/predictions_blind17_modelo_v7.csv")
if not pred_path.exists():
    pred_path = Path("results/blind17_v7/predictions_blind_v3.csv")

if not pred_path.exists():
    raise FileNotFoundError("Não encontrei predictions_blind17_modelo_v7.csv nem predictions_blind_v3.csv")

pred = pd.read_csv(pred_path)

true_col = "Attack_Type"
pred_col = "prediction"

macro_map = {
    "benign": "benign",
    "scan": "recon_scan",
    "bruteforce": "auth_control_repetition",
    "c2_beacon": "auth_control_repetition",
    "dos_flood": "availability_abuse",
    "slow_dos": "availability_abuse",
    "mqtt_abuse": "availability_abuse",
}

# ==========================================================
# 1. Tabela geral de resultados
# ==========================================================

pred["true_binary"] = pred[true_col].apply(lambda x: "benign" if x == "benign" else "malicious")
pred["pred_binary"] = pred[pred_col].apply(lambda x: "benign" if x == "benign" else "malicious")

pred["true_macro"] = pred[true_col].map(macro_map)
pred["pred_macro"] = pred[pred_col].map(macro_map)

mal = pred[pred[true_col] != "benign"].copy()

resultados = [
    {
        "Experimento": "V7 GroupCV",
        "Tipo": "Validação por capture_id",
        "Accuracy": 0.7571,
        "F1_macro": 0.7837,
        "F1_weighted": 0.7615,
        "Menor_recall": 0.6306,
        "Interpretacao": "Modelo V7 apresentou bom desempenho interno em validação por grupos."
    },
    {
        "Experimento": "Blind17 multiclasse",
        "Tipo": "Teste cego por subtipo",
        "Accuracy": accuracy_score(pred[true_col], pred[pred_col]),
        "F1_macro": f1_score(pred[true_col], pred[pred_col], average="macro", zero_division=0),
        "F1_weighted": f1_score(pred[true_col], pred[pred_col], average="weighted", zero_division=0),
        "Menor_recall": None,
        "Interpretacao": "Classificação detalhada aceitável, mas com confusão entre subtipos maliciosos."
    },
    {
        "Experimento": "Blind17 binário",
        "Tipo": "Benign x malicious",
        "Accuracy": accuracy_score(pred["true_binary"], pred["pred_binary"]),
        "F1_macro": f1_score(pred["true_binary"], pred["pred_binary"], average="macro", zero_division=0),
        "F1_weighted": f1_score(pred["true_binary"], pred["pred_binary"], average="weighted", zero_division=0),
        "Menor_recall": None,
        "Interpretacao": "IDS binário excelente; nenhum tráfego malicioso foi classificado como benigno."
    },
    {
        "Experimento": "Blind17 malicious-only",
        "Tipo": "Somente classes maliciosas",
        "Accuracy": accuracy_score(mal[true_col], mal[pred_col]),
        "F1_macro": f1_score(mal[true_col], mal[pred_col], average="macro", zero_division=0),
        "F1_weighted": f1_score(mal[true_col], mal[pred_col], average="weighted", zero_division=0),
        "Menor_recall": None,
        "Interpretacao": "Avaliação mostra limitação na diferenciação fina entre ataques semelhantes."
    },
    {
        "Experimento": "Blind17 macroclasses por remapeamento",
        "Tipo": "Famílias comportamentais",
        "Accuracy": accuracy_score(pred["true_macro"], pred["pred_macro"]),
        "F1_macro": f1_score(pred["true_macro"], pred["pred_macro"], average="macro", zero_division=0),
        "F1_weighted": f1_score(pred["true_macro"], pred["pred_macro"], average="weighted", zero_division=0),
        "Menor_recall": None,
        "Interpretacao": "Agrupamento por família comportamental reduz grande parte dos erros."
    },
    {
        "Experimento": "Modelo macroclasses V7",
        "Tipo": "Modelo treinado diretamente em macroclasses",
        "Accuracy": 0.9582,
        "F1_macro": 0.9687,
        "F1_weighted": 0.9600,
        "Menor_recall": None,
        "Interpretacao": "Melhor solução para reduzir erros entre subtipos parecidos."
    },
]

pd.DataFrame(resultados).to_csv(OUT / "01_tabela_resultados_gerais.csv", index=False)

# ==========================================================
# 2. Tabela classe por classe — multiclasse
# ==========================================================

report_multi = classification_report(
    pred[true_col],
    pred[pred_col],
    output_dict=True,
    zero_division=0
)

rows = []
for classe, vals in report_multi.items():
    if classe in ["accuracy", "macro avg", "weighted avg"]:
        continue

    recall = vals["recall"]
    precision = vals["precision"]

    if recall >= 0.90 and precision >= 0.90:
        nivel = "Excelente"
    elif recall >= 0.70:
        nivel = "Bom"
    elif recall >= 0.60:
        nivel = "Aceitável mínimo"
    elif recall >= 0.40:
        nivel = "Baixo"
    else:
        nivel = "Crítico"

    rows.append({
        "Classe": classe,
        "Precision": round(precision, 4),
        "Recall": round(recall, 4),
        "F1_score": round(vals["f1-score"], 4),
        "Support": int(vals["support"]),
        "Nivel": nivel,
    })

pd.DataFrame(rows).to_csv(OUT / "02_tabela_por_classe_multiclasse_blind17.csv", index=False)

# ==========================================================
# 3. Matriz de confusão multiclasse
# ==========================================================

cm_multi = pd.crosstab(
    pred[true_col],
    pred[pred_col],
    rownames=["Real"],
    colnames=["Previsto"]
)
cm_multi.to_csv(OUT / "03_matriz_confusao_multiclasse_blind17.csv")

# ==========================================================
# 4. Erros agrupados multiclasse
# ==========================================================

wrong = pred[pred[true_col] != pred[pred_col]].copy()

errors = (
    wrong
    .groupby([true_col, pred_col])
    .size()
    .reset_index(name="Quantidade")
    .sort_values("Quantidade", ascending=False)
)

errors.to_csv(OUT / "04_erros_agrupados_multiclasse_blind17.csv", index=False)

# ==========================================================
# 5. Resumo de erros por classe
# ==========================================================

resumo = []

for classe, grupo in pred.groupby(true_col):
    total = len(grupo)
    acertos = (grupo[true_col] == grupo[pred_col]).sum()
    erros = total - acertos

    resumo.append({
        "Classe": classe,
        "Total": total,
        "Acertos": acertos,
        "Erros": erros,
        "Taxa_erro": round(erros / total, 4),
        "Recall": round(acertos / total, 4),
    })

pd.DataFrame(resumo).sort_values("Taxa_erro", ascending=False).to_csv(
    OUT / "05_resumo_erros_por_classe_blind17.csv",
    index=False
)

# ==========================================================
# 6. Avaliação binária
# ==========================================================

report_bin = classification_report(
    pred["true_binary"],
    pred["pred_binary"],
    output_dict=True,
    zero_division=0
)

rows = []
for classe, vals in report_bin.items():
    if classe in ["accuracy", "macro avg", "weighted avg"]:
        continue

    rows.append({
        "Classe": classe,
        "Precision": round(vals["precision"], 4),
        "Recall": round(vals["recall"], 4),
        "F1_score": round(vals["f1-score"], 4),
        "Support": int(vals["support"]),
    })

pd.DataFrame(rows).to_csv(OUT / "06_tabela_binaria_blind17.csv", index=False)

cm_bin = pd.crosstab(
    pred["true_binary"],
    pred["pred_binary"],
    rownames=["Real"],
    colnames=["Previsto"]
)
cm_bin.to_csv(OUT / "07_matriz_confusao_binaria_blind17.csv")

# ==========================================================
# 7. Avaliação malicious-only
# ==========================================================

report_mal = classification_report(
    mal[true_col],
    mal[pred_col],
    output_dict=True,
    zero_division=0
)

rows = []
for classe, vals in report_mal.items():
    if classe in ["accuracy", "macro avg", "weighted avg"]:
        continue

    rows.append({
        "Classe": classe,
        "Precision": round(vals["precision"], 4),
        "Recall": round(vals["recall"], 4),
        "F1_score": round(vals["f1-score"], 4),
        "Support": int(vals["support"]),
    })

pd.DataFrame(rows).to_csv(OUT / "08_tabela_malicious_only_blind17.csv", index=False)

cm_mal = pd.crosstab(
    mal[true_col],
    mal[pred_col],
    rownames=["Real"],
    colnames=["Previsto"]
)
cm_mal.to_csv(OUT / "09_matriz_confusao_malicious_only_blind17.csv")

# ==========================================================
# 8. Avaliação macroclasses
# ==========================================================

report_macro = classification_report(
    pred["true_macro"],
    pred["pred_macro"],
    output_dict=True,
    zero_division=0
)

rows = []
for classe, vals in report_macro.items():
    if classe in ["accuracy", "macro avg", "weighted avg"]:
        continue

    rows.append({
        "Macroclasse": classe,
        "Precision": round(vals["precision"], 4),
        "Recall": round(vals["recall"], 4),
        "F1_score": round(vals["f1-score"], 4),
        "Support": int(vals["support"]),
    })

pd.DataFrame(rows).to_csv(OUT / "10_tabela_macroclasses_blind17.csv", index=False)

cm_macro = pd.crosstab(
    pred["true_macro"],
    pred["pred_macro"],
    rownames=["Real"],
    colnames=["Previsto"]
)
cm_macro.to_csv(OUT / "11_matriz_confusao_macroclasses_blind17.csv")

# ==========================================================
# 9. Mapeamento das macroclasses
# ==========================================================

mapping_rows = [
    {"Classe_original": k, "Macroclasse": v}
    for k, v in macro_map.items()
]

pd.DataFrame(mapping_rows).to_csv(OUT / "12_mapeamento_macroclasses.csv", index=False)

# ==========================================================
# 10. Ranking de features do modelo V7
# ==========================================================

model_path = Path("results/modelo_v7_reforco/best_model_v7_reforco.pkl")
features_path = Path("cicflowmeter/processed_csv_v7/feature_columns_no_ports_v7.txt")

if model_path.exists() and features_path.exists():
    model = joblib.load(model_path)
    features = [
        line.strip()
        for line in features_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    clf = model.named_steps.get("clf", None)

    if clf is not None and hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_

        rank = pd.DataFrame({
            "Feature": features,
            "Importance": importances
        }).sort_values("Importance", ascending=False)

        rank["Rank"] = range(1, len(rank) + 1)

        rank = rank[["Rank", "Feature", "Importance"]]

        rank.to_csv(OUT / "13_rank_features_modelo_v7.csv", index=False)

# ==========================================================
# 11. Índice das tabelas
# ==========================================================

indice = [
    {
        "Arquivo": "01_tabela_resultados_gerais.csv",
        "Conteudo": "Resumo dos principais experimentos e métricas finais."
    },
    {
        "Arquivo": "02_tabela_por_classe_multiclasse_blind17.csv",
        "Conteudo": "Precision, recall, F1 e support por classe no Blind17 multiclasse."
    },
    {
        "Arquivo": "03_matriz_confusao_multiclasse_blind17.csv",
        "Conteudo": "Matriz de confusão da classificação detalhada por subtipo."
    },
    {
        "Arquivo": "04_erros_agrupados_multiclasse_blind17.csv",
        "Conteudo": "Lista dos principais erros agrupados por classe real e classe prevista."
    },
    {
        "Arquivo": "05_resumo_erros_por_classe_blind17.csv",
        "Conteudo": "Resumo de acertos, erros, taxa de erro e recall por classe."
    },
    {
        "Arquivo": "06_tabela_binaria_blind17.csv",
        "Conteudo": "Métricas da avaliação binária benign x malicious."
    },
    {
        "Arquivo": "07_matriz_confusao_binaria_blind17.csv",
        "Conteudo": "Matriz de confusão da avaliação binária."
    },
    {
        "Arquivo": "08_tabela_malicious_only_blind17.csv",
        "Conteudo": "Métricas considerando apenas classes maliciosas."
    },
    {
        "Arquivo": "09_matriz_confusao_malicious_only_blind17.csv",
        "Conteudo": "Matriz de confusão apenas entre ataques."
    },
    {
        "Arquivo": "10_tabela_macroclasses_blind17.csv",
        "Conteudo": "Métricas por macroclasse comportamental."
    },
    {
        "Arquivo": "11_matriz_confusao_macroclasses_blind17.csv",
        "Conteudo": "Matriz de confusão por macroclasses."
    },
    {
        "Arquivo": "12_mapeamento_macroclasses.csv",
        "Conteudo": "Mapeamento entre classes originais e macroclasses."
    },
    {
        "Arquivo": "13_rank_features_modelo_v7.csv",
        "Conteudo": "Ranking de importância das features no modelo V7."
    },
]

pd.DataFrame(indice).to_csv(OUT / "00_indice_tabelas.csv", index=False)

print("[OK] Tabelas exportadas para:", OUT)
for f in sorted(OUT.glob("*.csv")):
    print(" -", f)
