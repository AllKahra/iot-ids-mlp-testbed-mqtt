from pathlib import Path
import argparse
import numpy as np
import pandas as pd
import joblib

parser = argparse.ArgumentParser(description="Pipeline final de triagem IDS hierárquica.")
parser.add_argument("--csv", required=True, help="CSV do CICFlowMeter ou pasta com CSVs.")
parser.add_argument("--out-dir", default="results/triage_final", help="Pasta de saída.")
parser.add_argument("--malicious-threshold", type=float, default=0.50)
args = parser.parse_args()

CSV_INPUT = Path(args.csv)
OUT_DIR = Path(args.out_dir)
OUT_DIR.mkdir(parents=True, exist_ok=True)

FEATURES_FILE = Path("cicflowmeter/processed_csv_v7/feature_columns_no_ports_v7.txt")

DETAILED_MODEL = Path("results/modelo_v7_reforco/best_model_v7_reforco.pkl")
BINARY_MODEL = Path("results/triage_models_v7/binary_model_v7.pkl")
MACRO_MODEL = Path("results/triage_models_v7/macroclass_model_v7.pkl")
AUTH_MODEL = Path("results/triage_models_v7/specialist_auth_control_repetition_v7.pkl")
AVAIL_MODEL = Path("results/triage_models_v7/specialist_availability_abuse_v7.pkl")

macro_map = {
    "benign": "benign",
    "scan": "recon_scan",
    "bruteforce": "auth_control_repetition",
    "c2_beacon": "auth_control_repetition",
    "dos_flood": "availability_abuse",
    "slow_dos": "availability_abuse",
    "mqtt_abuse": "availability_abuse",
}

macro_to_candidates = {
    "benign": ["benign"],
    "recon_scan": ["scan"],
    "auth_control_repetition": ["bruteforce", "c2_beacon"],
    "availability_abuse": ["dos_flood", "slow_dos", "mqtt_abuse"],
}

def load_csvs(path: Path) -> pd.DataFrame:
    if path.is_dir():
        csvs = sorted(path.glob("*.csv"))
        if not csvs:
            raise FileNotFoundError(f"Nenhum CSV encontrado em {path}")
        dfs = []
        for p in csvs:
            tmp = pd.read_csv(p, low_memory=False)
            tmp["source_csv"] = p.name
            dfs.append(tmp)
        return pd.concat(dfs, ignore_index=True)

    if not path.exists():
        raise FileNotFoundError(f"CSV não encontrado: {path}")

    df = pd.read_csv(path, low_memory=False)
    df["source_csv"] = path.name
    return df

def proba_dataframe(model, X):
    classes = list(model.classes_) if hasattr(model, "classes_") else list(model.named_steps["clf"].classes_)
    probs = model.predict_proba(X)
    return pd.DataFrame(probs, columns=classes)

def top_n_from_row(row, n=3):
    items = sorted(row.items(), key=lambda x: x[1], reverse=True)
    return items[:n]

def safe_get(row, col, default=0.0):
    return float(row[col]) if col in row else default

print("========== TRIAGEM FINAL IDS ==========")

for p in [FEATURES_FILE, DETAILED_MODEL, BINARY_MODEL, MACRO_MODEL, AUTH_MODEL, AVAIL_MODEL]:
    if not p.exists():
        raise FileNotFoundError(f"Arquivo necessário não encontrado: {p}")

features = [
    line.strip()
    for line in FEATURES_FILE.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

data = load_csvs(CSV_INPUT)
data = data.replace([np.inf, -np.inf], np.nan)

features = [f for f in features if f in data.columns]

if not features:
    raise ValueError("Nenhuma feature válida encontrada no CSV de entrada.")

X = data[features].apply(pd.to_numeric, errors="coerce")

detailed_model = joblib.load(DETAILED_MODEL)
binary_model = joblib.load(BINARY_MODEL)
macro_model = joblib.load(MACRO_MODEL)
auth_model = joblib.load(AUTH_MODEL)
avail_model = joblib.load(AVAIL_MODEL)

# Predições
binary_proba = proba_dataframe(binary_model, X)
macro_proba = proba_dataframe(macro_model, X)
detailed_proba = proba_dataframe(detailed_model, X)

binary_pred = binary_model.predict(X)
macro_pred = macro_model.predict(X)
detailed_pred = detailed_model.predict(X)

flows = pd.DataFrame({
    "source_csv": data["source_csv"].values,
    "binary_prediction": binary_pred,
    "macro_prediction": macro_pred,
    "detailed_prediction": detailed_pred,
})

flows["p_benign"] = binary_proba.get("benign", 0.0)
flows["p_malicious"] = binary_proba.get("malicious", 0.0)

# top macro
macro_top1 = []
macro_top2 = []
for _, row in macro_proba.iterrows():
    tops = top_n_from_row(row.to_dict(), 2)
    macro_top1.append(f"{tops[0][0]}:{tops[0][1]:.4f}")
    macro_top2.append(f"{tops[1][0]}:{tops[1][1]:.4f}" if len(tops) > 1 else "")

flows["macro_top1"] = macro_top1
flows["macro_top2"] = macro_top2

# top detalhado
detail_top1 = []
detail_top2 = []
detail_top3 = []

for _, row in detailed_proba.iterrows():
    tops = top_n_from_row(row.to_dict(), 3)
    detail_top1.append(f"{tops[0][0]}:{tops[0][1]:.4f}")
    detail_top2.append(f"{tops[1][0]}:{tops[1][1]:.4f}" if len(tops) > 1 else "")
    detail_top3.append(f"{tops[2][0]}:{tops[2][1]:.4f}" if len(tops) > 2 else "")

flows["detail_top1"] = detail_top1
flows["detail_top2"] = detail_top2
flows["detail_top3"] = detail_top3

# Probabilidades especialistas
auth_mask = flows["macro_prediction"] == "auth_control_repetition"
avail_mask = flows["macro_prediction"] == "availability_abuse"

flows["focused_family"] = flows["macro_prediction"]
flows["focused_prediction"] = flows["detailed_prediction"]
flows["focused_top1_prob"] = np.nan
flows["focused_top2"] = ""

if auth_mask.any():
    auth_X = X.loc[auth_mask]
    auth_proba = proba_dataframe(auth_model, auth_X)
    auth_pred = auth_model.predict(auth_X)

    idxs = flows.index[auth_mask]
    flows.loc[idxs, "focused_prediction"] = auth_pred

    for idx, (_, row) in zip(idxs, auth_proba.iterrows()):
        tops = top_n_from_row(row.to_dict(), 2)
        flows.loc[idx, "focused_top1_prob"] = tops[0][1]
        flows.loc[idx, "focused_top2"] = f"{tops[1][0]}:{tops[1][1]:.4f}" if len(tops) > 1 else ""

if avail_mask.any():
    avail_X = X.loc[avail_mask]
    avail_proba = proba_dataframe(avail_model, avail_X)
    avail_pred = avail_model.predict(avail_X)

    idxs = flows.index[avail_mask]
    flows.loc[idxs, "focused_prediction"] = avail_pred

    for idx, (_, row) in zip(idxs, avail_proba.iterrows()):
        tops = top_n_from_row(row.to_dict(), 3)
        flows.loc[idx, "focused_top1_prob"] = tops[0][1]
        flows.loc[idx, "focused_top2"] = " | ".join([f"{k}:{v:.4f}" for k, v in tops[1:]])

# Para benign e scan, foco é direto
direct_mask = flows["macro_prediction"].isin(["benign", "recon_scan"])
flows.loc[direct_mask & (flows["macro_prediction"] == "benign"), "focused_prediction"] = "benign"
flows.loc[direct_mask & (flows["macro_prediction"] == "recon_scan"), "focused_prediction"] = "scan"
flows.loc[direct_mask, "focused_top1_prob"] = 1.0

# Salvar fluxo a fluxo
flows.to_csv(OUT_DIR / "triage_per_flow.csv", index=False)

# Resumo geral
total_flows = len(flows)
malicious_flows = flows[flows["binary_prediction"] == "malicious"].copy()
n_mal = len(malicious_flows)
mal_ratio = n_mal / total_flows if total_flows else 0

macro_counts = flows["macro_prediction"].value_counts().reset_index()
macro_counts.columns = ["macroclasse", "quantidade_fluxos"]
macro_counts["percentual"] = macro_counts["quantidade_fluxos"] / total_flows
macro_counts.to_csv(OUT_DIR / "triage_macro_counts.csv", index=False)

detail_counts = flows["detailed_prediction"].value_counts().reset_index()
detail_counts.columns = ["classe_detalhada", "quantidade_fluxos"]
detail_counts["percentual"] = detail_counts["quantidade_fluxos"] / total_flows
detail_counts.to_csv(OUT_DIR / "triage_detailed_counts.csv", index=False)

focused_counts = flows["focused_prediction"].value_counts().reset_index()
focused_counts.columns = ["hipotese_final", "quantidade_fluxos"]
focused_counts["percentual"] = focused_counts["quantidade_fluxos"] / total_flows
focused_counts.to_csv(OUT_DIR / "triage_focused_counts.csv", index=False)

# Tabela final de probabilidade por hipótese
attack_rows = []

if n_mal > 0:
    mal = malicious_flows.copy()

    for attack in ["scan", "bruteforce", "c2_beacon", "dos_flood", "mqtt_abuse", "slow_dos"]:
        vote_detail = (mal["detailed_prediction"] == attack).mean()
        vote_focused = (mal["focused_prediction"] == attack).mean()

        if attack in detailed_proba.columns:
            mean_detail_prob = detailed_proba.loc[mal.index, attack].mean()
        else:
            mean_detail_prob = 0.0

        macro = macro_map[attack]
        if macro in macro_proba.columns:
            mean_macro_prob = macro_proba.loc[mal.index, macro].mean()
        else:
            mean_macro_prob = 0.0

        score = (
            0.40 * vote_focused
            + 0.25 * vote_detail
            + 0.20 * mean_detail_prob
            + 0.15 * mean_macro_prob
        )

        attack_rows.append({
            "hipotese_ataque": attack,
            "familia": macro,
            "score_final": round(float(score), 4),
            "voto_modelo_focado": round(float(vote_focused), 4),
            "voto_modelo_detalhado": round(float(vote_detail), 4),
            "prob_media_modelo_detalhado": round(float(mean_detail_prob), 4),
            "prob_media_macroclasse": round(float(mean_macro_prob), 4),
        })

attack_table = pd.DataFrame(attack_rows).sort_values("score_final", ascending=False)
attack_table.to_csv(OUT_DIR / "triage_attack_probability_table.csv", index=False)

# Confiança geral
if total_flows == 0:
    verdict = "sem_dados"
elif mal_ratio < args.malicious_threshold:
    verdict = "provavelmente_benigno"
else:
    verdict = "malicioso_detectado"

top_attack = attack_table.iloc[0]["hipotese_ataque"] if not attack_table.empty else "nenhum"
top_family = attack_table.iloc[0]["familia"] if not attack_table.empty else "nenhuma"
top_score = attack_table.iloc[0]["score_final"] if not attack_table.empty else 0.0

report_lines = []
report_lines.append("========== RELATÓRIO FINAL DE TRIAGEM IDS ==========")
report_lines.append("")
report_lines.append(f"Entrada analisada: {CSV_INPUT}")
report_lines.append(f"Total de fluxos analisados: {total_flows}")
report_lines.append(f"Fluxos classificados como malicious: {n_mal}")
report_lines.append(f"Percentual malicious: {mal_ratio:.4f}")
report_lines.append(f"Veredito geral: {verdict}")
report_lines.append("")
report_lines.append("========== MACROCLASSES ==========")
report_lines.append(macro_counts.to_string(index=False))
report_lines.append("")
report_lines.append("========== CLASSES DETALHADAS — MODELO GERAL ==========")
report_lines.append(detail_counts.to_string(index=False))
report_lines.append("")
report_lines.append("========== HIPÓTESES FINAIS — APÓS MODELO FOCADO ==========")
report_lines.append(focused_counts.to_string(index=False))
report_lines.append("")
report_lines.append("========== RANKING DE ATAQUES PROVÁVEIS ==========")
report_lines.append(attack_table.to_string(index=False))
report_lines.append("")
report_lines.append("========== CONCLUSÃO AUTOMÁTICA ==========")

if verdict == "provavelmente_benigno":
    report_lines.append("O tráfego analisado foi classificado majoritariamente como benigno.")
else:
    report_lines.append(f"O tráfego analisado foi classificado como malicioso.")
    report_lines.append(f"A família comportamental mais provável é: {top_family}.")
    report_lines.append(f"O subtipo de ataque mais provável é: {top_attack}.")
    report_lines.append(f"Score final da hipótese principal: {top_score:.4f}.")
    report_lines.append("")
    report_lines.append("Observação:")
    report_lines.append("O score final combina votos do modelo detalhado, modelo focado e probabilidade da macroclasse.")
    report_lines.append("Em caso real, esse resultado deve ser tratado como triagem e apoio à investigação, não como decisão única.")

report = "\n".join(report_lines)

(OUT_DIR / "triage_report.txt").write_text(report, encoding="utf-8")

print(report)
print("\n[OK] Arquivos gerados em:", OUT_DIR)
for f in sorted(OUT_DIR.glob("*")):
    print(" -", f)
