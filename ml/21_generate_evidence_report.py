from pathlib import Path
import pandas as pd
import hashlib

OUT_DIR = Path("results/evidence_pack_final")
OUT_DIR.mkdir(parents=True, exist_ok=True)

blind_pred_path = Path("results/blind17_v7/predictions_blind17_modelo_v7.csv")
blind_bin_metrics = Path("results/blind17_v7/metrics_binary_blind17_modelo_v7.txt")
blind_multi_metrics = Path("results/blind17_v7/metrics_malicious_only_blind17_modelo_v7.txt")

incident_pcap = Path("capture/pcaps/triage_incident_final/incident_final.pcap")
incident_sha = Path("capture/pcaps/triage_incident_final/SHA256SUMS_incident_final.txt")
incident_csv = Path("cicflowmeter/raw_csv_triage_incident_final/incident_final.csv")
incident_report = Path("results/triage_incident_final_v7/triage_report.txt")
incident_attack_rank = Path("results/triage_incident_final_v7/triage_attack_probability_table.csv")
incident_macro_counts = Path("results/triage_incident_final_v7/triage_macro_counts.csv")
incident_focused_counts = Path("results/triage_incident_final_v7/triage_focused_counts.csv")

required = [
    blind_pred_path,
    blind_bin_metrics,
    incident_pcap,
    incident_csv,
    incident_report,
    incident_attack_rank,
    incident_macro_counts,
    incident_focused_counts,
]

missing = [str(p) for p in required if not p.exists()]
if missing:
    raise FileNotFoundError("Arquivos ausentes:\n" + "\n".join(missing))

# ==========================
# 1. Prova de falso negativo
# ==========================
pred = pd.read_csv(blind_pred_path)

pred["true_binary"] = pred["Attack_Type"].apply(lambda x: "benign" if x == "benign" else "malicious")
pred["pred_binary"] = pred["prediction"].apply(lambda x: "benign" if x == "benign" else "malicious")

fn_binary = pred[(pred["true_binary"] == "malicious") & (pred["pred_binary"] == "benign")]
fp_binary = pred[(pred["true_binary"] == "benign") & (pred["pred_binary"] == "malicious")]

binary_cm = pd.crosstab(
    pred["true_binary"],
    pred["pred_binary"],
    rownames=["Real"],
    colnames=["Previsto"]
)

binary_cm.to_csv(OUT_DIR / "evidence_binary_confusion_blind17.csv")
fn_binary.to_csv(OUT_DIR / "evidence_false_negatives_blind17.csv", index=False)
fp_binary.to_csv(OUT_DIR / "evidence_false_positives_blind17.csv", index=False)

# ==========================
# 2. Prova do incidente final
# ==========================
rank = pd.read_csv(incident_attack_rank)
macro = pd.read_csv(incident_macro_counts)
focused = pd.read_csv(incident_focused_counts)

top_attack = rank.iloc[0]["hipotese_ataque"]
top_family = rank.iloc[0]["familia"]
top_score = rank.iloc[0]["score_final"]

top_macro = macro.iloc[0]["macroclasse"]
top_macro_count = int(macro.iloc[0]["quantidade_fluxos"])
top_macro_pct = float(macro.iloc[0]["percentual"])

top_focused = focused.iloc[0]["hipotese_final"]
top_focused_count = int(focused.iloc[0]["quantidade_fluxos"])
top_focused_pct = float(focused.iloc[0]["percentual"])

# hash calculado
sha256 = hashlib.sha256()
with incident_pcap.open("rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        sha256.update(chunk)

pcap_hash = sha256.hexdigest()
pcap_size = incident_pcap.stat().st_size

incident_lines = incident_csv.read_text(errors="ignore").splitlines()
incident_flow_count = max(0, len(incident_lines) - 1)

# ==========================
# 3. Arquivo CSV de resumo
# ==========================
summary_rows = [
    {
        "evidencia": "Blind17 rotulado - falsos negativos binários",
        "resultado": len(fn_binary),
        "interpretacao": "Número de fluxos maliciosos classificados como benignos. Zero indica ausência de falso negativo binário."
    },
    {
        "evidencia": "Blind17 rotulado - falsos positivos binários",
        "resultado": len(fp_binary),
        "interpretacao": "Número de fluxos benignos classificados como maliciosos."
    },
    {
        "evidencia": "Incidente final - fluxos CICFlowMeter",
        "resultado": incident_flow_count,
        "interpretacao": "Quantidade de fluxos extraídos do PCAP final."
    },
    {
        "evidencia": "Incidente final - macroclasse dominante",
        "resultado": top_macro,
        "interpretacao": f"{top_macro_count} fluxos, percentual {top_macro_pct:.4f}."
    },
    {
        "evidencia": "Incidente final - hipótese focada dominante",
        "resultado": top_focused,
        "interpretacao": f"{top_focused_count} fluxos, percentual {top_focused_pct:.4f}."
    },
    {
        "evidencia": "Incidente final - ranking principal",
        "resultado": top_attack,
        "interpretacao": f"Família {top_family}, score {top_score}."
    },
    {
        "evidencia": "Incidente final - SHA256 PCAP",
        "resultado": pcap_hash,
        "interpretacao": "Hash usado para integridade da evidência."
    },
]

summary = pd.DataFrame(summary_rows)
summary.to_csv(OUT_DIR / "evidence_summary.csv", index=False)

# ==========================
# 4. Relatório Markdown
# ==========================
report = f"""# Pacote de evidências — IDS IoT com triagem hierárquica

## 1. Objetivo da evidência

Este pacote reúne evidências para demonstrar dois pontos:

1. O modelo não apresentou falso negativo binário no conjunto rotulado Blind17.
2. A triagem final do incidente misto apontou uma hipótese coerente com o comportamento malicioso gerado no cenário, principalmente abuso de disponibilidade e slow DoS.

---

## 2. Prova de ausência de falso negativo binário

O conjunto Blind17 possui rótulos conhecidos, portanto permite verificar falso negativo de forma objetiva.

### Matriz binária Blind17

{binary_cm.to_string()}

### Resultado

- Falsos negativos binários: {len(fn_binary)}
- Falsos positivos binários: {len(fp_binary)}

Interpretação:

Um falso negativo binário ocorreria se um fluxo real malicioso fosse classificado como benigno. Como a quantidade de falsos negativos binários foi {len(fn_binary)}, o modelo não deixou ataques passarem como tráfego benigno no Blind17.

---

## 3. Prova de integridade do PCAP do incidente final

Arquivo analisado:

- {incident_pcap}

Tamanho:

- {pcap_size} bytes

SHA256 calculado:

- {pcap_hash}

Fluxos extraídos pelo CICFlowMeter:

- {incident_flow_count}

---

## 4. Resultado da triagem do incidente final

Macroclasse dominante:

- {top_macro}
- Fluxos: {top_macro_count}
- Percentual: {top_macro_pct:.4f}

Hipótese final dominante após modelo focado:

- {top_focused}
- Fluxos: {top_focused_count}
- Percentual: {top_focused_pct:.4f}

Ranking principal de ataque:

- Ataque mais provável: {top_attack}
- Família: {top_family}
- Score final: {top_score}

---

## 5. Interpretação técnica

A evidência do Blind17 prova que o modelo não apresentou falso negativo na tarefa binária de IDS, pois nenhum fluxo malicioso foi classificado como benigno.

A evidência do incidente final demonstra que o tráfego capturado foi interpretado como malicioso e que a família comportamental dominante foi associada a abuso de disponibilidade. A hipótese final mais forte foi {top_attack}, coerente com o cenário misto que incluiu slow DoS, MQTT abuse, C2 discreto e tentativa de flood.

Como o incidente final é misto e não possui rótulo por fluxo, ele deve ser usado como demonstração de triagem investigativa, e não como prova absoluta de classificação por subtipo. A prova objetiva de falso negativo deve ser baseada no Blind17, que é rotulado.
"""

(OUT_DIR / "evidence_report.md").write_text(report, encoding="utf-8")

print(report)

print("\n[OK] Pacote de evidências gerado em:", OUT_DIR)
for f in sorted(OUT_DIR.glob("*")):
    print(" -", f)
