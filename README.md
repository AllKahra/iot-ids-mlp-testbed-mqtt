# IDS para Tráfego IoT Simulado com Docker, CICFlowMeter e Machine Learning

Este repositório contém um projeto de IDS para tráfego IoT simulado, com geração de tráfego benigno e malicioso, captura de PCAPs, extração de features com CICFlowMeter e avaliação com Machine Learning.

## Estrutura principal

| Pasta | Função |
|---|---|
| `final_artifacts/` | Pasta oficial de avaliação, relatório e evidências finais |
| `legacy_project/` | Histórico bruto/original do desenvolvimento, preservado para rastreabilidade |
| `docs/` | Documentação complementar |
| `archive/` | Arquivos compactados e materiais auxiliares antigos |

## Pasta oficial do relatório

A pasta principal para avaliação do projeto é:

```text
final_artifacts/
```

Ela contém os artefatos finais separados por finalidade: objeto de estudo, dados utilizados, treino/reforço, teste cego final, modelos treinados, resultados oficiais, arquivos do Orange, scripts de reprodução e evidências do relatório.

## Histórico bruto

A pasta `legacy_project/` preserva a estrutura original do desenvolvimento. Ela mantém scripts, PCAPs, CSVs, datasets intermediários, resultados antigos e arquivos de experimentação. Essa pasta não deve ser usada como fonte principal do relatório, mas sim como rastreabilidade técnica.

## Modelo final adotado

Embora a proposta tenha passado por diferentes hipóteses de modelagem, o resultado oficial do projeto foi consolidado com Machine Learning aplicado sobre features extraídas pelo CICFlowMeter. O modelo V7 com Random Forest regularizado foi adotado como referência final por apresentar melhor adequação ao conjunto tabular avaliado.

## Classes avaliadas

- `benign`
- `scan`
- `bruteforce`
- `c2_beacon`
- `dos_flood`
- `slow_dos`
- `mqtt_abuse`

## Macroclasses comportamentais

| Macroclasse | Classes agrupadas |
|---|---|
| `benign` | `benign` |
| `recon_scan` | `scan` |
| `auth_control_repetition` | `bruteforce`, `c2_beacon` |
| `availability_abuse` | `dos_flood`, `slow_dos`, `mqtt_abuse` |

## Interpretação final

O modelo V7 apresentou excelente desempenho na detecção binária `benign x malicious`, desempenho aceitável na classificação multiclasse por subtipo e desempenho elevado na classificação por macroclasses comportamentais.

A principal limitação observada está na separação fina entre subtipos maliciosos semelhantes.
