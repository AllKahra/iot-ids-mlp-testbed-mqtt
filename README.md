# IDS para Tráfego IoT Simulado com Docker, CICFlowMeter e Machine Learning

Este repositório contém um projeto de IDS para tráfego IoT simulado, com geração de tráfego benigno e malicioso, captura de PCAPs, extração de features com CICFlowMeter e avaliação com Machine Learning.

## Estrutura do repositório

| Pasta | Conteúdo |
|---|---|
| `final_artifacts/` | Artefatos finais organizados para relatório e apresentação |
| `legacy_project/` | Estrutura bruta/original do projeto, preservada para rastreabilidade |
| `docs/` | Documentação complementar do projeto |
| `archive/` | Arquivos compactados e materiais auxiliares antigos |

## Resultado oficial

O resultado oficial do projeto está documentado em:

```text
final_artifacts/
```

Essa pasta separa:

- objeto de estudo;
- dados usados no projeto;
- dados de treino/reforço;
- teste cego final Blind17;
- modelos treinados;
- resultados oficiais;
- demonstração no Orange;
- scripts de reprodução;
- evidências do relatório.

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
