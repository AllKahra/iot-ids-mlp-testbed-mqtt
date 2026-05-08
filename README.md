# IDS para Tráfego IoT Simulado com Docker, CICFlowMeter e Machine Learning

Este projeto implementa um testbed IoT em Docker para geração de tráfego benigno e malicioso, captura de PCAPs, extração de features com CICFlowMeter e avaliação de modelos de Machine Learning para detecção de intrusão.

## Objetivo

Avaliar a identificação de tráfego malicioso em ambiente IoT simulado em três níveis: detecção binária, classificação multiclasse por subtipo e classificação por macroclasses comportamentais.

## Classes avaliadas

- benign
- scan
- bruteforce
- c2_beacon
- dos_flood
- slow_dos
- mqtt_abuse

## Macroclasses comportamentais

| Macroclasse | Classes agrupadas |
|---|---|
| benign | benign |
| recon_scan | scan |
| auth_control_repetition | bruteforce, c2_beacon |
| availability_abuse | dos_flood, slow_dos, mqtt_abuse |

## Pipeline experimental

Docker testbed → geração de tráfego → captura PCAP → CICFlowMeter → CSV rotulado → pré-processamento → treino do modelo → teste cego Blind17 → avaliações.

## Artefatos finais

Os artefatos organizados para relatório estão em final_artifacts/.
