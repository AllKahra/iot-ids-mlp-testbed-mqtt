# Prova de precisão — Random Forest

## Objetivo

Validar se o desempenho perfeito da Rodada 3 é coerente com a metodologia e não depende de atalhos óbvios como portas, IPs, Timestamp, Flow ID ou capture_id.

## Separação treino/teste

- Treino: capturas 01, 02 e 03.
- Teste: capturas 04.
- O teste foi separado do treino por capture_id.

## Experimentos

| experimento                        | target      |   features |   accuracy_train |   accuracy_test |   precision_weighted |   recall_weighted |   f1_weighted |   precision_macro |   recall_macro |   f1_macro |   gap_train_test |
|:-----------------------------------|:------------|-----------:|-----------------:|----------------:|---------------------:|------------------:|--------------:|------------------:|---------------:|-----------:|-----------------:|
| RF multiclasse sem portas          | Attack_Type |         77 |         1        |        1        |             1        |          1        |      1        |          1        |       1        |   1        |       0          |
| RF binario sem portas              | Label       |         77 |         1        |        0.998239 |             0.998243 |          0.998239 |      0.998228 |          0.99906  |       0.986486 |   0.99268  |       0.00176056 |
| RF multiclasse com portas          | Attack_Type |         79 |         1        |        1        |             1        |          1        |      1        |          1        |       1        |   1        |       0          |
| RF multiclasse Top 10 atributos    | Attack_Type |         10 |         1        |        1        |             1        |          1        |      1        |          1        |       1        |   1        |       0          |
| RF multiclasse labels embaralhados | Attack_Type |         77 |         0.983092 |        0.56162  |             0.385038 |          0.56162  |      0.427052 |          0.259369 |       0.169891 |   0.155168 |       0.421472   |

## Top 10 atributos

- subflow_fwd_byts
- totlen_fwd_pkts
- pkt_len_mean
- fwd_pkt_len_mean
- fwd_seg_size_avg
- pkt_size_avg
- fwd_byts_b_avg
- fwd_pkt_len_std
- pkt_len_std
- pkt_len_var

## Interpretação

- Se o modelo sem portas mantém desempenho alto, não há evidência de dependência direta de portas.
- Se Top 10 mantém desempenho próximo ao conjunto completo, poucos atributos comportamentais concentram poder discriminativo.
- Se labels embaralhados derrubam desempenho, o pipeline não está acertando por vazamento estrutural óbvio.
- O resultado deve ser interpretado dentro do escopo do testbed simulado, não como IDS universal.