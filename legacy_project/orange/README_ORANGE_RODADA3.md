
# Orange — Rodada 3

Estes arquivos representam a Rodada 3, considerada o dataset final consolidado.

## Uso recomendado

Os resultados oficiais foram gerados em Python. O Orange deve ser usado como apoio visual.

## Multiclasse

Treino:
- rodada3_multiclass_train_no_ports.csv

Teste:
- rodada3_multiclass_test_no_ports.csv

Target:
- Attack_Type

Meta:
- capture_id
- Label

## Binário

Treino:
- rodada3_binary_train_no_ports.csv

Teste:
- rodada3_binary_test_no_ports.csv

Target:
- Binary_Class

Meta:
- capture_id
- Attack_Type
- Label

## Top 10 atributos

Treino:
- rodada3_multiclass_train_top10.csv

Teste:
- rodada3_multiclass_test_top10.csv

Target:
- Attack_Type

Meta:
- capture_id
- Label

## Regra metodológica

Não usar split aleatório como resultado principal.

Usar:
- treino = capturas 01, 02 e 03;
- teste = capturas 04.

A versão oficial não usa portas, IP, Timestamp, Flow ID ou capture_id como feature.
