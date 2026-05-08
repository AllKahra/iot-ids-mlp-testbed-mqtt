# Avaliação cega — Rodada 05

## Regra metodológica

Os PCAPs da rodada 05 foram utilizados apenas como teste cego. O modelo não foi treinado novamente.

## Distribuição por classe

Attack_Type
benign         54
bruteforce     41
c2_beacon      40
dos_flood      84
mqtt_abuse    129
scan          150
slow_dos      139


## Resultados

                        experimento  accuracy  precision_weighted  recall_weighted  f1_weighted  precision_macro  recall_macro  f1_macro
RF multiclasse blind05 sem retreino  0.572998            0.660965         0.572998     0.571734         0.446360      0.457635  0.396121
    RF binario blind05 sem retreino  0.576138            0.929356         0.576138     0.663654         0.583333      0.768439  0.492188


## Interpretação

Se o desempenho se mantiver alto na rodada 05, isso reforça que o modelo generaliza para novas capturas dentro do testbed.
Se houver queda, a matriz de confusão deve ser usada para identificar quais classes precisam de mais variação.
Esse teste ainda é interno ao ambiente simulado, portanto não representa validação em rede IoT real.