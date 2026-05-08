# Rodadas e Experimentos

| Rodada | Papel no projeto | Uso final |
|---|---|---|
| Rodadas base | Construção inicial do dataset | Treino |
| Blind05 | Teste cego intermediário | Histórico |
| Blind09 | Teste cego intermediário | Histórico |
| Blind13 | Resultado cego positivo anterior | Comparação |
| Blind14 | Teste de estresse | Hard case |
| Blind15 | Teste de estresse | Hard case |
| Blind16 | Teste cego que revelou limitação | Incorporado ao V7 |
| Reforço V7 | Capturas direcionadas | Treino V7 |
| Blind17 | Teste cego final | Resultado final |

## Avaliações do Blind17

| Avaliação | Objetivo | Interpretação |
|---|---|---|
| Multiclasse | Identificar subtipo do ataque | Aceitável, com limitações |
| Binária | Separar benigno e malicioso | Excelente |
| Malicious-only | Diferenciar apenas ataques | Parcial |
| Macroclasses | Identificar família comportamental | Excelente |
