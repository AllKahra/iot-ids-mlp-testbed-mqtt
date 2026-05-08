# Resultado Oficial do Projeto

## Resultado oficial adotado

O resultado final adotado no relatório é o modelo V7 avaliado no Blind17.

Foram consideradas quatro leituras principais:

1. Validação GroupCV do modelo V7.
2. Teste cego Blind17 em classificação multiclasse por subtipo.
3. Teste cego Blind17 em classificação binária benign x malicious.
4. Teste cego Blind17 por macroclasses comportamentais.

## Uso de cada parte

| Pasta | Uso |
|---|---|
| 01_OBJETO_DE_ESTUDO_AMBIENTE | Ambiente IoT simulado usado como objeto de estudo |
| 02_DADOS_USADOS_NO_PROJETO/01_treino_reforco_v7 | Dados usados para reforço de treino |
| 02_DADOS_USADOS_NO_PROJETO/02_teste_cego_final_blind17 | Dados usados para teste cego final |
| 03_MODELOS_TREINADOS | Modelos finais treinados |
| 04_RESULTADO_OFICIAL_RELATORIO | Resultados oficiais usados no relatório |
| 05_ORANGE_DEMONSTRACAO | Demonstração visual no Orange |
| 06_SCRIPTS_REPRODUCAO | Scripts necessários para reprodução |
| 07_RELATORIO_E_PRINTS | Evidências visuais do relatório |

## Interpretação final

O modelo V7 apresentou excelente desempenho na detecção binária, desempenho aceitável na classificação multiclasse por subtipo e desempenho elevado na classificação por macroclasses comportamentais.

A principal limitação observada está na separação fina entre subtipos maliciosos semelhantes.
