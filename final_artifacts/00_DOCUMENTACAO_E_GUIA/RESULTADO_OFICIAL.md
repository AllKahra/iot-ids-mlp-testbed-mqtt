# Resultado Oficial do Projeto

## Pasta oficial

A pasta oficial de avaliação e relatório é:

```text
final_artifacts/
```

## Pasta histórica

A pasta `legacy_project/` contém o histórico bruto de desenvolvimento e foi preservada para rastreabilidade. Ela não deve ser usada como fonte principal do relatório.

## Resultado adotado

O resultado oficial adotado no relatório é o modelo V7 avaliado no Blind17.

Foram consideradas quatro leituras principais:

1. Validação GroupCV do modelo V7.
2. Teste cego Blind17 em classificação multiclasse por subtipo.
3. Teste cego Blind17 em classificação binária `benign x malicious`.
4. Teste cego Blind17 por macroclasses comportamentais.

## Interpretação final

O modelo V7 apresentou excelente desempenho na detecção binária, desempenho aceitável na classificação multiclasse por subtipo e desempenho elevado na classificação por macroclasses comportamentais.

A principal limitação observada está na separação fina entre subtipos maliciosos semelhantes.
