# Limitações do Experimento

Os resultados obtidos devem ser interpretados dentro do escopo experimental do projeto.

## 1. Ambiente controlado

O tráfego foi gerado em um testbed IoT simulado em Docker. Portanto, os resultados não representam automaticamente todos os cenários IoT reais.

## 2. Dataset limitado

As classes foram avaliadas com capturas próprias e controladas. Apesar da existência de teste cego, o volume e a diversidade dos dados ainda são limitados em comparação com ambientes reais de produção.

## 3. Generalização

A generalização foi avaliada dentro do próprio ambiente experimental, por meio de rodadas cegas e separação por capturas. Isso reduz memorização, mas não equivale a validação em redes IoT externas.

## 4. Classificação fina entre subtipos

O modelo apresentou desempenho forte na detecção binária e na classificação por macroclasses. Porém, a classificação detalhada por subtipo apresentou confusões entre ataques com comportamento semelhante, especialmente entre classes relacionadas a abuso de disponibilidade e repetição.

## 5. Modelo adotado

A proposta inicial considerou MLP, mas o resultado final consolidado utilizou Random Forest regularizado por apresentar melhor adequação ao conjunto tabular extraído pelo CICFlowMeter no escopo do projeto.

## Conclusão das limitações

O projeto deve ser interpretado como uma avaliação experimental de IDS em testbed IoT simulado, e não como uma solução universal pronta para implantação em ambientes reais.
