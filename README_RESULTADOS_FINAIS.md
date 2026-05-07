# Resultados finais do projeto IoT IDS

## Objetivo

Construir um testbed IoT em Docker para geração de tráfego benigno e malicioso, captura em PCAP, extração de features com CICFlowMeter e avaliação de modelos de Machine Learning para detecção e triagem de ataques.

## Classes trabalhadas

- benign
- scan
- bruteforce
- c2_beacon
- dos_flood
- slow_dos
- mqtt_abuse

## Resultado final adotado

A versão final utilizada foi a V7, com Random Forest regularizado e reforços direcionados para classes confundidas.

## Principais resultados

### Detecção binária

O modelo apresentou excelente desempenho na separação entre tráfego benigno e malicioso no Blind17.

### Multiclasse detalhado

A classificação multiclasse apresentou desempenho aceitável, mas ainda com confusão entre subtipos maliciosos semelhantes.

### Macroclasses

A avaliação por macroclasses apresentou desempenho elevado, mostrando que o modelo reconhece bem famílias comportamentais de ataque.

### Triagem final

Foi implementado um pipeline de triagem hierárquica com:

1. Detecção binária: benign x malicious.
2. Classificação por macroclasse.
3. Classificação detalhada.
4. Modelos especialistas.
5. Ranking final de hipóteses.

## Observação metodológica

O modelo deve ser interpretado como apoio à investigação e triagem IDS, não como decisão absoluta isolada.
