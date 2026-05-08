# Pacote de evidências — IDS IoT com triagem hierárquica

## 1. Objetivo da evidência

Este pacote reúne evidências para demonstrar dois pontos:

1. O modelo não apresentou falso negativo binário no conjunto rotulado Blind17.
2. A triagem final do incidente misto apontou uma hipótese coerente com o comportamento malicioso gerado no cenário, principalmente abuso de disponibilidade e slow DoS.

---

## 2. Prova de ausência de falso negativo binário

O conjunto Blind17 possui rótulos conhecidos, portanto permite verificar falso negativo de forma objetiva.

### Matriz binária Blind17

Previsto   benign  malicious
Real                        
benign         56          0
malicious       0        757

### Resultado

- Falsos negativos binários: 0
- Falsos positivos binários: 0

Interpretação:

Um falso negativo binário ocorreria se um fluxo real malicioso fosse classificado como benigno. Como a quantidade de falsos negativos binários foi 0, o modelo não deixou ataques passarem como tráfego benigno no Blind17.

---

## 3. Prova de integridade do PCAP do incidente final

Arquivo analisado:

- capture/pcaps/triage_incident_final/incident_final.pcap

Tamanho:

- 1320342 bytes

SHA256 calculado:

- 458978f9a02461d60baa56f0502d4ce11a4cc4fc22da35a845d4e2ddb29af2fa

Fluxos extraídos pelo CICFlowMeter:

- 876

---

## 4. Resultado da triagem do incidente final

Macroclasse dominante:

- availability_abuse
- Fluxos: 512
- Percentual: 0.5845

Hipótese final dominante após modelo focado:

- slow_dos
- Fluxos: 315
- Percentual: 0.3596

Ranking principal de ataque:

- Ataque mais provável: slow_dos
- Família: availability_abuse
- Score final: 0.5206

---

## 5. Interpretação técnica

A evidência do Blind17 prova que o modelo não apresentou falso negativo na tarefa binária de IDS, pois nenhum fluxo malicioso foi classificado como benigno.

A evidência do incidente final demonstra que o tráfego capturado foi interpretado como malicioso e que a família comportamental dominante foi associada a abuso de disponibilidade. A hipótese final mais forte foi slow_dos, coerente com o cenário misto que incluiu slow DoS, MQTT abuse, C2 discreto e tentativa de flood.

Como o incidente final é misto e não possui rótulo por fluxo, ele deve ser usado como demonstração de triagem investigativa, e não como prova absoluta de classificação por subtipo. A prova objetiva de falso negativo deve ser baseada no Blind17, que é rotulado.
