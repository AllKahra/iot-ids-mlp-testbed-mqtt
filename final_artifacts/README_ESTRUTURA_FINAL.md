# Estrutura Final dos Artefatos

Esta pasta organiza os artefatos finais do projeto de forma separada por finalidade.

## 00_DOCUMENTACAO_E_GUIA
Documentação de apoio, guias e arquivos de leitura.

## 01_OBJETO_DE_ESTUDO_AMBIENTE
Arquivos do testbed IoT em Docker, incluindo sensores, gateway, broker MQTT, fake C2 e botnet-controller.

## 02_DADOS_USADOS_NO_PROJETO
Dados utilizados no experimento, separados entre reforço de treino, teste cego final e datasets processados.

### 01_treino_reforco_v7
PCAPs e CSVs usados como reforço de treino para melhorar a diferenciação entre classes confundidas.

### 02_teste_cego_final_blind17
PCAPs e CSVs do Blind17, usado como teste cego final do modelo V7.

### 03_datasets_processados
Datasets finais e lista de features utilizadas.

## 03_MODELOS_TREINADOS
Modelos finais treinados, incluindo o modelo V7 e o modelo de macroclasses.

## 04_RESULTADO_OFICIAL_RELATORIO
Resultados finais usados no relatório: GroupCV, Blind17 multiclasse, binário, malicious-only, macroclasses, análise de erros e matrizes.

## 05_ORANGE_DEMONSTRACAO
Arquivos utilizados para demonstrar o fluxo no Orange.

## 06_SCRIPTS_REPRODUCAO
Scripts usados para captura, treino, avaliação e exportação de tabelas.

## 07_RELATORIO_E_PRINTS
Prints e materiais visuais utilizados no relatório.

## 99_MANIFESTOS_INTEGRIDADE
Manifesto dos arquivos e hashes SHA256 dos artefatos finais.
