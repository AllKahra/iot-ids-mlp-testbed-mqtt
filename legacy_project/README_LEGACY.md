# Legacy Project

Esta pasta contém a estrutura bruta/original do projeto, preservada para rastreabilidade.

## Importante

Esta pasta não é a entrega final do relatório. A entrega oficial está em:

```text
../final_artifacts/
```

## Por que esta pasta existe?

Ela preserva:

- código original do testbed Docker;
- scripts de captura;
- scripts de treino e avaliação;
- PCAPs brutos;
- CSVs extraídos pelo CICFlowMeter;
- datasets intermediários;
- modelos antigos e finais;
- resultados experimentais;
- arquivos de Orange usados durante o desenvolvimento.

## Como executar scripts antigos

Entre nesta pasta antes de rodar comandos antigos:

```bash
cd legacy_project
```

Depois execute os scripts usando os caminhos originais, por exemplo:

```bash
python ml/17_train_v7_rf_final.py
```

## Organização interna

A estrutura interna foi preservada para evitar quebra de caminhos relativos usados pelos scripts.
