# Reprodução no Legacy Project

Para reproduzir scripts antigos, execute os comandos a partir da pasta `legacy_project/`.

## Entrar na pasta

```bash
cd legacy_project
```

## Subir ambiente

```bash
docker compose up -d --build
```

## Capturar Blind17

```bash
./scripts/run_blind17_pcaps.sh
```

## Treinar modelo V7

```bash
python ml/17_train_v7_rf_final.py
```

## Avaliar Blind17

```bash
python ml/09_evaluate_blind_any_v2.py \\
  --csv-dir cicflowmeter/raw_csv_blind17 \\
  --labels capture/pcaps/blind17/pcap_labels_blind17.csv \\
  --out-dir results/blind17_v7 \\
  --model results/modelo_v7_reforco/best_model_v7_reforco.pkl \\
  --features cicflowmeter/processed_csv_v7/feature_columns_no_ports_v7.txt
```

## Treinar macroclasses

```bash
python ml/18_train_macroclass_v7.py
```

## Aviso

Os scripts foram preservados com os caminhos originais. Por isso, mover novamente as pastas internas pode quebrar a reprodução.
