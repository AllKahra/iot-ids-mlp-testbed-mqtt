# Triagem individual por PCAP — Blind17

## Resumo

| pcap_csv      | ataque_real   | macro_real              | resultado_binario   |   malicious_ratio | detectou_ataque_sem_falso_negativo   | macro_prevista          |   macro_pct | macro_correta   | ataque_top1   |   score_top1 | ataque_top2   |   score_top2 |   margem_top1_top2 | subtipo_correto_top1   | hipotese_focada_dominante   |   hipotese_focada_pct | precisa_analise_focada   | predito_final_pcap   |
|:--------------|:--------------|:------------------------|:--------------------|------------------:|:-------------------------------------|:------------------------|------------:|:----------------|:--------------|-------------:|:--------------|-------------:|-------------------:|:-----------------------|:----------------------------|----------------------:|:-------------------------|:---------------------|
| benign_17     | benign        | benign                  | benign              |                 0 | True                                 | benign                  |      1      | True            | benign        |       1      |               |       0      |             1      | True                   | benign                      |                1      | NAO                      | benign               |
| bruteforce_17 | bruteforce    | auth_control_repetition | malicious           |                 1 | True                                 | auth_control_repetition |      1      | True            | bruteforce    |       0.9361 | c2_beacon     |       0.1914 |             0.7447 | True                   | bruteforce                  |                1      | NAO                      | bruteforce           |
| c2_17         | c2_beacon     | auth_control_repetition | malicious           |                 1 | True                                 | auth_control_repetition |      0.9933 | True            | c2_beacon     |       0.6785 | bruteforce    |       0.4526 |             0.2259 | True                   | c2_beacon                   |                0.6107 | NAO                      | c2_beacon            |
| flood_17      | dos_flood     | availability_abuse      | malicious           |                 1 | True                                 | availability_abuse      |      0.5156 | True            | dos_flood     |       0.3132 | c2_beacon     |       0.2955 |             0.0177 | True                   | c2_beacon                   |                0.25   | SIM                      | dos_flood            |
| mqtt_abuse_17 | mqtt_abuse    | availability_abuse      | malicious           |                 1 | True                                 | availability_abuse      |      1      | True            | mqtt_abuse    |       0.7117 | dos_flood     |       0.3033 |             0.4084 | True                   | mqtt_abuse                  |                0.686  | NAO                      | mqtt_abuse           |
| scan_17       | scan          | recon_scan              | malicious           |                 1 | True                                 | recon_scan              |      1      | True            | scan          |       1      | bruteforce    |       0      |             1      | True                   | scan                        |                1      | NAO                      | scan                 |
| slow_dos_17   | slow_dos      | availability_abuse      | malicious           |                 1 | True                                 | availability_abuse      |      0.9957 | True            | slow_dos      |       0.8398 | dos_flood     |       0.2444 |             0.5954 | True                   | slow_dos                    |                0.8412 | NAO                      | slow_dos             |

## Matriz PCAP-level

| Real       |   benign |   bruteforce |   c2_beacon |   dos_flood |   mqtt_abuse |   scan |   slow_dos |
|:-----------|---------:|-------------:|------------:|------------:|-------------:|-------:|-----------:|
| benign     |        1 |            0 |           0 |           0 |            0 |      0 |          0 |
| bruteforce |        0 |            1 |           0 |           0 |            0 |      0 |          0 |
| c2_beacon  |        0 |            0 |           1 |           0 |            0 |      0 |          0 |
| dos_flood  |        0 |            0 |           0 |           1 |            0 |      0 |          0 |
| mqtt_abuse |        0 |            0 |           0 |           0 |            1 |      0 |          0 |
| scan       |        0 |            0 |           0 |           0 |            0 |      1 |          0 |
| slow_dos   |        0 |            0 |           0 |           0 |            0 |      0 |          1 |

## Falsos negativos binários

Não houve falso negativo binário em nível de PCAP: todos os PCAPs de ataque foram classificados como malicious.

## Casos que precisam análise focada

| pcap_csv   | ataque_real   | macro_real         | resultado_binario   |   malicious_ratio | detectou_ataque_sem_falso_negativo   | macro_prevista     |   macro_pct | macro_correta   | ataque_top1   |   score_top1 | ataque_top2   |   score_top2 |   margem_top1_top2 | subtipo_correto_top1   | hipotese_focada_dominante   |   hipotese_focada_pct | precisa_analise_focada   | predito_final_pcap   |
|:-----------|:--------------|:-------------------|:--------------------|------------------:|:-------------------------------------|:-------------------|------------:|:----------------|:--------------|-------------:|:--------------|-------------:|-------------------:|:-----------------------|:----------------------------|----------------------:|:-------------------------|:---------------------|
| flood_17   | dos_flood     | availability_abuse | malicious           |                 1 | True                                 | availability_abuse |      0.5156 | True            | dos_flood     |       0.3132 | c2_beacon     |       0.2955 |             0.0177 | True                   | c2_beacon                   |                  0.25 | SIM                      | dos_flood            |