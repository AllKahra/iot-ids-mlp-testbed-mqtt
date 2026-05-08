# Modelos de triagem V7

Dataset:
cicflowmeter/processed_csv_v7/dataset_v7_rodadas_01_16_reforcos.csv

Features:
cicflowmeter/processed_csv_v7/feature_columns_no_ports_v7.txt

Modelos gerados:
- binary_model_v7.pkl
- macroclass_model_v7.pkl
- specialist_auth_control_repetition_v7.pkl
- specialist_availability_abuse_v7.pkl

Mapeamento de macroclasses:
- benign -> benign
- scan -> recon_scan
- bruteforce + c2_beacon -> auth_control_repetition
- dos_flood + slow_dos + mqtt_abuse -> availability_abuse
