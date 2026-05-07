# Orange — Macroclasses combinado

Use este arquivo único no Orange:

- orange_macroclasses_combined_train_test.csv

Target:
- Macro_Class

Meta:
- Split
- Attack_Type
- Label
- capture_id

Como separar:
- Select Rows com Split = train para treino
- Select Rows com Split = test para teste

Macroclasses:
- benign
- recon_scan
- auth_control_repetition = bruteforce + c2_beacon
- availability_abuse = dos_flood + slow_dos + mqtt_abuse
