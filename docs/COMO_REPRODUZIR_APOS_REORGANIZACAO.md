# Como Reproduzir Após a Reorganização

Após a organização da raiz do repositório, a estrutura bruta do projeto foi movida para:

```text
legacy_project/
```

Por isso, scripts antigos devem ser executados a partir dessa pasta.

## Entrar no projeto bruto

```bash
cd legacy_project
```

## Subir ambiente Docker

```bash
docker compose up -d --build
```

## Executar scripts antigos

Exemplo:

```bash
python ml/17_train_v7_rf_final.py
```

ou:

```bash
./scripts/run_blind17_pcaps.sh
```

## Artefatos oficiais

Os artefatos oficiais usados no relatório não estão no `legacy_project/`. Eles estão em:

```text
final_artifacts/
```

Use `legacy_project/` para rastreabilidade e reprodução técnica. Use `final_artifacts/` para consulta final, relatório e apresentação.
