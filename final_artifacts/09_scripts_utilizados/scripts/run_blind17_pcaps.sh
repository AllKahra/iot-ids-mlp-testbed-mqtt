#!/usr/bin/env bash
set -u

OUT_DIR="capture/pcaps/blind17"
ROUND="17"

mkdir -p "$OUT_DIR"

echo
echo "========== BLIND17 — TESTE CEGO REAL DO MODELO V7 =========="

sudo -v || exit 1

echo
echo "========== SUBINDO CONTAINERS =========="
docker compose up -d --build iot-gateway mqtt-broker fake-c2 botnet-controller sensor01 sensor02 sensor-mqtt-normal

echo
echo "========== DETECTANDO BRIDGE DOCKER =========="
BRIDGE_ID=$(docker network inspect iot_ids_net -f '{{.Id}}' | cut -c1-12)
IFACE="br-$BRIDGE_ID"

echo "[INFO] Interface Docker detectada: $IFACE"
ip link show "$IFACE" || {
  echo "[ERRO] Interface $IFACE não encontrada."
  exit 1
}

sudo ip link set "$IFACE" up 2>/dev/null || true

echo
echo "========== LIMPANDO PROCESSOS ANTIGOS =========="
sudo pkill -2 tcpdump 2>/dev/null || true
true # pkill removido: container nao tem pkill

echo
echo "========== CRIANDO LABELS DO BLIND17 =========="
cat > "$OUT_DIR/pcap_labels_blind17.csv" <<LABELS
filename,label,attack_type
benign_17.pcap,0,benign
scan_17.pcap,1,scan
bruteforce_17.pcap,1,bruteforce
c2_17.pcap,1,c2_beacon
flood_17.pcap,1,dos_flood
mqtt_abuse_17.pcap,1,mqtt_abuse
slow_dos_17.pcap,1,slow_dos
LABELS

cat "$OUT_DIR/pcap_labels_blind17.csv"

start_tcpdump() {
  local name="$1"
  local outfile="$OUT_DIR/${name}_${ROUND}.pcap"
  local logfile="/tmp/tcpdump_${name}_${ROUND}.log"

  rm -f "$outfile" "$logfile"

  echo
  echo "[CAPTURA] Iniciando tcpdump: $outfile"

  sudo tcpdump -i "$IFACE" -w "$outfile" > "$logfile" 2>&1 &
  TCPDUMP_PID=$!

  sleep 3
}

stop_tcpdump() {
  local name="$1"
  local outfile="$OUT_DIR/${name}_${ROUND}.pcap"
  local logfile="/tmp/tcpdump_${name}_${ROUND}.log"

  echo "[CAPTURA] Parando tcpdump..."
  sudo kill -2 "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true

  sudo chown "$USER:$USER" "$outfile" 2>/dev/null || true

  echo
  echo "===== LOG TCPDUMP ${name}_${ROUND} ====="
  cat "$logfile" || true

  echo
  echo "===== ARQUIVO GERADO ====="
  ls -lh "$outfile" || true

  echo
  echo "===== PRIMEIROS PACOTES ====="
  sudo tcpdump -r "$outfile" -c 5 || true

  if [ ! -s "$outfile" ]; then
    echo "[ERRO] PCAP vazio ou não gerado: $outfile"
    exit 1
  fi

  echo "[OK] PCAP válido: $outfile"
}

run_benign() {
  echo
  echo "========== 1/7 — BENIGN =========="
  docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

  start_tcpdump "benign"
  sleep 90
  stop_tcpdump "benign"

  docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
}

run_attack() {
  local name="$1"
  local max_time="$2"
  shift 2

  echo
  echo "========== CAPTURANDO: ${name}_${ROUND} =========="

  docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

  start_tcpdump "$name"

  echo "[GERADOR] Executando: $*"
  timeout -k 5s "$max_time" docker compose exec -T botnet-controller "$@" || true

  stop_tcpdump "$name"
}

run_benign

run_attack "scan" 55s \
  python -u rodada5_generators.py scan --rounds 10 --delay 0.065

run_attack "bruteforce" 80s \
  python -u rodada5_generators.py bruteforce --count 115 --delay 0.055

run_attack "c2" 120s \
  python -u rodada5_generators.py c2 --count 105 --interval 1.05 --jitter 0.55 --payload-size 130

run_attack "flood" 60s \
  python -u rodada5_generators.py flood --count 720 --delay 0.0045 --payload-size 220

run_attack "slow_dos" 120s \
  python -u rodada5_generators.py slow_dos --connections 85 --chunks 12 --chunk-delay 1.0 --hold-time 24 --payload-size 70 --conn-delay 0.026

run_attack "mqtt_abuse" 95s \
  python -u rodada5_generators.py mqtt_abuse --connections 75 --messages-per-conn 12 --topics 18 --payload-size 220 --msg-delay 0.018 --conn-delay 0.020

echo
echo "========== RELIGANDO SENSORES NORMAIS =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

echo
echo "========== GERANDO SHA256 =========="
sha256sum "$OUT_DIR"/*.pcap > "$OUT_DIR/SHA256SUMS_blind17.txt"
cat "$OUT_DIR/SHA256SUMS_blind17.txt"

echo
echo "========== PCAPS GERADOS =========="
ls -lh "$OUT_DIR"/*.pcap

echo
echo "========== QUANTIDADE DE PCAPS =========="
QTD=$(find "$OUT_DIR" -maxdepth 1 -type f -name "*.pcap" | wc -l)
echo "$QTD"

if [ "$QTD" -ne 7 ]; then
  echo "[ALERTA] Era esperado gerar 7 PCAPs. Verifique a pasta $OUT_DIR."
else
  echo "[OK] 7 PCAPs gerados corretamente."
fi

echo
echo "========== FINALIZADO =========="
echo "Blind17 salvo em: $OUT_DIR"
echo "Próximo passo: converter os PCAPs no CICFlowMeter."
