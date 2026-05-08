#!/usr/bin/env bash
set -u

OUT_DIR="capture/pcaps/blind16"
ROUND="16"

mkdir -p "$OUT_DIR"

echo
echo "========== BLIND16 — TESTE CEGO REAL DO MODELO V6 =========="

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
docker compose exec -T botnet-controller pkill -f rodada5_generators.py 2>/dev/null || true

echo
echo "========== CRIANDO LABELS DO BLIND16 =========="
cat > "$OUT_DIR/pcap_labels_blind16.csv" <<LABELS
filename,label,attack_type
benign_16.pcap,0,benign
scan_16.pcap,1,scan
bruteforce_16.pcap,1,bruteforce
c2_16.pcap,1,c2_beacon
flood_16.pcap,1,dos_flood
mqtt_abuse_16.pcap,1,mqtt_abuse
slow_dos_16.pcap,1,slow_dos
LABELS

cat "$OUT_DIR/pcap_labels_blind16.csv"

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
  sleep 85
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

run_attack "scan" 50s \
  python -u rodada5_generators.py scan --rounds 12 --delay 0.050

run_attack "bruteforce" 75s \
  python -u rodada5_generators.py bruteforce --count 125 --delay 0.040

run_attack "c2" 95s \
  python -u rodada5_generators.py c2 --count 100 --interval 0.50 --jitter 0.40 --payload-size 170

run_attack "flood" 50s \
  python -u rodada5_generators.py flood --count 650 --delay 0.0065 --payload-size 280

run_attack "slow_dos" 95s \
  python -u rodada5_generators.py slow_dos --connections 90 --chunks 10 --chunk-delay 0.78 --hold-time 17 --payload-size 70 --conn-delay 0.021

run_attack "mqtt_abuse" 80s \
  python -u rodada5_generators.py mqtt_abuse --connections 90 --messages-per-conn 9 --topics 13 --payload-size 250 --msg-delay 0.013 --conn-delay 0.018

echo
echo "========== RELIGANDO SENSORES NORMAIS =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

echo
echo "========== GERANDO SHA256 =========="
sha256sum "$OUT_DIR"/*.pcap > "$OUT_DIR/SHA256SUMS_blind16.txt"
cat "$OUT_DIR/SHA256SUMS_blind16.txt"

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
echo "Blind16 salvo em: $OUT_DIR"
echo "Próximo passo: converter os PCAPs no CICFlowMeter."
