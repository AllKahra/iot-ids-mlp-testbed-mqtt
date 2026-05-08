#!/usr/bin/env bash
set -u

OUT_DIR="capture/pcaps/reforco_v7"

mkdir -p "$OUT_DIR"

echo
echo "========== REFORÇOS V7 — PCAPS DIRECIONADOS =========="
echo "Esses PCAPs NÃO são teste cego. Eles serão usados para treino/reforço."

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
echo "========== CRIANDO LABELS DO REFORÇO V7 =========="
cat > "$OUT_DIR/pcap_labels_reforco_v7.csv" <<LABELS
filename,label,attack_type
benign_ref01.pcap,0,benign
benign_ref02.pcap,0,benign
benign_ref03.pcap,0,benign
benign_ref04.pcap,0,benign
bruteforce_ref01.pcap,1,bruteforce
bruteforce_ref02.pcap,1,bruteforce
bruteforce_ref03.pcap,1,bruteforce
c2_ref01.pcap,1,c2_beacon
c2_ref02.pcap,1,c2_beacon
c2_ref03.pcap,1,c2_beacon
c2_ref04.pcap,1,c2_beacon
dos_flood_ref01.pcap,1,dos_flood
dos_flood_ref02.pcap,1,dos_flood
dos_flood_ref03.pcap,1,dos_flood
dos_flood_ref04.pcap,1,dos_flood
mqtt_abuse_ref01.pcap,1,mqtt_abuse
mqtt_abuse_ref02.pcap,1,mqtt_abuse
mqtt_abuse_ref03.pcap,1,mqtt_abuse
mqtt_abuse_ref04.pcap,1,mqtt_abuse
slow_dos_ref01.pcap,1,slow_dos
slow_dos_ref02.pcap,1,slow_dos
slow_dos_ref03.pcap,1,slow_dos
slow_dos_ref04.pcap,1,slow_dos
scan_ref01.pcap,1,scan
LABELS

cat "$OUT_DIR/pcap_labels_reforco_v7.csv"

start_tcpdump() {
  local name="$1"
  local outfile="$OUT_DIR/${name}.pcap"
  local logfile="/tmp/tcpdump_${name}.log"

  rm -f "$outfile" "$logfile"

  echo
  echo "[CAPTURA] Iniciando tcpdump: $outfile"

  sudo tcpdump -i "$IFACE" -w "$outfile" > "$logfile" 2>&1 &
  TCPDUMP_PID=$!

  sleep 3
}

stop_tcpdump() {
  local name="$1"
  local outfile="$OUT_DIR/${name}.pcap"
  local logfile="/tmp/tcpdump_${name}.log"

  echo "[CAPTURA] Parando tcpdump..."
  sudo kill -2 "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true

  sudo chown "$USER:$USER" "$outfile" 2>/dev/null || true

  echo
  echo "===== LOG TCPDUMP ${name} ====="
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

run_benign_all() {
  local name="$1"
  local seconds="$2"

  echo
  echo "========== BENIGN: $name =========="
  docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

  start_tcpdump "$name"
  sleep "$seconds"
  stop_tcpdump "$name"

  docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
}

run_benign_http() {
  local name="$1"
  local seconds="$2"

  echo
  echo "========== BENIGN HTTP: $name =========="
  docker compose start sensor01 sensor02 >/dev/null 2>&1 || true
  docker compose stop sensor-mqtt-normal >/dev/null 2>&1 || true

  start_tcpdump "$name"
  sleep "$seconds"
  stop_tcpdump "$name"

  docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
}

run_benign_mqtt() {
  local name="$1"
  local seconds="$2"

  echo
  echo "========== BENIGN MQTT: $name =========="
  docker compose stop sensor01 sensor02 >/dev/null 2>&1 || true
  docker compose start sensor-mqtt-normal >/dev/null 2>&1 || true

  start_tcpdump "$name"
  sleep "$seconds"
  stop_tcpdump "$name"

  docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
}

run_attack() {
  local name="$1"
  local max_time="$2"
  shift 2

  echo
  echo "========== CAPTURANDO REFORÇO: ${name} =========="

  docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

  start_tcpdump "$name"

  echo "[GERADOR] Executando: $*"
  timeout -k 5s "$max_time" docker compose exec -T botnet-controller "$@" || true

  stop_tcpdump "$name"
}

echo
echo "========== BENIGN REFORÇOS =========="
run_benign_http "benign_ref01" 75
run_benign_all "benign_ref02" 85
run_benign_mqtt "benign_ref03" 80
run_benign_all "benign_ref04" 95

echo
echo "========== BRUTEFORCE REFORÇOS =========="
run_attack "bruteforce_ref01" 75s \
  python -u rodada5_generators.py bruteforce --count 150 --delay 0.025

run_attack "bruteforce_ref02" 90s \
  python -u rodada5_generators.py bruteforce --count 90 --delay 0.080

run_attack "bruteforce_ref03" 80s \
  python -u rodada5_generators.py bruteforce --count 130 --delay 0.045

echo
echo "========== C2 REFORÇOS =========="
run_attack "c2_ref01" 120s \
  python -u rodada5_generators.py c2 --count 120 --interval 0.80 --jitter 0.10 --payload-size 80

run_attack "c2_ref02" 130s \
  python -u rodada5_generators.py c2 --count 100 --interval 1.20 --jitter 0.40 --payload-size 120

run_attack "c2_ref03" 140s \
  python -u rodada5_generators.py c2 --count 90 --interval 1.60 --jitter 0.60 --payload-size 160

run_attack "c2_ref04" 130s \
  python -u rodada5_generators.py c2 --count 110 --interval 1.00 --jitter 0.80 --payload-size 100

echo
echo "========== DOS FLOOD REFORÇOS =========="
run_attack "dos_flood_ref01" 55s \
  python -u rodada5_generators.py flood --count 800 --delay 0.003 --payload-size 120

run_attack "dos_flood_ref02" 60s \
  python -u rodada5_generators.py flood --count 650 --delay 0.006 --payload-size 250

run_attack "dos_flood_ref03" 65s \
  python -u rodada5_generators.py flood --count 450 --delay 0.008 --payload-size 500

run_attack "dos_flood_ref04" 55s \
  python -u rodada5_generators.py flood --count 1000 --delay 0.002 --payload-size 80

echo
echo "========== MQTT ABUSE REFORÇOS =========="
run_attack "mqtt_abuse_ref01" 90s \
  python -u rodada5_generators.py mqtt_abuse --connections 90 --messages-per-conn 10 --topics 20 --payload-size 180 --msg-delay 0.014 --conn-delay 0.018

run_attack "mqtt_abuse_ref02" 95s \
  python -u rodada5_generators.py mqtt_abuse --connections 70 --messages-per-conn 15 --topics 10 --payload-size 260 --msg-delay 0.016 --conn-delay 0.020

run_attack "mqtt_abuse_ref03" 90s \
  python -u rodada5_generators.py mqtt_abuse --connections 100 --messages-per-conn 8 --topics 25 --payload-size 120 --msg-delay 0.012 --conn-delay 0.017

run_attack "mqtt_abuse_ref04" 100s \
  python -u rodada5_generators.py mqtt_abuse --connections 60 --messages-per-conn 20 --topics 15 --payload-size 300 --msg-delay 0.018 --conn-delay 0.022

echo
echo "========== SLOW DOS REFORÇOS =========="
run_attack "slow_dos_ref01" 120s \
  python -u rodada5_generators.py slow_dos --connections 100 --chunks 12 --chunk-delay 0.9 --hold-time 22 --payload-size 70 --conn-delay 0.025

run_attack "slow_dos_ref02" 130s \
  python -u rodada5_generators.py slow_dos --connections 75 --chunks 15 --chunk-delay 1.1 --hold-time 25 --payload-size 65 --conn-delay 0.030

run_attack "slow_dos_ref03" 145s \
  python -u rodada5_generators.py slow_dos --connections 60 --chunks 10 --chunk-delay 1.4 --hold-time 30 --payload-size 80 --conn-delay 0.035

run_attack "slow_dos_ref04" 115s \
  python -u rodada5_generators.py slow_dos --connections 120 --chunks 8 --chunk-delay 0.75 --hold-time 20 --payload-size 75 --conn-delay 0.022

echo
echo "========== SCAN MANUTENÇÃO =========="
run_attack "scan_ref01" 55s \
  python -u rodada5_generators.py scan --rounds 9 --delay 0.060

echo
echo "========== RELIGANDO SENSORES NORMAIS =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

echo
echo "========== GERANDO SHA256 =========="
sha256sum "$OUT_DIR"/*.pcap > "$OUT_DIR/SHA256SUMS_reforco_v7.txt"
cat "$OUT_DIR/SHA256SUMS_reforco_v7.txt"

echo
echo "========== PCAPS GERADOS =========="
ls -lh "$OUT_DIR"/*.pcap

echo
echo "========== QUANTIDADE DE PCAPS =========="
QTD=$(find "$OUT_DIR" -maxdepth 1 -type f -name "*.pcap" | wc -l)
echo "$QTD"

if [ "$QTD" -ne 24 ]; then
  echo "[ALERTA] Era esperado gerar 24 PCAPs. Verifique a pasta $OUT_DIR."
else
  echo "[OK] 24 PCAPs gerados corretamente."
fi

echo
echo "========== FINALIZADO =========="
echo "Reforços V7 salvos em: $OUT_DIR"
echo "Próximo passo: converter os PCAPs no CICFlowMeter."
