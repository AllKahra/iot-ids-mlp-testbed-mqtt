#!/usr/bin/env bash
set -u

OUT_DIR="capture/pcaps/blind05"

BRIDGE_ID=$(docker network inspect iot_ids_net -f '{{.Id}}' | cut -c1-12)
IFACE="br-$BRIDGE_ID"

mkdir -p "$OUT_DIR"

echo "[INFO] Interface: $IFACE"
ip link show "$IFACE" || exit 1

sudo -v || exit 1

run_capture() {
  local name="$1"
  local duration="$2"
  shift 2

  local outfile="$OUT_DIR/${name}_05.pcap"
  local logfile="/tmp/tcpdump_${name}_05.log"

  echo
  echo "========== CAPTURANDO ${name}_05 =========="

  rm -f "$outfile" "$logfile"

  sudo -n timeout "$duration" tcpdump -i "$IFACE" -w "$outfile" > "$logfile" 2>&1 &
  CAP_PID=$!

  sleep 3

  "$@"

  wait $CAP_PID || true

  sudo chown "$USER:$USER" "$outfile" 2>/dev/null || true

  echo "===== LOG TCPDUMP ${name}_05 ====="
  cat "$logfile"

  echo
  echo "===== ARQUIVO GERADO ====="
  ls -lh "$outfile"

  echo
  echo "===== PRIMEIROS PACOTES ====="
  sudo tcpdump -r "$outfile" -c 5 || true
}

echo
echo "========== GARANTINDO CONTAINERS PRINCIPAIS =========="
docker compose start iot-gateway mqtt-broker fake-c2 botnet-controller >/dev/null 2>&1 || true

echo
echo "========== BENIGN =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
run_capture "benign" 90 bash -c "sleep 70"

echo
echo "========== PARANDO SENSORES NORMAIS PARA ATAQUES =========="
docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

run_capture "scan" 90 \
  docker compose exec -T botnet-controller python -u rodada5_generators.py scan \
  --rounds 10 \
  --delay 0.025

run_capture "bruteforce" 90 \
  docker compose exec -T botnet-controller python -u rodada5_generators.py bruteforce \
  --count 90 \
  --delay 0.035

run_capture "c2" 90 \
  docker compose exec -T botnet-controller python -u rodada5_generators.py c2 \
  --count 40 \
  --interval 0.65 \
  --jitter 0.4 \
  --payload-size 90

run_capture "flood" 90 \
  docker compose exec -T botnet-controller python -u rodada5_generators.py flood \
  --count 550 \
  --delay 0.008 \
  --payload-size 220

run_capture "slow_dos" 110 \
  docker compose exec -T botnet-controller python -u rodada5_generators.py slow_dos \
  --connections 80 \
  --chunks 9 \
  --chunk-delay 1 \
  --hold-time 22 \
  --payload-size 40 \
  --conn-delay 0.025

run_capture "mqtt_abuse" 100 \
  docker compose exec -T botnet-controller python -u rodada5_generators.py mqtt_abuse \
  --connections 80 \
  --messages-per-conn 6 \
  --topics 12 \
  --payload-size 220 \
  --msg-delay 0.01 \
  --conn-delay 0.02

echo
echo "========== RELIGANDO SENSORES NORMAIS =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

echo
echo "========== PCAPS GERADOS =========="
ls -lh "$OUT_DIR"/*.pcap

echo
echo "Quantidade:"
find "$OUT_DIR" -maxdepth 1 -type f -name "*.pcap" | wc -l
