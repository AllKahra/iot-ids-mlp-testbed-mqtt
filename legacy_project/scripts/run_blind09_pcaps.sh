#!/usr/bin/env bash
set -u

OUT_DIR="capture/pcaps/blind09"

BRIDGE_ID=$(docker network inspect iot_ids_net -f '{{.Id}}' | cut -c1-12)
IFACE="br-$BRIDGE_ID"

mkdir -p "$OUT_DIR"

echo "[INFO] Interface: $IFACE"
ip link show "$IFACE" || exit 1

sudo -v || exit 1

run_capture() {
  local name="$1"
  shift 1

  local outfile="$OUT_DIR/${name}_09.pcap"
  local logfile="/tmp/tcpdump_${name}_09.log"

  echo
  echo "========== CAPTURANDO ${name}_09 =========="

  rm -f "$outfile" "$logfile"

  sudo -n tcpdump -i "$IFACE" -w "$outfile" > "$logfile" 2>&1 &
  CAP_PID=$!

  sleep 3

  "$@"

  sleep 5

  sudo kill -2 $CAP_PID 2>/dev/null || true
  wait $CAP_PID 2>/dev/null || true

  sudo chown "$USER:$USER" "$outfile" 2>/dev/null || true

  echo "===== LOG TCPDUMP ${name}_09 ====="
  cat "$logfile"

  echo
  echo "===== ARQUIVO GERADO ====="
  ls -lh "$outfile"

  echo
  echo "===== PRIMEIROS PACOTES ====="
  sudo tcpdump -r "$outfile" -c 5 || true
}

echo
echo "========== GARANTINDO CONTAINERS =========="
docker compose start iot-gateway mqtt-broker fake-c2 botnet-controller >/dev/null 2>&1 || true

echo
echo "========== BENIGN =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
run_capture "benign" bash -c "sleep 80"

echo
echo "========== PARANDO SENSORES NORMAIS PARA ATAQUES =========="
docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

run_capture "scan" \
  docker compose exec -T botnet-controller python -u rodada5_generators.py scan \
  --rounds 12 \
  --delay 0.035

run_capture "bruteforce" \
  docker compose exec -T botnet-controller python -u rodada5_generators.py bruteforce \
  --count 120 \
  --delay 0.030

run_capture "c2" \
  docker compose exec -T botnet-controller python -u rodada5_generators.py c2 \
  --count 95 \
  --interval 0.45 \
  --jitter 0.30 \
  --payload-size 160

run_capture "flood" \
  docker compose exec -T botnet-controller python -u rodada5_generators.py flood \
  --count 650 \
  --delay 0.006 \
  --payload-size 260

run_capture "slow_dos" \
  docker compose exec -T botnet-controller python -u rodada5_generators.py slow_dos \
  --connections 90 \
  --chunks 10 \
  --chunk-delay 0.8 \
  --hold-time 20 \
  --payload-size 60 \
  --conn-delay 0.020

run_capture "mqtt_abuse" \
  docker compose exec -T botnet-controller python -u rodada5_generators.py mqtt_abuse \
  --connections 90 \
  --messages-per-conn 7 \
  --topics 14 \
  --payload-size 240 \
  --msg-delay 0.010 \
  --conn-delay 0.015

echo
echo "========== RELIGANDO SENSORES NORMAIS =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

echo
echo "========== PCAPS GERADOS =========="
ls -lh "$OUT_DIR"/*.pcap

echo
echo "Quantidade:"
find "$OUT_DIR" -maxdepth 1 -type f -name "*.pcap" | wc -l
