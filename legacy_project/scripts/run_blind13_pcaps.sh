#!/usr/bin/env bash
set -u

OUT_DIR="capture/pcaps/blind13"

BRIDGE_ID=$(docker network inspect iot_ids_net -f '{{.Id}}' | cut -c1-12)
IFACE="br-$BRIDGE_ID"

mkdir -p "$OUT_DIR"

echo "[INFO] Interface: $IFACE"
ip link show "$IFACE" || exit 1

sudo -v || exit 1

run_capture() {
  local name="$1"
  local cap_seconds="$2"
  local gen_seconds="$3"
  local gen_cmd="$4"

  local outfile="$OUT_DIR/${name}_13.pcap"
  local logfile="/tmp/tcpdump_${name}_13.log"

  echo
  echo "========== CAPTURANDO ${name}_13 =========="

  rm -f "$outfile" "$logfile"

  sudo -n timeout "$cap_seconds" tcpdump -i "$IFACE" -w "$outfile" > "$logfile" 2>&1 &
  CAP_PID=$!

  sleep 3

  timeout "$gen_seconds" bash -lc "$gen_cmd" || true

  sudo pkill -2 -f "tcpdump -i .*${name}_13.pcap" 2>/dev/null || true
  wait $CAP_PID 2>/dev/null || true

  sudo chown "$USER:$USER" "$outfile" 2>/dev/null || true

  echo "===== LOG TCPDUMP ${name}_13 ====="
  cat "$logfile"

  echo
  echo "===== ARQUIVO GERADO ====="
  ls -lh "$outfile"

  echo
  echo "===== PRIMEIROS PACOTES ====="
  sudo tcpdump -r "$outfile" -c 5 || true
}

echo
echo "========== LIMPANDO PROCESSOS ANTIGOS =========="
sudo pkill -f "tcpdump -i" 2>/dev/null || true
docker compose exec -T botnet-controller pkill -f rodada5_generators.py 2>/dev/null || true

echo
echo "========== GARANTINDO CONTAINERS =========="
docker compose start iot-gateway mqtt-broker fake-c2 botnet-controller >/dev/null 2>&1 || true

echo
echo "========== BENIGN =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
run_capture "benign" 90 85 "sleep 80"

echo
echo "========== PARANDO SENSORES NORMAIS PARA ATAQUES =========="
docker compose stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

run_capture "scan" 80 70 \
"docker compose exec -T botnet-controller python -u rodada5_generators.py scan --rounds 14 --delay 0.030"

run_capture "bruteforce" 100 90 \
"docker compose exec -T botnet-controller python -u rodada5_generators.py bruteforce --count 140 --delay 0.025"

run_capture "c2" 110 100 \
"docker compose exec -T botnet-controller python -u rodada5_generators.py c2 --count 110 --interval 0.35 --jitter 0.25 --payload-size 180"

run_capture "flood" 110 100 \
"docker compose exec -T botnet-controller python -u rodada5_generators.py flood --count 750 --delay 0.005 --payload-size 300"

run_capture "slow_dos" 130 120 \
"docker compose exec -T botnet-controller python -u rodada5_generators.py slow_dos --connections 95 --chunks 10 --chunk-delay 0.7 --hold-time 20 --payload-size 70 --conn-delay 0.018"

run_capture "mqtt_abuse" 110 100 \
"docker compose exec -T botnet-controller python -u rodada5_generators.py mqtt_abuse --connections 95 --messages-per-conn 7 --topics 15 --payload-size 260 --msg-delay 0.010 --conn-delay 0.015"

echo
echo "========== RELIGANDO SENSORES NORMAIS =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

echo
echo "========== PCAPS GERADOS =========="
ls -lh "$OUT_DIR"/*.pcap

echo
echo "Quantidade:"
find "$OUT_DIR" -maxdepth 1 -type f -name "*.pcap" | wc -l
