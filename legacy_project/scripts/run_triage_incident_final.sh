#!/usr/bin/env bash
set -u

OUT_DIR="capture/pcaps/triage_incident_final"
OUT_FILE="$OUT_DIR/incident_final.pcap"

mkdir -p "$OUT_DIR"

echo
echo "========== INCIDENTE FINAL — TRIAGEM IDS =========="
echo "Este PCAP simula tráfego misto: benigno + C2 discreto + abuso de disponibilidade."
echo "Ele NÃO será usado para treino."

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
echo "========== LIMPANDO CAPTURAS ANTIGAS =========="
sudo pkill -2 tcpdump 2>/dev/null || true
rm -f "$OUT_FILE" /tmp/tcpdump_incident_final.log

echo
echo "========== INICIANDO SENSORES BENIGNOS =========="
docker compose start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true

echo
echo "========== INICIANDO TCPDUMP =========="
sudo tcpdump -i "$IFACE" -w "$OUT_FILE" > /tmp/tcpdump_incident_final.log 2>&1 &
TCPDUMP_PID=$!

sleep 8

echo
echo "========== FASE 1 — C2 BEACON DISCRETO EM BACKGROUND =========="
timeout -k 5s 120s docker compose exec -T botnet-controller \
  python -u rodada5_generators.py c2 --count 100 --interval 1.05 --jitter 0.55 --payload-size 130 &

sleep 18

echo
echo "========== FASE 2 — MQTT ABUSE MODERADO =========="
timeout -k 5s 90s docker compose exec -T botnet-controller \
  python -u rodada5_generators.py mqtt_abuse --connections 75 --messages-per-conn 12 --topics 18 --payload-size 220 --msg-delay 0.018 --conn-delay 0.020 &

sleep 20

echo
echo "========== FASE 3 — SLOW DOS CONTROLADO =========="
timeout -k 5s 110s docker compose exec -T botnet-controller \
  python -u rodada5_generators.py slow_dos --connections 85 --chunks 12 --chunk-delay 1.0 --hold-time 24 --payload-size 70 --conn-delay 0.026 &

sleep 20

echo
echo "========== FASE 4 — RAJADA CURTA DE FLOOD =========="
timeout -k 5s 55s docker compose exec -T botnet-controller \
  python -u rodada5_generators.py flood --count 720 --delay 0.0045 --payload-size 220 || true

echo
echo "========== AGUARDANDO FINALIZAÇÃO =========="
wait || true

sleep 5

echo
echo "========== PARANDO TCPDUMP =========="
sudo kill -2 "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

sudo chown "$USER:$USER" "$OUT_FILE" 2>/dev/null || true

echo
echo "========== LOG TCPDUMP =========="
cat /tmp/tcpdump_incident_final.log || true

echo
echo "========== PCAP GERADO =========="
ls -lh "$OUT_FILE"

echo
echo "========== PRIMEIROS PACOTES =========="
sudo tcpdump -r "$OUT_FILE" -c 10 || true

echo
echo "========== SHA256 =========="
sha256sum "$OUT_FILE" > "$OUT_DIR/SHA256SUMS_incident_final.txt"
cat "$OUT_DIR/SHA256SUMS_incident_final.txt"

echo
echo "========== FINALIZADO =========="
echo "PCAP: $OUT_FILE"
