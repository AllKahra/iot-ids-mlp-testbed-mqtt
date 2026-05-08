#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="$(pwd)"
PCAP_DIR="$PROJECT_DIR/capture/pcaps"
NETWORK_NAME="iot_ids_net"

mkdir -p "$PCAP_DIR"

echo "[INFO] Diretório do projeto: $PROJECT_DIR"
echo "[INFO] PCAPs serão salvos em: $PCAP_DIR"

# Detecta se o sistema usa docker compose ou docker-compose.
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
    echo "[INFO] Usando: docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
    echo "[INFO] Usando: docker-compose"
else
    echo "[ERRO] Nem docker compose nem docker-compose foram encontrados."
    exit 1
fi

echo "[INFO] Subindo ambiente..."
"${COMPOSE[@]}" up -d --build

echo "[INFO] Aguardando containers estabilizarem..."
sleep 8

echo "[INFO] Containers ativos:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo "[INFO] Detectando interface Docker..."

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    echo "[ERRO] Rede $NETWORK_NAME não encontrada."
    echo "[INFO] Redes disponíveis:"
    docker network ls
    exit 1
fi

BRIDGE_ID=$(docker network inspect "$NETWORK_NAME" -f '{{.Id}}' | cut -c1-12)
IFACE="br-$BRIDGE_ID"

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "[ERRO] Interface $IFACE não encontrada."
    echo "[INFO] Bridges disponíveis:"
    ip link | grep br- || true
    exit 1
fi

echo "[INFO] Interface Docker detectada: $IFACE"

TCPDUMP_PID=""

start_capture() {
    local name="$1"
    local outfile="$PCAP_DIR/${name}.pcap"

    echo
    echo "============================================================"
    echo "[CAPTURA] Iniciando: $name"
    echo "[CAPTURA] Arquivo: $outfile"
    echo "============================================================"

    if [ -f "$outfile" ]; then
        echo "[INFO] Removendo PCAP antigo: $outfile"
        rm -f "$outfile"
    fi

    sudo tcpdump -i "$IFACE" -w "$outfile" >/dev/null 2>&1 &
    TCPDUMP_PID=$!

    sleep 2
}

stop_capture() {
    local name="$1"
    local outfile="$PCAP_DIR/${name}.pcap"

    sleep 2

    if [ -n "${TCPDUMP_PID:-}" ] && kill -0 "$TCPDUMP_PID" >/dev/null 2>&1; then
        sudo kill -INT "$TCPDUMP_PID" >/dev/null 2>&1 || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi

    TCPDUMP_PID=""

    if [ -s "$outfile" ]; then
        echo "[OK] PCAP gerado: $outfile"
        ls -lh "$outfile"
    else
        echo "[ALERTA] PCAP vazio ou não gerado: $outfile"
    fi
}

stop_benign_sensors() {
    echo "[INFO] Parando sensores benignos..."
    "${COMPOSE[@]}" stop sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
    sleep 3
}

start_http_sensor01() {
    echo "[INFO] Iniciando sensor01..."
    "${COMPOSE[@]}" start sensor01 >/dev/null 2>&1 || true
    sleep 5
}

start_http_sensors() {
    echo "[INFO] Iniciando sensores HTTP benignos..."
    "${COMPOSE[@]}" start sensor01 sensor02 >/dev/null 2>&1 || true
    sleep 5
}

start_mqtt_sensor() {
    echo "[INFO] Iniciando sensor MQTT benigno..."
    "${COMPOSE[@]}" start sensor-mqtt-normal >/dev/null 2>&1 || true
    sleep 5
}

start_all_benign_sensors() {
    echo "[INFO] Iniciando todos os sensores benignos..."
    "${COMPOSE[@]}" start sensor01 sensor02 sensor-mqtt-normal >/dev/null 2>&1 || true
    sleep 5
}

capture_sleep() {
    local name="$1"
    local seconds="$2"

    start_capture "$name"

    echo "[INFO] Capturando tráfego benigno por ${seconds}s..."
    sleep "$seconds"

    stop_capture "$name"
}

capture_command() {
    local name="$1"
    shift

    start_capture "$name"

    echo "[INFO] Executando comando de geração de tráfego:"
    echo "       $*"

    set +e
    "$@"
    local status=$?
    set -e

    if [ "$status" -ne 0 ]; then
        echo "[ALERTA] O comando retornou status $status em $name"
    fi

    stop_capture "$name"
}

echo
echo "============================================================"
echo "[FASE] Capturas BENIGN"
echo "============================================================"

# Para benign, os sensores precisam estar ligados.
# Aqui fazemos variações:
# benign_01 = HTTP sensor01
# benign_02 = HTTP sensor01 + sensor02
# benign_03 = MQTT normal
# benign_04 = HTTP + MQTT normal

stop_benign_sensors
start_http_sensor01
capture_sleep "benign_01" 45

stop_benign_sensors
start_http_sensors
capture_sleep "benign_02" 45

stop_benign_sensors
start_mqtt_sensor
capture_sleep "benign_03" 45

stop_benign_sensors
start_all_benign_sensors
capture_sleep "benign_04" 60

echo
echo "================================================------------"
echo "[FASE] Preparando capturas de ataques"
echo "================================================------------"

# Para ataques, paramos sensores benignos para evitar mistura de classe.
stop_benign_sensors

echo
echo "============================================================"
echo "[FASE] Capturas SCAN"
echo "============================================================"

capture_command "scan_01" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py scan --delay 0.03

capture_command "scan_02" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py scan --delay 0.20

capture_command "scan_03" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py scan --delay 0.10

capture_command "scan_04" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py scan --delay 0.07

echo
echo "============================================================"
echo "[FASE] Capturas BRUTEFORCE"
echo "============================================================"

capture_command "bruteforce_01" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py bruteforce --count 20 --delay 0.10

capture_command "bruteforce_02" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py bruteforce --count 50 --delay 0.05

capture_command "bruteforce_03" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py bruteforce --count 25 --delay 0.40

capture_command "bruteforce_04" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py bruteforce --count 35 --delay 0.20

echo
echo "============================================================"
echo "[FASE] Capturas C2_BEACON"
echo "============================================================"

capture_command "c2_01" \
    "${COMPOSE[@]}" exec -T sensor03-compromised \
    python -u sensor_compromised.py --count 20 --interval 1 --jitter 0

capture_command "c2_02" \
    "${COMPOSE[@]}" exec -T sensor03-compromised \
    python -u sensor_compromised.py --count 15 --interval 2.5 --jitter 0

capture_command "c2_03" \
    "${COMPOSE[@]}" exec -T sensor03-compromised \
    python -u sensor_compromised.py --count 20 --interval 1 --jitter 1.5

capture_command "c2_04" \
    "${COMPOSE[@]}" exec -T sensor03-compromised \
    python -u sensor_compromised.py --count 20 --interval 1.5 --jitter 2

echo
echo "============================================================"
echo "[FASE] Capturas DOS_FLOOD"
echo "============================================================"

capture_command "flood_01" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py flood --count 100 --delay 0.03 --payload-size 20

capture_command "flood_02" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py flood --count 200 --delay 0.01 --payload-size 30

capture_command "flood_03" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py flood --count 150 --delay 0.01 --payload-size 120

capture_command "flood_04" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py flood --count 120 --delay 0.005 --payload-size 60

echo
echo "============================================================"
echo "[FASE] Capturas SLOW_DOS"
echo "============================================================"

capture_command "slow_dos_01" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py slow_dos \
    --connections 3 \
    --chunks 3 \
    --chunk-delay 2 \
    --hold-time 10 \
    --payload-size 10

capture_command "slow_dos_02" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py slow_dos \
    --connections 6 \
    --chunks 3 \
    --chunk-delay 2 \
    --hold-time 12 \
    --payload-size 10

capture_command "slow_dos_03" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py slow_dos \
    --connections 5 \
    --chunks 4 \
    --chunk-delay 4 \
    --hold-time 15 \
    --payload-size 8

capture_command "slow_dos_04" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py slow_dos \
    --connections 4 \
    --chunks 5 \
    --chunk-delay 3 \
    --hold-time 18 \
    --payload-size 12

echo
echo "============================================================"
echo "[FASE] Capturas MQTT_ABUSE"
echo "============================================================"

capture_command "mqtt_abuse_01" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py mqtt_abuse \
    --count 80 \
    --delay 0.05 \
    --payload-size 30 \
    --topics 2

capture_command "mqtt_abuse_02" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py mqtt_abuse \
    --count 80 \
    --delay 0.05 \
    --payload-size 30 \
    --topics 5

capture_command "mqtt_abuse_03" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py mqtt_abuse \
    --count 60 \
    --delay 0.08 \
    --payload-size 150 \
    --topics 3

capture_command "mqtt_abuse_04" \
    "${COMPOSE[@]}" exec -T botnet-controller \
    python -u botnet_controller.py mqtt_abuse \
    --count 70 \
    --delay 0.03 \
    --payload-size 80 \
    --topics 4

echo
echo "============================================================"
echo "[FINAL] Capturas concluídas"
echo "============================================================"

echo "[INFO] Reiniciando sensores benignos para deixar ambiente normal..."
start_all_benign_sensors

echo
echo "[INFO] PCAPs gerados:"
ls -lh "$PCAP_DIR"

echo
echo "[INFO] Total de PCAPs:"
find "$PCAP_DIR" -maxdepth 1 -name "*.pcap" | wc -l

echo
echo "[INFO] Verificação esperada:"
echo "       Total esperado: 28 PCAPs"
echo "       7 classes x 4 capturas"

echo
echo "[OK] Script finalizado."
