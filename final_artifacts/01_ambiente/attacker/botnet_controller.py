import socket
import time
import json
import argparse
import random
from datetime import datetime

import paho.mqtt.client as mqtt


TARGETS = [
    "172.30.0.10",
    "172.30.0.11",
    "172.30.0.12",
    "172.30.0.13",
    "172.30.0.20",
    "172.30.0.100"
]

COMMON_PORTS = [
    22,
    23,
    80,
    443,
    8080,
    8081,
    1883,
    2323,
    9090
]

GATEWAY_HOST = "172.30.0.10"
GATEWAY_TELEMETRY_PORT = 8080
GATEWAY_LOGIN_PORT = 8081

MQTT_HOST = "172.30.0.20"
MQTT_PORT = 1883

C2_HOST = "172.30.0.100"
C2_PORT = 9090


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [botnet-controller] {message}", flush=True)


def try_connect(host: str, port: int, payload: bytes | None = None, timeout: float = 0.5) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            if payload:
                s.sendall(payload)

            return True

    except Exception:
        return False


def scan(delay: float) -> None:
    log("iniciando scan simulado")

    for target in TARGETS:
        for port in COMMON_PORTS:
            opened = try_connect(target, port)
            status = "aberto/respondeu" if opened else "sem resposta"

            log(f"scan {target}:{port} -> {status}")

            time.sleep(delay)

    log("scan simulado finalizado")


def bruteforce(count: int, delay: float) -> None:
    log("iniciando brute force simulado")

    users = [
        "admin",
        "root",
        "user",
        "iot",
        "operator",
        "guest"
    ]

    passwords = [
        "admin",
        "root",
        "123456",
        "password",
        "iot123",
        "1234",
        "qwerty"
    ]

    attempts = 0

    while attempts < count:
        user = users[attempts % len(users)]
        password = passwords[attempts % len(passwords)]

        payload = {
            "type": "LOGIN_ATTEMPT",
            "user": user,
            "password": password,
            "attempt": attempts + 1,
            "timestamp": time.time()
        }

        sent = try_connect(
            GATEWAY_HOST,
            GATEWAY_LOGIN_PORT,
            json.dumps(payload).encode(),
            timeout=1
        )

        log(f"login fake enviado {user}:{password} -> {'ok' if sent else 'erro'}")

        attempts += 1
        time.sleep(delay)

    log("brute force simulado finalizado")


def c2_beacon(count: int, interval: float) -> None:
    log("iniciando C2 beaconing simulado")

    for i in range(1, count + 1):
        payload = {
            "type": "BOT_HEARTBEAT",
            "source": "botnet-controller",
            "sequence": i,
            "timestamp": time.time()
        }

        sent = try_connect(
            C2_HOST,
            C2_PORT,
            json.dumps(payload).encode(),
            timeout=1
        )

        log(f"heartbeat C2 {i}/{count} -> {'ok' if sent else 'erro'}")

        time.sleep(interval)

    log("C2 beaconing simulado finalizado")


def flood(count: int, delay: float, payload_size: int) -> None:
    log("iniciando flood controlado")

    payload = {
        "type": "FLOOD_PACKET_SIMULATED",
        "data": "X" * payload_size,
        "timestamp": time.time()
    }

    raw_payload = json.dumps(payload).encode()

    for i in range(1, count + 1):
        sent = try_connect(
            GATEWAY_HOST,
            GATEWAY_TELEMETRY_PORT,
            raw_payload,
            timeout=0.2
        )

        if i % 10 == 0:
            log(f"flood progresso {i}/{count} -> {'ok' if sent else 'erro'}")

        time.sleep(delay)

    log("flood controlado finalizado")


def slow_dos(
    connections: int,
    hold_time: float,
    chunk_delay: float,
    chunks: int,
    payload_size: int
) -> None:
    log("iniciando slow DoS simulado")

    sockets: list[socket.socket] = []

    for i in range(1, connections + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((GATEWAY_HOST, GATEWAY_TELEMETRY_PORT))

            start_payload = {
                "type": "SLOW_DOS_SIMULATED_START",
                "connection": i,
                "timestamp": time.time()
            }

            s.sendall(json.dumps(start_payload).encode())

            sockets.append(s)

            log(f"slow_dos conexão {i}/{connections} aberta")

            time.sleep(0.2)

        except Exception as e:
            log(f"erro ao abrir conexão slow_dos {i}: {e}")

    for chunk_index in range(1, chunks + 1):
        for idx, s in enumerate(list(sockets), start=1):
            try:
                payload = {
                    "type": "SLOW_DOS_SIMULATED_CHUNK",
                    "connection": idx,
                    "chunk": chunk_index,
                    "data": "S" * payload_size,
                    "timestamp": time.time()
                }

                s.sendall(json.dumps(payload).encode())

                log(
                    f"slow_dos chunk {chunk_index}/{chunks} "
                    f"enviado na conexão {idx}"
                )

            except Exception as e:
                log(f"erro ao enviar chunk slow_dos na conexão {idx}: {e}")

                try:
                    sockets.remove(s)
                except ValueError:
                    pass

        time.sleep(chunk_delay)

    log(f"mantendo conexões abertas por {hold_time} segundos")
    time.sleep(hold_time)

    for idx, s in enumerate(sockets, start=1):
        try:
            s.close()
            log(f"slow_dos conexão {idx} encerrada")
        except Exception:
            pass

    log("slow DoS simulado finalizado")


def mqtt_abuse(count: int, delay: float, payload_size: int, topics: int) -> None:
    """
    Simula abuso MQTT controlado.

    O objetivo é gerar comportamento diferente do MQTT benigno:
    - mais mensagens;
    - maior frequência;
    - tópicos variados;
    - payload maior.
    """

    log("iniciando mqtt_abuse simulado")

    client = mqtt.Client(client_id=f"mqtt-abuse-{int(time.time())}")

    try:
        client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)

        topic_list = [
            "iot/abuse/temp",
            "iot/abuse/status",
            "iot/abuse/debug",
            "iot/abuse/config",
            "iot/abuse/bulk",
            "iot/abuse/random"
        ]

        topic_list = topic_list[:max(1, min(topics, len(topic_list)))]

        for i in range(1, count + 1):
            topic = random.choice(topic_list)

            payload = {
                "type": "MQTT_ABUSE_SIMULATED",
                "sequence": i,
                "topic": topic,
                "data": "M" * payload_size,
                "timestamp": time.time()
            }

            client.publish(topic, json.dumps(payload), qos=0)

            if i % 20 == 0:
                log(f"mqtt_abuse progresso {i}/{count} em tópico {topic}")

            time.sleep(delay)

        client.disconnect()

    except Exception as e:
        log(f"erro no mqtt_abuse: {e}")

    log("mqtt_abuse simulado finalizado")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Botnet-controller simulado para laboratório IoT IDS/ML"
    )

    parser.add_argument(
        "mode",
        choices=[
            "scan",
            "bruteforce",
            "c2",
            "flood",
            "slow_dos",
            "mqtt_abuse"
        ],
        help="Modo de tráfego a ser gerado"
    )

    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--payload-size", type=int, default=20)

    parser.add_argument("--connections", type=int, default=5)
    parser.add_argument("--hold-time", type=float, default=10)
    parser.add_argument("--chunk-delay", type=float, default=2)
    parser.add_argument("--chunks", type=int, default=3)

    parser.add_argument("--topics", type=int, default=3)

    args = parser.parse_args()

    if args.mode == "scan":
        scan(delay=args.delay)

    elif args.mode == "bruteforce":
        bruteforce(
            count=args.count,
            delay=args.delay
        )

    elif args.mode == "c2":
        c2_beacon(
            count=args.count,
            interval=args.interval
        )

    elif args.mode == "flood":
        flood(
            count=args.count,
            delay=args.delay,
            payload_size=args.payload_size
        )

    elif args.mode == "slow_dos":
        slow_dos(
            connections=args.connections,
            hold_time=args.hold_time,
            chunk_delay=args.chunk_delay,
            chunks=args.chunks,
            payload_size=args.payload_size
        )

    elif args.mode == "mqtt_abuse":
        mqtt_abuse(
            count=args.count,
            delay=args.delay,
            payload_size=args.payload_size,
            topics=args.topics
        )
