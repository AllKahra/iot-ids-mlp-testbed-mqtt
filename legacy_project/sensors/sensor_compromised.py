import socket
import time
import json
import random
import argparse
from datetime import datetime

C2_HOST = "172.30.0.100"
C2_PORT = 9090


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [sensor03-compromised] {message}", flush=True)


def send_heartbeat(index: int) -> None:
    payload = {
        "type": "BOT_HEARTBEAT",
        "sensor": "sensor03-compromised",
        "status": "online",
        "sequence": index,
        "timestamp": time.time()
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((C2_HOST, C2_PORT))
            s.sendall(json.dumps(payload).encode())

        log(f"heartbeat enviado: {payload}")

    except Exception as e:
        log(f"erro ao enviar heartbeat: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--jitter", type=float, default=0)

    args = parser.parse_args()

    for i in range(1, args.count + 1):
        send_heartbeat(i)

        sleep_time = args.interval

        if args.jitter > 0:
            sleep_time += random.uniform(0, args.jitter)

        time.sleep(sleep_time)
