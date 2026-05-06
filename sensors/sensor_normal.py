import socket
import time
import random
import sys
import json
from datetime import datetime

GATEWAY_HOST = "172.30.0.10"
GATEWAY_PORT = 8080

sensor_id = sys.argv[1] if len(sys.argv) > 1 else "sensor"
min_delay = float(sys.argv[2]) if len(sys.argv) > 2 else 3
max_delay = float(sys.argv[3]) if len(sys.argv) > 3 else 5


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [{sensor_id}] {message}", flush=True)


while True:
    payload = {
        "type": "telemetry",
        "sensor": sensor_id,
        "temperature": round(random.uniform(20, 35), 2),
        "humidity": round(random.uniform(40, 80), 2),
        "battery": round(random.uniform(70, 100), 2),
        "status": "normal",
        "timestamp": time.time()
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((GATEWAY_HOST, GATEWAY_PORT))
            s.sendall(json.dumps(payload).encode())

        log(f"telemetria HTTP enviada: {payload}")

    except Exception as e:
        log(f"erro ao enviar telemetria HTTP: {e}")

    time.sleep(random.uniform(min_delay, max_delay))
