import time
import random
import sys
import json
from datetime import datetime

import paho.mqtt.client as mqtt

MQTT_HOST = "172.30.0.20"
MQTT_PORT = 1883

sensor_id = sys.argv[1] if len(sys.argv) > 1 else "sensor-mqtt"
min_delay = float(sys.argv[2]) if len(sys.argv) > 2 else 4
max_delay = float(sys.argv[3]) if len(sys.argv) > 3 else 8


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [{sensor_id}] {message}", flush=True)


client = mqtt.Client(client_id=sensor_id)

while True:
    topic = f"iot/sensors/{sensor_id}/telemetry"

    payload = {
        "type": "mqtt_telemetry",
        "sensor": sensor_id,
        "temperature": round(random.uniform(20, 35), 2),
        "humidity": round(random.uniform(40, 80), 2),
        "battery": round(random.uniform(70, 100), 2),
        "status": "normal",
        "timestamp": time.time()
    }

    try:
        client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
        client.publish(topic, json.dumps(payload), qos=0)
        client.disconnect()

        log(f"telemetria MQTT enviada em {topic}: {payload}")

    except Exception as e:
        log(f"erro ao enviar telemetria MQTT: {e}")

    time.sleep(random.uniform(min_delay, max_delay))
