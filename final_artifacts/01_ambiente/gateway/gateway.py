import socket
import threading
import time
from datetime import datetime

HOST = "0.0.0.0"

TELEMETRY_PORT = 8080
LOGIN_PORT = 8081


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}", flush=True)


def handle_client(conn: socket.socket, addr, service_name: str) -> None:
    total_bytes = 0
    chunks = 0

    try:
        conn.settimeout(120)
        log(f"[{service_name}] conexão iniciada de {addr}")

        while True:
            data = conn.recv(4096)

            if not data:
                break

            chunks += 1
            total_bytes += len(data)

            text = data.decode(errors="ignore")

            log(
                f"[{service_name}] chunk {chunks} recebido de {addr} "
                f"({len(data)} bytes): {text[:150]}"
            )

    except socket.timeout:
        log(f"[{service_name}] timeout/cliente lento de {addr}")

    except Exception as e:
        log(f"[{service_name}] erro com {addr}: {e}")

    finally:
        try:
            conn.close()
        except Exception:
            pass

        log(
            f"[{service_name}] conexão encerrada de {addr} "
            f"chunks={chunks}, bytes={total_bytes}"
        )


def start_server(port: int, service_name: str) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, port))
    server.listen(100)

    log(f"[{service_name}] escutando em {HOST}:{port}")

    while True:
        conn, addr = server.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr, service_name),
            daemon=True
        )

        thread.start()


if __name__ == "__main__":
    threading.Thread(
        target=start_server,
        args=(TELEMETRY_PORT, "TELEMETRY"),
        daemon=True
    ).start()

    threading.Thread(
        target=start_server,
        args=(LOGIN_PORT, "LOGIN_FAKE"),
        daemon=True
    ).start()

    log("[GATEWAY] iniciado com serviços de telemetria e login fake")

    while True:
        time.sleep(1)
