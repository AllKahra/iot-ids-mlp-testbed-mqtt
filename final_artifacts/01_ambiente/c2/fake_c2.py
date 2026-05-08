import socket
from datetime import datetime

HOST = "0.0.0.0"
PORT = 9090


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}", flush=True)


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(100)

log(f"[FAKE-C2] escutando em {HOST}:{PORT}")

while True:
    conn, addr = server.accept()

    try:
        data = conn.recv(4096)

        if data:
            text = data.decode(errors="ignore")
            log(f"[FAKE-C2] heartbeat recebido de {addr}: {text}")

    except Exception as e:
        log(f"[FAKE-C2] erro: {e}")

    finally:
        conn.close()
