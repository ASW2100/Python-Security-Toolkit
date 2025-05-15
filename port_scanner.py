import socket
import threading
from queue import Queue

# Global constants
THREAD_COUNT = 100
print_lock = threading.Lock()


def scan_port(host: str, port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    s.send(b"Hello\r\n")
                    banner = s.recv(1024).decode().strip()
                except:
                    banner = "No banner"
                with print_lock:
                    print(f"[+] Port {port} is open | Banner: {banner}")
    except Exception:
        pass


def threader(q, host):
    while True:
        port = q.get()
        scan_port(host, port)
        q.task_done()


def run(host: str, port_range: str):
    print(f"Starting port scan on {host} with range {port_range}")
    try:
        start_port, end_port = map(int, port_range.split('-'))
    except ValueError:
        print("Invalid port range format. Use start-end (e.g., 20-80).")
        return

    q = Queue()

    # Launch threads
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=threader, args=(q, host), daemon=True)
        t.start()

    # Queue ports
    for port in range(start_port, end_port + 1):
        q.put(port)

    q.join()
    print("Scan complete.")
