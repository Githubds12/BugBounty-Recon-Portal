#!/usr/bin/env python3
import socket
import sys
import threading
from queue import Queue

# Mimicking Naabu's Top 100 Ports
TOP_PORTS = [
    80, 443, 21, 22, 23, 25, 53, 110, 143, 445, 3389, 8080, 8443, 3306, 5432, 27017, 6379, 111, 135, 139, 161, 445, 514, 5900, 8000, 8888, 9000, 9200, 10000
]

def scan_port(host, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                results.append(f"{host}:{port}")
    except:
        pass

def worker(q, results):
    while not q.empty():
        host, port = q.get()
        scan_port(host, port, results)
        q.task_done()

def main():
    if "-list" in sys.argv:
        idx = sys.argv.index("-list")
        list_file = sys.argv[idx + 1]
        with open(list_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [arg for arg in sys.argv if not arg.startswith("-") and "." in arg]

    if not targets:
        print("Naabu v2.3.1-Python-Engine")
        sys.exit(0)

    q = Queue()
    results = []
    
    for t in targets:
        for p in TOP_PORTS:
            q.put((t, p))

    # Run 50 threads for speed
    for _ in range(50):
        t = threading.Thread(target=worker, args=(q, results))
        t.daemon = True
        t.start()

    q.join()
    
    for r in results:
        print(r)

if __name__ == "__main__":
    main()
