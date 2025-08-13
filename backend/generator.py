import time
import random
import os
from datetime import datetime

SAMPLE_LOG = "sample.log"
LINES = [
    "Failed password for root from 192.168.1.100 port 22 ssh2",
    "Failed password for root from 10.0.0.5 port 22 ssh2",
    "GET /index.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1",
    "GET /wp-admin HTTP/1.1",
    "GET /about.html HTTP/1.1",
    "SYN Scan from 91.198.174.192 detected",
    "Failed password for invalid user admin from 45.33.32.156 port 22 ssh2"
]

if __name__ == "__main__":
    print("Starting log generator...")
    if not os.path.exists(SAMPLE_LOG):
        open(SAMPLE_LOG, "w").close()

    with open(SAMPLE_LOG, "a", encoding="utf-8") as f:
        while True:
            line = random.choice(LINES)
            timestamp = datetime.now().strftime("%b %d %H:%M:%S")
            full_line = f"{timestamp} server {line}"
            f.write(full_line + "\n")
            f.flush()
            print("Generated:", full_line)
            time.sleep(random.uniform(1.0, 3.0))