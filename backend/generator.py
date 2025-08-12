#!/usr/bin/env python3
"""
Simple demo log generator for AttackReplay backend.
Write some sample attack lines into sample.log.
"""
import time
import random

SAMPLE_LOG = "sample.log"
LINES = [
    "Jan 10 12:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Jan 10 12:00:05 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
    "Jan 10 12:00:06 server apache[5678]: GET /index.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1",
    "Jan 10 12:00:08 server apache[5678]: GET /wp-admin HTTP/1.1",
    "Jan 10 12:00:10 server apache[5678]: GET /about.html HTTP/1.1",
    "Jan 10 12:00:12 server nmap[9999]: SYN Scan from 91.198.174.192 detected",
    "Jan 10 12:00:15 server sshd[1234]: Failed password for invalid user admin from 45.33.32.156 port 22 ssh2"
]

if __name__ == "__main__":
    print("Starting generator. Appending lines to sample.log every 1-2 seconds.")
    with open(SAMPLE_LOG, "a", encoding="utf-8") as f:
        while True:
            line = random.choice(LINES)
            f.write(line + "\n")
            f.flush()
            print("Wrote:", line)
            time.sleep(random.uniform(0.8, 2.2))
