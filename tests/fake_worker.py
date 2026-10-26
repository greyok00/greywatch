import os
import socket
import sys
import time

n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
events = os.environ["NFQ_EVENTS_PATH"].encode()
control_path = os.environ["NFQ_CONTROL_PATH"]

ctl = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
ctl.bind(control_path)
ctl.settimeout(3)
out = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

targets = [("93.184.216.34", 443), ("140.82.121.4", 443),
           ("151.101.0.50", 443), ("192.168.77.9", 22)]
sent = 0
for i in range(n):
    dst, dport = targets[i % len(targets)]
    out.sendto(f"PKT {9000+i} tcp 127.0.0.1 {40000+i} {dst} {dport}".encode(),
               events)
    sent += 1
    try:
        line, _ = ctl.recvfrom(128)
    except socket.timeout:
        for f in (ctl, out):
            f.close()
        print("TIMEOUT-waiting-verdict", flush=True)
        sys.exit(1)                                  # never hang a suite
    verb = line.decode().split()[0]
    print(f"VERDICT {9000+i} {verb}", flush=True)
    time.sleep(0.05)
print(f"DONE {sent}")
