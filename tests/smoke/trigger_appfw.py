import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("198.51.100.44", 9999))
    s.send(b"SMOKE")
    print("CONNECTED 198.51.100.44:9999 — appfw intercepted (allowed once)")
except Exception as e:
    print(f"Connection result: {e}")
finally:
    s.close()
print("verify: tail -2 ~/greywatch/data/appfw/events.jsonl")
