import json, os, pathlib, time
log = pathlib.Path.home() / "security-hardening" / "yara-scan.log"
line = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
        f"SMOKE: yara match rule=SmokeTest.YARA file=/tmp/smoke_payload.bin "
        f"logfile={log} process=/usr/bin/python3 pid={os.getpid()}")
print(line)
if os.geteuid() != 0:
    print("NEED SUDO — run: sudo python3 tests/smoke/inject_yara.py")
print("then: watch events.jsonl for a yara-watch HIGH/MEDIUM event within 5 s")
