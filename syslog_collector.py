"""COLECTOR SYSLOG: recibe mensajes UDP, decodifica PRI (Facility/Severidad) y los almacena.

Uso:  python syslog_collector.py --port 5514
(El puerto estándar es 514/UDP y requiere privilegios; se usa 5514 para pruebas.)
"""
import argparse
import re
import socket
from datetime import datetime
from pathlib import Path

SEV = ["EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"]
FAC = {16: "local0", 17: "local1", 18: "local2", 19: "local3", 20: "local4",
       21: "local5", 22: "local6", 23: "local7", 4: "auth", 3: "daemon", 1: "user"}


def parse(line: str) -> dict:
    m = re.match(r"<(\d+)>(.*)", line)
    pri = int(m.group(1)) if m else 13
    mn = re.search(r"%(\w+)-(\d)-(\w+):", line)
    return {"pri": pri, "facility": FAC.get(pri // 8, str(pri // 8)), "severity": SEV[pri % 8],
            "mnemonic": mn.group(3) if mn else "-", "msg": m.group(2) if m else line}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--out", default="logs/collector.log")
    args = ap.parse_args()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    print(f"[COLECTOR] Escuchando syslog UDP en {args.host}:{args.port}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        line = data.decode("utf-8", "replace").strip()
        p = parse(line)
        out = (f"{datetime.now():%H:%M:%S} from={addr[0]} facility={p['facility']} "
               f"severity={p['severity']} mnemonic={p['mnemonic']} | {p['msg']}")
        print(out, flush=True)
        with open(args.out, "a", encoding="utf-8") as f:
            f.write(out + "\n")


if __name__ == "__main__":
    main()
