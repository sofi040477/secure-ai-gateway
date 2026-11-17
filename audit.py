"""AUDITORÍA: cada decisión genera un evento con Event ID único, en formato Syslog.

Formato (estilo Cisco, con MNEMÓNICO):
  <PRI>Mmm dd hh:mm:ss HOST aigw[PID]: %AIGW-<SEVERIDAD>-<MNEMÓNICO>: EventID=... clave=valor ...
  PRI = Facility*8 + Severidad
"""
import datetime as dt
import json
import os
import socket
import uuid
from pathlib import Path
from typing import Optional, Tuple

FACILITIES = {"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
              "authpriv": 10, **{f"local{i}": 16 + i for i in range(8)}}
SEVERITIES = {0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERR", 4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"}

# Mnemónicos y severidad por defecto
MNEMONICS = {
    "REQ_ALLOW": 6, "REQ_REVIEW": 5, "REQ_BLOCK": 4,
    "PROMPT_INJECTION": 4, "PROMPT_INJECTION_INDIRECT": 4,
    "DLP_OUTPUT_REDACTED": 4, "REVIEW_APPROVED": 5, "REVIEW_REJECTED": 5,
    "CORRELATION_ALERT": 2, "FAIL_SAFE": 3,
}


class AuditError(Exception):
    pass


def _fmt(value) -> str:
    s = str(value)[:120]
    return json.dumps(s, ensure_ascii=False) if (not s or any(c in s for c in ' "=')) else s


class AuditLogger:
    def __init__(self, cfg):
        self.cfg = cfg
        self.facility = FACILITIES[cfg.facility]
        cfg.log_dir.mkdir(parents=True, exist_ok=True)
        self.syslog_path = cfg.log_dir / "syslog.log"
        self.jsonl_path = cfg.log_dir / "audit.jsonl"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if cfg.syslog_host else None

    @staticmethod
    def new_event_id() -> str:
        return f"EVT-{dt.datetime.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"

    def emit(self, mnemonic: str, event_id: Optional[str] = None,
             severity: Optional[int] = None, **fields) -> Tuple[str, str]:
        severity = MNEMONICS[mnemonic] if severity is None else severity
        event_id = event_id or self.new_event_id()
        now = dt.datetime.now()
        pri = self.facility * 8 + severity
        body = " ".join(f"{k}={_fmt(v)}" for k, v in fields.items())
        line = (f"<{pri}>{now:%b %d %H:%M:%S} {self.cfg.hostname} aigw[{os.getpid()}]: "
                f"%AIGW-{severity}-{mnemonic}: EventID={event_id} {body}").rstrip()
        record = {"ts": now.isoformat(timespec="seconds"), "event_id": event_id,
                  "facility": self.cfg.facility, "severity": severity,
                  "severity_name": SEVERITIES[severity], "mnemonic": mnemonic,
                  **{k: str(v)[:300] for k, v in fields.items()}}
        try:
            with open(self.syslog_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            raise AuditError(f"No se pudo escribir la auditoría: {exc}") from exc
        if self.sock:  # envío al colector: mejor esfuerzo (UDP); el log local es la fuente de verdad
            try:
                self.sock.sendto(line.encode("utf-8"), (self.cfg.syslog_host, self.cfg.syslog_port))
            except OSError:
                pass
        return event_id, line
