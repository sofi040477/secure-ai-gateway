"""Configuración centralizada. Los secretos SOLO se leen de variables de entorno (.env)."""
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """Cargador mínimo de .env (sin dependencias externas)."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass
class Config:
    log_dir: Path
    policy_file: Path
    syslog_host: Optional[str]
    syslog_port: int
    facility: str
    hostname: str
    api_key: Optional[str]
    model: str

    @classmethod
    def from_env(cls, **overrides) -> "Config":
        _load_dotenv(BASE_DIR / ".env")
        cfg = cls(
            log_dir=Path(os.getenv("LOG_DIR", BASE_DIR / "logs")),
            policy_file=Path(os.getenv("POLICY_FILE", BASE_DIR / "policies.json")),
            syslog_host=os.getenv("SYSLOG_HOST") or None,
            syslog_port=int(os.getenv("SYSLOG_PORT", "5514")),
            facility=os.getenv("SYSLOG_FACILITY", "local0"),
            hostname=os.getenv("HOSTNAME_OVERRIDE", socket.gethostname()),
            api_key=os.getenv("ANTHROPIC_API_KEY") or None,
            model=os.getenv("AI_MODEL", "claude-sonnet-5-5"),
        )
        for key, value in overrides.items():
            setattr(cfg, key, value)
        return cfg
