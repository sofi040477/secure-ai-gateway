"""CORRELACIÓN de eventos (por usuario / IP) y limitador de tasa."""
import time
from collections import defaultdict, deque
from typing import Callable, Optional


class RateLimiter:
    def __init__(self, now: Callable[[], float] = time.time):
        self.now = now
        self.hits = defaultdict(deque)

    def hit(self, key: str, limit: int, window: int) -> bool:
        """Registra una solicitud. True si se excedió el límite."""
        t, q = self.now(), self.hits[key]
        while q and t - q[0] > window:
            q.popleft()
        q.append(t)
        return len(q) > limit


class Correlator:
    """Relaciona eventos aislados para detectar ataques que una sola regla no ve.

    R1: >= N BLOCK del mismo usuario en la ventana  -> bloqueo temporal (lockout).
    R2: BLOCK de >= M usuarios distintos desde la misma IP -> alerta crítica (ataque distribuido/compartido).
    """

    def __init__(self, cfg: dict, now: Callable[[], float] = time.time):
        self.cfg, self.now = cfg, now
        self.user_blocks = defaultdict(deque)
        self.ip_blocks = defaultdict(deque)   # (ts, user)
        self.locked = {}                      # user -> expira

    def is_locked(self, user: str) -> bool:
        until = self.locked.get(user)
        if until and self.now() < until:
            return True
        self.locked.pop(user, None)
        return False

    def record(self, user: str, ip: str, action: str) -> Optional[dict]:
        if action != "BLOCK":
            return None
        c, t = self.cfg, self.now()
        q = self.user_blocks[user]
        q.append(t)
        while q and t - q[0] > c["window_s"]:
            q.popleft()
        iq = self.ip_blocks[ip]
        iq.append((t, user))
        while iq and t - iq[0][0] > c["window_s"]:
            iq.popleft()

        if len(q) >= c["block_threshold"] and not self.is_locked(user):
            self.locked[user] = t + c["lockout_s"]
            return {"rule": "COR-001", "user": user, "ip": ip, "blocks": len(q),
                    "window_s": c["window_s"], "action": f"lockout {c['lockout_s']}s"}
        users = {u for _, u in iq}
        if len(users) >= c["ip_distinct_users"]:
            iq.clear()
            return {"rule": "COR-002", "user": user, "ip": ip, "blocks": len(users),
                    "window_s": c["window_s"], "action": "alert_only"}
        return None
