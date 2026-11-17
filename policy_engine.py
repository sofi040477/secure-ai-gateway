"""MOTOR DE POLÍTICAS: único punto que decide ALLOW / BLOCK / REVIEW.

Las reglas viven en policies.json (política como configuración, no como código).
Si el archivo es inválido o falta, se lanza PolicyError y el gateway aplica FALLA SEGURA.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from detector import Scan
from normalizer import Normalized

ALLOW, REVIEW, BLOCK = "ALLOW", "REVIEW", "BLOCK"
_RANK = {ALLOW: 0, REVIEW: 1, BLOCK: 2}

_REQUIRED = {
    "limits": ["max_prompt_chars", "max_external_chars", "rate_limit_requests", "rate_limit_window_s"],
    "thresholds": ["direct_block_score", "direct_review_score", "indirect_block_score", "indirect_review_score"],
    "dlp": ["review_on_input"],
    "sensitive_actions": ["review", "keywords"],
    "correlation": ["window_s", "block_threshold", "lockout_s", "ip_distinct_users"],
}


class PolicyError(Exception):
    pass


def load_policy(path: Path) -> dict:
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"Política ilegible: {exc}") from exc
    for section, keys in _REQUIRED.items():
        if not isinstance(policy.get(section), dict):
            raise PolicyError(f"Falta la sección '{section}'")
        for key in keys:
            if key not in policy[section]:
                raise PolicyError(f"Falta '{section}.{key}'")
    if policy.get("default_action") not in _RANK or policy.get("on_error") not in _RANK:
        raise PolicyError("default_action / on_error inválidos")
    return policy


@dataclass
class Context:
    prompt: Normalized
    prompt_scan: Scan
    external: Optional[Normalized] = None
    external_scan: Optional[Scan] = None
    sensitive_kinds: List[str] = field(default_factory=list)
    rate_exceeded: bool = False
    locked_out: bool = False


@dataclass
class Decision:
    action: str
    score: int
    rules: List[dict]

    @property
    def reasons(self) -> List[str]:
        return [f"{r['id']}: {r['reason']}" for r in self.rules]


class PolicyEngine:
    def __init__(self, policy: dict):
        self.policy = policy
        kws = policy["sensitive_actions"]["keywords"]
        self._action_rx = re.compile(r"\b(" + "|".join(re.escape(k) for k in kws) + r")\b", re.I)

    @classmethod
    def from_file(cls, path: Path) -> "PolicyEngine":
        return cls(load_policy(path))

    def evaluate(self, ctx: Context) -> Decision:
        p, t = self.policy, self.policy["thresholds"]
        hits: List[dict] = []

        def hit(rule_id, action, reason):
            hits.append({"id": rule_id, "action": action, "reason": reason})

        if ctx.locked_out:
            hit("POL-002", BLOCK, "Usuario/IP bloqueado temporalmente por correlación de eventos")
        if ctx.rate_exceeded:
            hit("POL-001", BLOCK, "Límite de solicitudes por ventana de tiempo excedido")

        s = ctx.prompt_scan.score
        cats = ",".join(sorted({f["category"] for f in ctx.prompt_scan.findings}))
        if s >= t["direct_block_score"]:
            hit("POL-003", BLOCK, f"Prompt Injection directa (score={s}; {cats})")
        elif s >= t["direct_review_score"]:
            hit("POL-004", REVIEW, f"Entrada sospechosa (score={s}; {cats})")

        if ctx.external_scan is not None:
            e = ctx.external_scan.score
            ecats = ",".join(sorted({f["category"] for f in ctx.external_scan.findings}))
            if e >= t["indirect_block_score"]:
                hit("POL-005", BLOCK, f"Prompt Injection INDIRECTA en contenido externo (score={e}; {ecats})")
            elif e >= t["indirect_review_score"]:
                hit("POL-006", REVIEW, f"Contenido externo sospechoso (score={e}; {ecats})")

        risky = [k for k in ctx.sensitive_kinds if k in p["dlp"]["review_on_input"]]
        if risky:
            hit("POL-007", REVIEW, f"Dato sensible en la entrada ({','.join(risky)})")

        if p["sensitive_actions"]["review"]:
            m = self._action_rx.search(ctx.prompt.canonical)
            if m:
                hit("POL-008", REVIEW, f"Acción sensible solicitada ('{m.group(1)}')")

        if "truncated" in ctx.prompt.flags:
            hit("POL-009", REVIEW, "Entrada excede el tamaño máximo y fue truncada")

        if not hits:
            hit("POL-099", p["default_action"], "Sin hallazgos: acción por defecto")

        final = max((h["action"] for h in hits), key=_RANK.get)
        score = max(ctx.prompt_scan.score, ctx.external_scan.score if ctx.external_scan else 0)
        return Decision(action=final, score=score, rules=hits)
