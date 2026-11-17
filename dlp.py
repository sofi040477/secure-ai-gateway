"""Prevención de fuga de datos (DLP): detecta y enmascara información sensible."""
import re
from typing import List, Tuple

# Token "canario" incrustado en el prompt del sistema: si aparece en una salida,
# el modelo está filtrando sus instrucciones internas.
CANARY = "CANARY-7F3A9C"

PATTERNS = {
    "api_key": re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})\b"),
    "credit_card": re.compile(r"\b\d(?:[ -]?\d){12,15}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "password_assignment": re.compile(r"(?i)\b(?:password|contrase[nñ]a|passwd|pwd)\s*[:=]\s*\S+"),
}


def _luhn(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_sensitive(text: str) -> List[str]:
    """Devuelve los tipos de dato sensible presentes (sin duplicados)."""
    kinds = []
    for kind, rx in PATTERNS.items():
        for m in rx.finditer(text):
            if kind == "credit_card" and not _luhn(m.group()):
                continue
            kinds.append(kind)
            break
    return kinds


def redact(text: str) -> Tuple[str, List[str]]:
    """Enmascara datos sensibles. Devuelve (texto_seguro, tipos_detectados)."""
    found: List[str] = []

    def make(kind):
        def _sub(m):
            if kind == "credit_card" and not _luhn(m.group()):
                return m.group()
            if kind not in found:
                found.append(kind)
            return f"[REDACTADO:{kind}]"
        return _sub

    for kind, rx in PATTERNS.items():
        text = rx.sub(make(kind), text)
    return text, found


def output_guard(text: str) -> Tuple[str, List[str]]:
    """Filtro de salida: canario + redacción de datos sensibles."""
    if CANARY in text:
        return "[RESPUESTA BLOQUEADA: posible fuga del prompt del sistema]", ["system_prompt_leak"]
    return redact(text)
