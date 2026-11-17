"""NORMALIZACIÓN: convierte cualquier entrada a una forma canónica antes de analizarla.

Evita evasiones (Unicode, caracteres invisibles, base64, leetspeak) y produce un
formato único que el detector y el motor de políticas pueden evaluar.
"""
import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u202a\u202b\u202c\u202d\u202e"), None)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


@dataclass
class Normalized:
    original: str
    text: str            # legible, limpio (se envía al agente)
    canonical: str       # minúsculas, sin acentos, sin leetspeak (se usa para detectar)
    flags: List[str] = field(default_factory=list)


def _try_b64(token: str) -> str:
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        decoded = raw.decode("utf-8")
    except Exception:
        return ""
    printable = sum(c.isprintable() or c.isspace() for c in decoded)
    return decoded if decoded and printable / len(decoded) > 0.9 else ""


def normalize(raw: str, max_len: int = 4000) -> Normalized:
    flags: List[str] = []
    if not isinstance(raw, str):
        raise TypeError("La entrada debe ser texto")
    text = unicodedata.normalize("NFKC", raw)
    if text.translate(ZERO_WIDTH) != text:
        flags.append("zero_width_removed")
        text = text.translate(ZERO_WIDTH)
    if CONTROL_RE.search(text):
        flags.append("control_chars_removed")
        text = CONTROL_RE.sub("", text)
    text = re.sub(r"[ \t]+", " ", text).strip()
    if len(text) > max_len:
        flags.append("truncated")
        text = text[:max_len]

    decoded_parts = [d for d in (_try_b64(t) for t in B64_RE.findall(text)) if d]
    if decoded_parts:
        flags.append("base64_decoded")
        text = text + "\n[decodificado] " + " | ".join(decoded_parts)

    folded = unicodedata.normalize("NFD", text.lower())
    folded = "".join(c for c in folded if unicodedata.category(c) != "Mn")
    canonical = re.sub(r"\s+", " ", folded.translate(LEET))
    return Normalized(original=raw, text=text, canonical=canonical, flags=flags)
