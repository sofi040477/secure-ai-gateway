"""Detector de PROMPT INJECTION (directa e indirecta) basado en reglas ponderadas."""
import re
from dataclasses import dataclass, field
from typing import List

from normalizer import Normalized

# (id, categoría, peso, regex sobre texto canónico)
_RULES = [
    ("PI-001", "override_instructions", 80,
     r"(ignor\w*|olvid\w*|omit\w*|desobedec\w*|disregard|forget)\s+(\w+\s+){0,3}"
     r"(instruccion\w*|reglas|indicacion\w*|instructions|rules|prompts?|guidelines)"),
    ("PI-002", "reveal_system_prompt", 80,
     r"(reveal|show|print|repeat|leak|muestra\w*|revela\w*|dime|imprime|repite)\s+(\w+\s+){0,4}"
     r"(system prompt|prompt del sistema|instrucciones del sistema|instrucciones iniciales|"
     r"hidden instructions|prompt original)"),
    ("PI-003", "role_hijack", 70,
     r"(developer mode|modo desarrollador|jailbreak|\bdan\b|do anything now|sin restricciones|sin filtros|unrestricted)"),
    ("PI-004", "role_change", 40,
     r"(a partir de ahora|you are now|ahora eres|pretend to be|finge ser|actua como|act as)\b"),
    ("PI-005", "bypass_safety", 70,
     r"(desactiva\w*|disable|bypass|saltate|evita|turn off)\s+(\w+\s+){0,3}"
     r"(seguridad|filtros?|restricciones|safety|guardrails|politicas|policies)"),
    ("PI-006", "credential_exfiltration", 70,
     r"(muestra\w*|dame|revela\w*|show|give|print|leak|envia\w*)\s+(\w+\s+){0,3}"
     r"(api[_ ]?keys?|contrasenas?|passwords?|tokens?|credenciales|secretos?)"),
    ("PI-007", "data_exfiltration_url", 60,
     r"(envia\w*|send|post|upload|sube|exfiltr\w*)\s+(\w+\s+){0,6}(a|to)\s+https?://"),
    ("PI-008", "fake_delimiters", 50,
     r"(<\|?(system|im_start|im_end)\|?>|\[/?inst\]|###\s*(system|instruction)|^system:)"),
]

# Reglas típicas de INJECTION INDIRECTA: instrucciones dirigidas a la IA escondidas
# dentro de documentos, páginas web, correos o resultados de herramientas.
_EXTERNAL_RULES = [
    ("PI-101", "instruction_to_ai", 50,
     r"(note to (the )?(ai|assistant|model)|dear (ai|assistant)|nota para (la ia|el asistente|el modelo)|"
     r"instruccion para (la ia|el asistente)|al asistente de ia|ai assistant[:,]|when you read this|cuando leas esto)"),
    ("PI-102", "hidden_markup", 40,
     r"(<!--.*?-->|display:\s*none|font-size:\s*0|color:\s*white)"),
]

COMPILED = [(i, c, w, re.compile(rx, re.S)) for i, c, w, rx in _RULES]
COMPILED_EXT = [(i, c, w, re.compile(rx, re.S)) for i, c, w, rx in _EXTERNAL_RULES]


@dataclass
class Scan:
    score: int = 0
    findings: List[dict] = field(default_factory=list)
    indirect: bool = False


def scan(norm: Normalized, external: bool = False) -> Scan:
    """Analiza un texto normalizado. external=True => contenido NO confiable (indirecta)."""
    rules = COMPILED + (COMPILED_EXT if external else [])
    result = Scan(indirect=external)
    for rule_id, category, weight, rx in rules:
        m = rx.search(norm.canonical)
        if m:
            result.findings.append({"rule": rule_id, "category": category,
                                    "weight": weight, "match": m.group()[:60]})
    if result.findings and "base64_decoded" in norm.flags:
        result.findings.append({"rule": "PI-900", "category": "obfuscated_payload",
                                "weight": 30, "match": "base64"})
    if result.findings and "zero_width_removed" in norm.flags:
        result.findings.append({"rule": "PI-901", "category": "invisible_chars",
                                "weight": 20, "match": "zero-width"})
    result.score = min(100, sum(f["weight"] for f in result.findings))
    return result
