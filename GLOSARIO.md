# Glosario → Implementación

| Término | Dónde / cómo se aplica |
|---|---|
| Agente de IA | `agent.py` → `AIAgent` (sin herramientas, mínimo privilegio) |
| Motor de políticas | `policy_engine.py` → `PolicyEngine.evaluate()`; reglas en `policies.json` |
| Frontera de confianza | `pipeline.py`: entrada, contenido externo y salida del modelo se tratan como no confiables; `<datos_externos>` |
| Normalización | `normalizer.py`: NFKC, invisibles, base64, acentos, leetspeak. También el formato único de eventos de auditoría |
| Correlación | `correlation.py`: COR-001 (3 BLOCK/usuario) y COR-002 (varios usuarios, misma IP) |
| Auditoría | `audit.py`: cada decisión se registra (`logs/audit.jsonl` y `logs/syslog.log`) |
| Event ID | `EVT-AAAAMMDD-XXXXXXXX`, único por evento; los eventos relacionados usan `ref=` |
| Syslog | Mensajes RFC 3164 con `<PRI>`; envío UDP al colector |
| Colector Syslog | `syslog_collector.py` (UDP 5514; 514 en producción) |
| Severidad Syslog | 0–7; usamos 2 CRIT, 3 ERR, 4 WARNING, 5 NOTICE, 6 INFO |
| Facility | `local0` (16) configurable con `SYSLOG_FACILITY` |
| Mnemónico Syslog | `%AIGW-4-REQ_BLOCK`, `PROMPT_INJECTION`, `FAIL_SAFE`, etc. |
| ALLOW / BLOCK / REVIEW | Acciones del motor de políticas (BLOCK > REVIEW > ALLOW al combinar reglas) |
| Humano en el circuito | `review_queue.py` + `/aprobar` `/rechazar` |
| Falla segura | `pipeline._fail_safe()`: cualquier excepción => BLOCK sin respuesta |
| Prompt Injection | `detector.scan()` (PI-001…PI-008) |
| Prompt Injection Indirecta | `detector.scan(external=True)` (PI-101, PI-102) sobre documentos/web/correos |
