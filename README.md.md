# 🛡️ Secure AI Gateway

Aplicación con Inteligencia Artificial **actualizada con controles y políticas de ciberseguridad**.
Proyecto de la asignatura **Cableado Estructurado**.

Toda solicitud al agente de IA pasa por: frontera de confianza → normalización → detección de
*Prompt Injection* (directa e indirecta) → **motor de políticas** (`ALLOW` / `BLOCK` / `REVIEW`) →
**humano en el circuito** → agente de IA → filtro de salida → **auditoría Syslog** (Event ID) → correlación.
Ante cualquier error el sistema aplica **falla segura** (BLOCK).

**Autora:** Sofía Céspedes López · Ing. en Redes de Telecomunicaciones

## Requisitos
Python 3.9 o superior. Sin dependencias externas.

## Uso
```bash
python demo.py --clean                      # 10 escenarios de seguridad
python main.py                              # CLI interactiva
python -m unittest discover -p "test_*.py" -v   # 15 pruebas automáticas
```
Para usar un modelo real: renombra `env.example` a `.env` y agrega `ANTHROPIC_API_KEY`. Sin clave funciona en modo simulado.

### Colector Syslog (2 terminales)
```bash
python syslog_collector.py --port 5514
SYSLOG_HOST=127.0.0.1 SYSLOG_PORT=5514 python demo.py --clean
```

### Comandos de la CLI
`/ext <texto>` (contenido externo) · `/file ruta | pregunta` · `/pendientes` · `/aprobar <ID>` · `/rechazar <ID>` · `/salir`

## Archivos
| Archivo | Función |
|---|---|
| `normalizer.py` | Normalización (Unicode, invisibles, base64, leetspeak) |
| `detector.py` | Prompt Injection directa e indirecta |
| `policy_engine.py` + `policies.json` | Motor de políticas ALLOW / REVIEW / BLOCK |
| `dlp.py` | Datos sensibles, filtro de salida, token canario |
| `audit.py` | Auditoría: Event ID + Syslog (facility, severidad, mnemónico) |
| `correlation.py` | Correlación de eventos y límite de solicitudes |
| `review_queue.py` | Humano en el circuito |
| `agent.py` | Agente de IA con mínimo privilegio |
| `pipeline.py` | Orquestación y falla segura |
| `syslog_collector.py` | Colector Syslog UDP |
| `main.py` · `demo.py` · `test_security.py` | CLI, demostración y pruebas |
| `ARQUITECTURA.md` · `POLITICAS.md` · `GLOSARIO.md` | Documentación |
| `evidencia_*.txt/.log` | Salidas reales de ejecución |

## Seguridad del repositorio
Las claves solo se leen de variables de entorno / `.env` (ignorado por Git). Los logs no se versionan.

> Los detectores por reglas reducen el riesgo pero no son infalibles; por eso se complementan con revisión humana, DLP de salida, mínimo privilegio y correlación.
