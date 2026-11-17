# Arquitectura

```mermaid
flowchart TD
    U[Usuario / contenido externo] -->|NO CONFIABLE| FT{{Frontera de confianza}}
    FT --> N[Normalización]
    N --> D[Detector Prompt Injection<br/>directa + indirecta]
    D --> PE[Motor de políticas]
    PE -->|ALLOW| AG[Agente de IA<br/>mínimo privilegio]
    PE -->|REVIEW| HC[Humano en el circuito]
    PE -->|BLOCK| X[Rechazo]
    HC -->|aprueba| AG
    HC -->|rechaza| X
    AG --> OF[Filtro de salida DLP + canario]
    OF --> R[Respuesta]
    PE -.-> AU[(Auditoría: Event ID)]
    HC -.-> AU
    OF -.-> AU
    AU -->|Syslog UDP| CS[Colector Syslog]
    AU --> CO[Correlación]
    CO -->|lockout / alerta| PE
    ERR[[Cualquier error]] -->|FALLA SEGURA| X
```

## Fronteras de confianza
| Zona | Confianza | Control al cruzar |
|---|---|---|
| Entrada del usuario | No confiable | Normalización + detección + políticas |
| Documentos, web, correos (contenido externo) | No confiable | Detección de injection indirecta + delimitadores `<datos_externos>` |
| Salida del modelo | No confiable | Filtro DLP + token canario |
| `policies.json` | Confiable (controlada) | Validación de esquema; inválida => falla segura |

## Formato Syslog
```
<PRI>Mmm dd hh:mm:ss HOST aigw[PID]: %AIGW-<SEV>-<MNEMÓNICO>: EventID=EVT-... clave=valor
PRI = Facility * 8 + Severidad      (local0 = 16; WARNING = 4  =>  <132>)
```
| Mnemónico | Severidad | Cuándo |
|---|---|---|
| `REQ_ALLOW` | 6 INFO | Solicitud permitida |
| `REQ_REVIEW` / `REVIEW_APPROVED` / `REVIEW_REJECTED` | 5 NOTICE | Humano en el circuito |
| `REQ_BLOCK` / `PROMPT_INJECTION` / `PROMPT_INJECTION_INDIRECT` / `DLP_OUTPUT_REDACTED` | 4 WARNING | Bloqueo o detección |
| `FAIL_SAFE` | 3 ERR | Error interno => denegar |
| `CORRELATION_ALERT` | 2 CRIT | Patrón de ataque correlacionado |
