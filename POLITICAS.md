# Políticas de ciberseguridad implementadas

| ID | Política | Acción | Implementación |
|---|---|---|---|
| POL-001 | Límite de solicitudes (10/min por usuario) | BLOCK | `correlation.RateLimiter` |
| POL-002 | Bloqueo temporal por correlación (3 BLOCK / 5 min => 5 min) | BLOCK | `correlation.Correlator` |
| POL-003 | Prompt Injection directa (score ≥ 70) | BLOCK | `detector` + `policy_engine` |
| POL-004 | Entrada sospechosa (30 ≤ score < 70) | REVIEW | `policy_engine` |
| POL-005 | Prompt Injection **indirecta** en contenido externo (≥ 60) | BLOCK | `detector.scan(external=True)` |
| POL-006 | Contenido externo sospechoso (30–59) | REVIEW | `policy_engine` |
| POL-007 | Datos sensibles en la entrada (API key, tarjeta con Luhn, contraseña) | REVIEW | `dlp.find_sensitive` |
| POL-008 | Acciones sensibles (borrar, transferir, ejecutar…) | REVIEW | `policies.json` |
| POL-009 | Entrada demasiado larga (truncada) | REVIEW | `normalizer` |
| POL-099 | Sin hallazgos | ALLOW | `default_action` |
| FAIL-SAFE | Política ilegible, error del agente, timeout o fallo de auditoría | BLOCK | `pipeline._fail_safe` |

## Principios transversales
1. **Mínimo privilegio**: el agente no tiene herramientas (`allowed_tools = ()`), ni acceso a archivos o red propios.
2. **Validación de entradas y salidas**: normalización de entrada; filtro DLP y token canario en la salida.
3. **Gestión de secretos**: API key solo por variable de entorno; `.env` y `logs/` en `.gitignore`.
4. **Auditoría obligatoria**: sin registro de auditoría no se entrega respuesta (falla segura).
5. **Datos como datos**: el contenido externo se encapsula en `<datos_externos>` y el prompt del sistema ordena no obedecerlo.
6. **Humano en el circuito** para decisiones ambiguas o de alto impacto.
7. **Mínima exposición en logs**: la entrada se registra truncada (80 caracteres) y con datos sensibles enmascarados.
8. **Política como configuración**: `policies.json` validado al iniciar.
