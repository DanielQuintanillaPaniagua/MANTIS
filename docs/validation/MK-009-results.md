# MK-009 — Resultados de Validación Externa

| Laboratorio | Versión | Fecha | Entorno |
|---|---|---|---|
| OWASP crAPI | v1.x | (pendiente) | Docker local |
| VAmPI | v1.x | (pendiente) | Docker local |

---

## 1. Metodología

MANTIS se ejecutará contra instancias locales de crAPI y VAmPI, utilizando sus especificaciones OpenAPI y al menos dos identidades de prueba.

Cada escaneo se ejecutará con `--sequences` y con límites de seguridad para evitar operaciones destructivas sin restauración verificada.

## 2. Resultados en crAPI

| Vulnerabilidad conocida | Detectada | Estado MANTIS | Notas |
|---|---|---|---|
| BOLA en vehículos | ? | ? | Pendiente de ejecución |
| BFLA en mecánicos | ? | ? | Pendiente de ejecución |
| ... | ... | ... | ... |

## 3. Resultados en VAmPI

| Vulnerabilidad conocida | Detectada | Estado MANTIS | Notas |
|---|---|---|---|
| BOLA en usuarios | ? | ? | Pendiente de ejecución |
| ... | ... | ... | ... |

## 4. Limitaciones observadas

- (Documentar falsos positivos)
- (Documentar falsos negativos)
- (Documentar pruebas omitidas por falta de reset_endpoint)