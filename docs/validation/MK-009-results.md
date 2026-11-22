# MK-009 — Resultados de Validación Externa

| Laboratorio | Versión | Fecha | Entorno | Estado |
|---|---|---|---|---|
| OWASP crAPI | v1.x | (pendiente) | Docker local | ⏳ Pendiente |
| VAmPI | v1.x | (pendiente) | Docker local | ⏳ Pendiente |

---

## ⚠️ Estado Actual

**Este documento es una plantilla. La validación externa aún no se ha ejecutado.**

Para ejecutar las pruebas:
1. Levantar crAPI y VAmPI en Docker.
2. Obtener sus especificaciones OpenAPI.
3. Ejecutar `mantis scan <spec> --identity admin:key --identity user:key --sequences`.
4. Rellenar la tabla de resultados a continuación.

---

## 1. Metodología (planificada)

MANTIS se ejecutará contra instancias locales de crAPI y VAmPI, utilizando sus especificaciones OpenAPI y al menos dos identidades de prueba.
Cada escaneo se ejecutará con `--sequences` y con límites de seguridad para evitar operaciones destructivas sin restauración verificada.

## 2. Resultados en crAPI

| Vulnerabilidad conocida | Detectada | Estado MANTIS | Notas |
|---|---|---|---|
| BOLA en vehículos | - | Pendiente | - |
| BFLA en mecánicos | - | Pendiente | - |

## 3. Resultados en VAmPI

| Vulnerabilidad conocida | Detectada | Estado MANTIS | Notas |
|---|---|---|---|
| BOLA en usuarios | - | Pendiente | - |

## 4. Limitaciones observadas

*(Se documentarán tras la ejecución)*
- Posibles falsos positivos.
- Pruebas omitidas por falta de reset.
