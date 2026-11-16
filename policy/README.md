# Sesión 9 · Security Quality Gate y Policy as Code — Security Policy v1.0

**Proyecto:** SecureBank API · SecurePipeline · **Versión:** 1.0 · **Fecha:** 16-11-2026
**Grupo:** Benjamín Garrido · Abdiel Ortiz · Justin Navarro · Emilio Santibáñez

Hasta la Sesión 8 el pipeline solo producía reportes. Desde ahora **decide**: el job `security-gate` junta los reportes de todos los scanners en un `findings.json` y OPA evalúa [`security-policy-v1.rego`](security-policy-v1.rego). Si hay al menos un motivo de bloqueo, el pipeline falla y no se empaqueta ni se publica nada.

```
Secret Scan ─┐
SAST ────────┤
SCA ─────────┼──► findings.json ──► OPA · security-policy-v1.rego ──► ALLOW → package → publish
Imagen ──────┤    (scripts/consolidar_findings.py)                 └─► BLOCK → exit 1, PR rechazado
DAST ────────┤
Coverage ────┘
```

## Archivos

| Archivo | Qué es |
| :-- | :-- |
| [`security-policy-v1.rego`](security-policy-v1.rego) | La política. `allow` solo si `deny` está vacío. Cada regla devuelve un mensaje legible. |
| [`security-policy-v1_test.rego`](security-policy-v1_test.rego) | 19 pruebas automáticas: casos verdes (deben pasar) y rojos (deben bloquear). |
| [`context.json`](context.json) | Metadatos de negocio versionados: criticidad, exposición y mitigaciones. Alimentan el criterio de riesgo. |
| [`examples/`](examples/) | `findings-verde.json` y `findings-rojo.json` para probar la política a mano. |
| [`../scripts/consolidar_findings.py`](../scripts/consolidar_findings.py) | Normaliza Gitleaks, Semgrep, Trivy, ZAP y Cobertura a un único JSON. |

## Umbrales y justificación

| # | Regla | Umbral | Scanner | Justificación |
| :-: | :-- | :-- | :-- | :-- |
| 0 | Todos los controles corrieron | 6 de 6 reportes presentes | todos | Un control que no corrió no puede contarse como aprobado. Si un job falla o se salta, su reporte falta y el gate bloquea con el motivo exacto. **Auditabilidad.** |
| 1 | No secrets | `secrets.total = 0` | Gitleaks | Un secreto en el historial es un incidente: no hay deuda aceptable (Sesión 7). |
| 2 | Critical | `= 0` en SAST, SCA e imagen | Semgrep, Trivy | CVSS ≥ 9: normalmente explotable por red y sin autenticación. En una API bancaria no se negocia. |
| 3a | SAST High | `= 0` | Semgrep | Un High en **nuestro** código siempre lo podemos corregir nosotros. Mismo criterio del gate de la Sesión 5. |
| 3b | SCA High | `≤ 2` | Trivy (dependencias) | Deuda controlada (lámina 7). A veces la parte vulnerable de la librería no se usa; además, los CVSS 7.0–8.9 siguen pasando por el environment `aprobacion-seguridad` (Sesión 6). |
| 3c | Imagen High con parche | `fixable_high ≤ 2` | Trivy (imagen v2) | Solo cuentan los CVE que **ya tienen versión corregida**. Los de la imagen base sin parche de Debian se reportan pero no bloquean: no son accionables (criterio de *exploitability*). |
| 3d | DAST High | `= 0` | ZAP | Un High de DAST es explotable sobre la app en ejecución. |
| 4 | SCA Medium | `≤ 10` | Trivy | Evita acumular deuda silenciosa; sobre 10 se exige limpieza antes del merge. |
| 5 | **Criterio de riesgo:** DAST Medium | `= 0` si `exposure_level = internet` y `business_criticality = alta`; `≤ 2` en otro caso | ZAP + `context.json` | La misma alerta pesa distinto en una API financiera pública que en un servicio interno (lámina 14: *contexto del negocio × exposición*). SecureBank está en el peor cuadrante. |
| 6 | Coverage | `≥ 80 %` de líneas | pytest-cov | Calidad = seguridad: sin pruebas, cualquier fix futuro es incierto. Hoy está en ~98 %. |

**Mapeo de severidades de Semgrep:** `error` → High (Critical si la regla trae `security-severity ≥ 9.0`), `warning` → Medium, `note` → Low.

Los umbrales están en un solo bloque (`umbral := {...}`) al inicio de la política. Cambiarlos exige un PR con revisión de CODEOWNERS: cada build evalúa la versión exacta de la política de su commit.

## Pruebas: un caso que pasa y uno que bloquea

```bash
opa test policy/security-policy-v1.rego policy/security-policy-v1_test.rego -v   # PASS: 19/19

opa eval -d policy/security-policy-v1.rego -i policy/examples/findings-verde.json 'data.securepipeline.gate.decision' --format pretty
# { "allow": true, "deny": [], ... }

opa eval -d policy/security-policy-v1.rego -i policy/examples/findings-rojo.json 'data.securepipeline.gate.decision' --format pretty
# { "allow": false, "deny": [
#     "Coverage: 72.50% · mínimo 80%",
#     "DAST Medium: 1 · máximo 0 (exposure_level=internet, business_criticality=alta)",
#     "SCA High: 4 · máximo 2",
#     "Secret scan: 1 secreto(s) detectado(s) · máximo 0" ] }
```

En el pipeline, las pruebas de la política corren **antes** de usarla: si alguien rompe una regla, el gate falla aunque los scanners estén limpios.

## Evidencia auditable por build

El artefacto `security-gate-<sha>` guarda `findings.json` (con commit, ref, run y fecha) y `gate-decision.json` (decisión + motivos). La decisión también queda en el resumen del run.

## Caso de discusión: "el producto crítico sale mañana" (0 Critical · 3 High · 12 Medium)

Con esta política el deploy **se bloquea**: si los 3 High son de dependencias superan el máximo de 2, y si alguno es de SAST o DAST basta uno solo. Los 12 Medium también bloquean si son de SCA (máximo 10) y, con que uno sea de DAST, por el criterio de exposición. La salida que da la política no es saltarse el gate, es corregir o documentar: actualizar una dependencia baja de 3 a 2 High, y si un High no aplica a nuestro uso, el camino es un PR que lo justifique y quede en el historial. Así no hay excepciones manuales que se vuelvan jurisprudencia interna.
