# Sesión 6 · SCA, SBOM y política de umbrales CVSS

**Proyecto:** SecureBank API · **Versión:** 1.0 · **Fecha:** 02-11-2026

## 1. Qué se agregó al pipeline

```
build ─┬─► unit-tests ──► sast ─────────────────┐
       └─► sca (Trivy + SBOM + semáforo) ──► [aprobacion-seguridad] ──► package
```

El job `sca` corre en paralelo a las pruebas y hace cuatro cosas:

1. Instala las dependencias de producción (`requirements.txt`) en una carpeta aparte (`sbom-env/`). Así Trivy ve también las dependencias transitivas (Jinja2, click, MarkupSafe, itsdangerous, blinker), que no aparecen en el `requirements.txt`.
2. Escanea esa carpeta con **Trivy** y genera el listado de CVE conocidos (`trivy-vulns.json`).
3. Genera el **SBOM** en dos formatos estándar: CycloneDX (`securebank-sbom.cdx.json`) y SPDX (`securebank-sbom.spdx.json`).
4. Aplica el **semáforo CVSS** con `scripts/politica_cvss.py` y deja el reporte de componentes vulnerables en `securebank-vulns.html` y `securebank-vulns.json`.

Todo queda como artefacto `sca-reports-<sha>` (7 días), incluso cuando el pipeline falla.

## 2. Política de umbrales (semáforo)

| CVSS | Color | Qué pasa en el pipeline | Responsable |
| :-- | :-- | :-- | :-- |
| ≥ 9.0 (crítico) | 🔴 Rojo | El job `sca` falla y **no se empaqueta**. Hay que actualizar la dependencia. | Quien abrió el PR |
| 7.0 a 8.9 (alto) | 🟡 Amarillo | El pipeline **queda en pausa** en el job `aprobacion-seguridad` hasta que un revisor apruebe en GitHub. | Líder técnico |
| < 7.0 (medio/bajo) | 🟢 Verde | Continúa. El CVE se anota en el backlog de deuda de seguridad (sección 4). | Equipo, próximo sprint |

**De dónde sale el puntaje:** se usa el CVSS v3 de NVD; si no existe, el de GitHub Advisory (GHSA); si no hay ninguno, CVSS v4; y si Trivy no trae puntaje, se usa el piso de su severidad (CRITICAL = 9.0, HIGH = 7.0, MEDIUM = 4.0).

**Por qué estos cortes:** 9.0 es donde empieza "crítico" en CVSS v3.1, normalmente explotable por red y sin autenticación. Para una API bancaria eso no se negocia. Entre 7.0 y 8.9 a veces la parte vulnerable de la librería no la usamos, así que tiene sentido que una persona lo evalúe en vez de bloquear a ciegas.

## 3. Cómo se configura la aprobación

El job `aprobacion-seguridad` usa el environment de GitHub del mismo nombre. Para que de verdad pida aprobación:

`Settings → Environments → New environment → aprobacion-seguridad → Required reviewers` → agregar al líder técnico (@shastin-nav).

Sin esa configuración GitHub crea el environment vacío y el job pasa solo, así que este paso es obligatorio.

## 4. Backlog de deuda de seguridad (CVSS < 7.0)

| Fecha | CVE | Componente | CVSS | Decisión | Estado |
| :-- | :-- | :-- | :-: | :-- | :-- |
| 02-11-2026 | CVE-2026-102598 (GHSA-g6x2-hccm-hh4m) · `safe_join()` acepta nombres de dispositivo de Windows | Werkzeug 3.1.8 | Moderado (CVSS 4.0) | Verde: iba al backlog, pero el arreglo era un parche menor y se aplicó junto con PyJWT | ✅ Cerrado: Werkzeug 3.1.9 |

Cada vez que el reporte muestre un CVE en verde se agrega una fila aquí.

## 5. Evidencia

**Primer hallazgo real.** El primer run del job `sca` en esta rama **bloqueó el pipeline** sin que lo forzáramos: la versión de PyJWT que usábamos (la librería que firma los JWT de la API) tenía un CVE crítico.

| Fecha | CVE | Componente | CVSS | Semáforo | Acción |
| :-- | :-- | :-- | :-: | :-- | :-- |
| 02-11-2026 | CVE-2026-102268 (GHSA-ffc3-869f-jxw9) · se salta la detección de llaves PEM asimétricas | PyJWT 2.12.1 | 9.1 | 🔴 Bloqueo | Actualizado a PyJWT 2.15.1. Run bloqueado: https://github.com/shastin-nav/securebank-api/actions/runs/41526668771 |
| 02-11-2026 | Otros 15 avisos de PyJWT 2.12.1 (altos y moderados, casi todos en `PyJWKClient`) | PyJWT 2.12.1 | 3.7 a 7.4 | 🟡 / 🟢 | Se cierran con la misma actualización |

Antes de subir el cambio se corrieron las 41 pruebas con PyJWT 2.15.1 y Werkzeug 3.1.9 (todas pasan) y se revisó en OSV que esas versiones no tengan CVE conocidos.

La API usa HS256 con una clave secreta y no carga llaves PEM, así que en la práctica no estaba expuesta a este CVE. Igual se actualizó: la política no hace excepciones por "no nos afecta" sin una aprobación registrada, y el cambio no rompía nada.

| Prueba | Rama | Resultado esperado | Run |
| :-- | :-- | :-- | :-- |
| Dependencia vulnerable a propósito: `urllib3==1.22` (CVE-2018-20060, CVSS 9.8) | `feat/sca-antes` | 🔴 `sca` falla, `package` no corre | https://github.com/shastin-nav/securebank-api/actions/runs/41527686580 |
| Dependencias originales (PyJWT 2.12.1) | `feat/s06-sca-sbom` | 🔴 Bloqueado por un CVE real (ver arriba) | https://github.com/shastin-nav/securebank-api/actions/runs/41526668771 |
| Dependencias actualizadas (PyJWT 2.15.1, Werkzeug 3.1.9) | `feat/s06-sca-sbom` | 🟢 `sca` pasa y genera los reportes | https://github.com/shastin-nav/securebank-api/actions/runs/41527686266 |

La rama `feat/sca-antes` no se mergea nunca; solo existe para mostrar que el bloqueo funciona (igual que `feat/sast-antes` en la Sesión 5).

Los reportes del run verde (commit `c77af54`) están en [`reports/`](../../reports/): SBOM CycloneDX 1.6 y SPDX 2.3 con 10 componentes (Flask, Werkzeug, PyJWT, gunicorn y sus 6 dependencias transitivas) y el reporte de vulnerabilidades en estado **APROBADO**, con 0 CVE conocidos.

## 6. Cómo correrlo local

```bash
pip install --target sbom-env -r requirements.txt
trivy rootfs --scanners vuln --format json --output reports/trivy-vulns.json sbom-env
trivy rootfs --format cyclonedx --output reports/securebank-sbom.cdx.json sbom-env
python scripts/politica_cvss.py reports/trivy-vulns.json reports/securebank-vulns
```
