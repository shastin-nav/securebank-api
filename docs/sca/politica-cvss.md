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
| — | — | — | — | Sin CVE abiertos al momento de crear la política | — |

Cada vez que el reporte muestre un CVE en verde se agrega una fila aquí.

## 5. Evidencia

| Prueba | Rama | Resultado esperado | Run |
| :-- | :-- | :-- | :-- |
| Dependencia vulnerable a propósito: `urllib3==1.22` (CVE-2018-20060, CVSS 9.8) | `feat/sca-antes` | 🔴 `sca` falla, `package` no corre | _(pegar enlace del run)_ |
| Dependencias actuales del proyecto | `feat/s06-sca-sbom` | 🟢 `sca` pasa y genera los reportes | _(pegar enlace del run)_ |

La rama `feat/sca-antes` no se mergea nunca; solo existe para mostrar que el bloqueo funciona (igual que `feat/sast-antes` en la Sesión 5).

Los reportes del run verde se descargan del artefacto `sca-reports-<sha>` y se guardan en [`reports/`](../../reports/).

## 6. Cómo correrlo local

```bash
pip install --target sbom-env -r requirements.txt
trivy rootfs --scanners vuln --format json --output reports/trivy-vulns.json sbom-env
trivy rootfs --format cyclonedx --output reports/securebank-sbom.cdx.json sbom-env
python scripts/politica_cvss.py reports/trivy-vulns.json reports/securebank-vulns
```
