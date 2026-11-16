# Sesión 8 · DAST y seguridad de APIs — Reporte DAST y plan de mitigación

**Proyecto:** SecureBank API · SecurePipeline · **Versión:** 1.0 · **Fecha:** 16-11-2026
**Entrega al aula virtual:** exportar este documento a `reporte-dast-<grupo>.pdf` con las capturas del reporte HTML del run.

## Sección 1 · Reporte DAST

### 1.1 Cómo se ejecuta

El job `dast` del pipeline (`.github/workflows/ci.yml`) levanta la **misma imagen que se publica** (`securebank:v2-secure`) con `docker compose` y le corre el ZAP Baseline Scan:

```bash
SECUREBANK_JWT_SECRET="$(openssl rand -hex 32)" SECUREBANK_IMAGE=securebank:v2-secure \
  docker compose up -d --no-build --wait            # http://localhost:8080 → {"status":"ok"}

docker run --rm --network=host -v "$PWD/zap-out:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "http://localhost:8080/bienvenida?name=cliente" -c rules.tsv -I \
  -r zap-report.html -J zap-report.json -w zap-report.md

docker compose down -v
```

- **Versión de ZAP y timestamp** (requisito 3), del run [43973218491](https://github.com/shastin-nav/securebank-api/actions/runs/43973218491) de `main` (commit `68c47a0`): ZAP **2.17.0**, imagen `ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af`, inicio del scan **2026-11-16T22:49:57Z**. El log del job imprime ambos datos en cada run.
- **`report.json` adjunto** (requisito 4): [`reports/dast/zap-report.json`](../../reports/dast/zap-report.json) es el de ese run. En cada run queda además en el artefacto `dast-report-<sha>` y es la entrada del security gate de la Sesión 9.
- [`.zap/rules.tsv`](../../.zap/rules.tsv): las alertas ya corregidas están en `FAIL`. Si una cabecera vuelve a faltar, el job falla como **regresión**. El resto de las severidades las decide el gate.

### 1.2 Tabla de hallazgos (estado inicial, `main` antes de este PR)

Las respuestas de la API en `main` solo traían `Content-Type` y `Content-Length` (verificado con el cliente de pruebas de Flask sobre el commit `9d84f01`), y los errores 404/405 devolvían la página HTML por defecto de Werkzeug.

| Severidad ZAP | CWE | ID ZAP | URL | Hallazgo | Evidencia |
| :-- | :-- | :-- | :-- | :-- | :-- |
| Medium | CWE-693 | 10038 | `/bienvenida`, `/health`, todas | Content-Security-Policy ausente | Respuesta sin cabecera `Content-Security-Policy` |
| Medium | CWE-1021 | 10020 | `/bienvenida` | Anti-clickjacking ausente | Sin `X-Frame-Options` ni `frame-ancestors` |
| Low | CWE-693 | 10021 | todas | `X-Content-Type-Options` ausente | Sin `nosniff` |
| Low | CWE-693 | 10063 | todas | Permissions-Policy ausente | — |
| Low | CWE-693 | 90004 | todas | Spectre / site isolation (CORP) | Sin `Cross-Origin-Resource-Policy` |
| Informational | CWE-525 | 10049 | `/accounts`, `/health` | Contenido almacenable en caché | Sin `Cache-Control: no-store` en datos bancarios |
| Low | CWE-209 | — | `/admin`, `/actuator` | Errores con HTML del framework | 404 con `<!doctype html>… Not Found` de Werkzeug |
| (manual) | CWE-639 | — | `/accounts/{id}`, `/transfer` | BOLA (ejercicio guiado) | Corregido en Sesiones 3 y 5: ownership check; ver 1.4 |

No aplican en SecureBank: **cookies inseguras** (la API no usa cookies; el JWT viaja en `Authorization`) y **CORS permisivo** (no se envía `Access-Control-Allow-Origin`; hay test que lo garantiza). HSTS (10035) solo lo evalúa ZAP sobre HTTPS; en el scan por HTTP se ignora y se valida con test unitario.

### 1.3 Resultado después de la corrección

Run 43973218491 de `main`: `FAIL-NEW: 0 · WARN-NEW: 2 · PASS: 66`.

| Riesgo | Cantidad de alertas |
| :-- | --: |
| High | 0 |
| Medium | 0 |
| Low | 1 |
| Informational | 1 |

Alertas restantes (son solo dos, no hay top 3):

| Severidad ZAP | CWE | ID ZAP | URL | Hallazgo | Decisión |
| :-- | :-- | :-- | :-- | :-- | :-- |
| Low | CWE-693 | 90004 | `/bienvenida` (1) | `Cross-Origin-Embedder-Policy` ausente o inválida | Backlog. La API no incrusta recursos de otros orígenes; ya envía CORP y COOP `same-origin`. |
| Informational | CWE-524 | 10049 | 4 URLs | Contenido no almacenable en caché | Es el efecto buscado de `Cache-Control: no-store`. No se corrige. |

Criterio del gate (Sesión 9): **0 High y 0 Medium**, porque SecureBank es una API financiera expuesta a Internet (`policy/context.json`). El gate de este run respondió `allow: true`.

> Capturas pendientes: dashboard del reporte HTML (`zap-report.html` del artefacto `dast-report-<sha>`). Se agregan al exportar el PDF.

### 1.4 Ejercicio BOLA

En SecureBank no existe `GET /users/{id}`: el perfil se obtiene en `GET /users/me` con el `sub` del JWT, así que el id del path no se puede manipular. El caso equivalente son las cuentas (`/accounts/{id}`, `/accounts/{id}/movements`) y `/transfer`, donde el backend verifica `owner_id == g.user["id"]` (o rol admin) y registra el intento en el log (`accounts.can_access`, `transfers.transfer`). Los tests de `tests/unit/test_dast.py::TestBOLA` envían el id de otro usuario y esperan **403** (refuerzo 4 de la lámina).

## Sección 2 · Plan de mitigación (hallazgos High/Medium)

| Hallazgo | Acción correctiva | Verificación | Responsable | Plazo | Estado |
| :-- | :-- | :-- | :-- | :-- | :-- |
| **CSP ausente** (10038) | Cabecera `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` en un `after_request` central (equivalente a `helmet()`): `src/securebank/app.py` | Re-scan ZAP sin 10038 (regla `FAIL`) + `test_todas_las_respuestas_traen_las_cabeceras` | Backend team | Sprint 1 | ✅ Corregido |
| **Clickjacking** (10020) | `X-Frame-Options: DENY` + `frame-ancestors 'none'` | Re-scan ZAP sin 10020 + `test_csp_no_permite_scripts_ni_frames` | Backend team | Sprint 1 | ✅ Corregido |
| **Cabeceras Low** (10021, 10063, 90004, HSTS) | `nosniff`, `Permissions-Policy`, `CORP/COOP same-origin`, `Strict-Transport-Security` | Re-scan ZAP + test de cabeceras | Backend team | Sprint 1 | ✅ Corregido |
| **Caché de datos bancarios** (10049) | `Cache-Control: no-store` en todas las respuestas | `test_respuestas_autenticadas_no_se_cachean` | Backend team | Sprint 1 | ✅ Corregido |
| **Errores verbosos** | Manejadores 404/405/413/500 que devuelven JSON sin detalles internos | `TestErroresSinDetalles` | Backend team | Sprint 1 | ✅ Corregido |
| **BOLA** `/accounts/{id}` | Ownership check en el backend + log de intentos | `TestBOLA` (id ajeno → 403) | Backend team | Sesión 3/5 | ✅ Corregido |
| **Rate limiting en `/login`** (fuerza bruta, no lo ve el baseline) | Regla rate-based del WAF del ALB (Sesión 11, `infra/terraform/main.tf`) | Prueba de carga contra `/login` → 403 del WAF | Infra | Sprint 2 | 🟡 En infraestructura |

Cada fila se cierra con un nuevo scan de ZAP que ya no reporta el hallazgo: ese principio es el que automatiza el security gate de la Sesión 9.
