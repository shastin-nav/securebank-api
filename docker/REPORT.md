# Sesión 10 · Seguridad de contenedores — securebank:v1 vs securebank:v2-secure

**Proyecto:** SecureBank API · SecurePipeline · **Versión:** 1.0 · **Fecha:** 16-11-2026

| Archivo | Imagen | Uso |
| :-- | :-- | :-- |
| [`Dockerfile.v1`](Dockerfile.v1) | `securebank:v1` | Inseguro a propósito. Solo se construye y escanea para comparar; nunca se despliega. |
| [`Dockerfile.v2`](Dockerfile.v2) | `securebank:v2-secure` | Endurecido. Es la imagen que usan el DAST, el gate y la publicación firmada (Sesión 13). |
| [`../.dockerignore`](../.dockerignore) | — | Contexto de build de v2. `Dockerfile.v1.dockerignore` está vacío a propósito para que v1 represente un build **sin** `.dockerignore`. |

## 1. Laboratorio: build → scan → fix → rebuild

Lo hace el job `image` del pipeline en cada push. Para repetirlo a mano desde la raíz del repo:

```bash
docker build -f docker/Dockerfile.v1 -t securebank:v1 .
docker build -f docker/Dockerfile.v2 -t securebank:v2-secure .
trivy image --severity HIGH,CRITICAL --format table securebank:v1
trivy image --severity HIGH,CRITICAL --format table securebank:v2-secure
trivy image -f json --list-all-pkgs -o v1.json securebank:v1
trivy image -f json --list-all-pkgs -o v2.json securebank:v2-secure
docker run --rm --entrypoint id securebank:v2-secure -u      # 10001
```

## 2. Tabla comparativa

El job `image` genera la tabla con las cifras **reales** del run (`scripts/comparar_imagenes.py`) en el resumen del run y en el artefacto `image-scan-<sha>`. Cifras del run [43973218491](https://github.com/shastin-nav/securebank-api/actions/runs/43973218491) de `main` (commit `68c47a0`, 16-11-2026):

| Métrica | securebank:v1 | securebank:v2-secure | Δ mejora |
| :-- | --: | --: | :-- |
| Vulnerabilidades (HIGH + CRITICAL) | 8 | 49 | ↑ 512 % (ver 2.1) |
| Tamaño de la imagen | 278 MB | 48 MB | ↓ 83 % |
| Paquetes instalados | 316 | 117 | ↓ 63 % |
| Usuario de ejecución | root (uid 0) | 10001:10001 | ✓ mínimo privilegio |
| Puertos expuestos | 22/tcp, 8000/tcp | 8000/tcp | ✓ solo la app |
| Sistema base | ubuntu 26.04 | debian 13.7 | |

Salida completa de `trivy image --severity HIGH,CRITICAL` de ese run: [`reports/image/trivy-securebank-v1.txt`](../reports/image/trivy-securebank-v1.txt) y [`reports/image/trivy-securebank-v2-secure.txt`](../reports/image/trivy-securebank-v2-secure.txt).

### 2.1 Por qué v2 tiene más CVE High que v1

El resultado es el contrario al de la lámina, y lo dejamos tal cual:

| | securebank:v1 | securebank:v2-secure |
| :-- | --: | --: |
| CRITICAL | 0 | 0 |
| HIGH del sistema base | 8 (todos en `linux-libc-dev`) | 47 (util-linux: `libmount1`, `libblkid1`, `login`, `mount`, etc.) |
| HIGH en paquetes Python | 0 | 2 (`jaraco.context` y `wheel`, que vienen con `setuptools`) |
| HIGH **con parche disponible** | 0 | 2 |
| Secretos en la imagen | 3 (llaves SSH del host que genera `openssh-server`) | 0 |

- `ubuntu:latest` hoy es la 26.04, recién publicada, y casi no tiene CVE registrados todavía. Eso es justo el problema de `latest`: el número depende del día en que se construye.
- Los 47 High de Debian 13.7 **no tienen versión corregida**: no hay nada que actualizar. Trivy los reporta y el gate no los cuenta.
- Los 2 que sí tienen parche son los únicos accionables, y están dentro del máximo de 2 de la política (`fixable_high ≤ 2`, Sesión 9). Con Debian 12 eran 3 y el gate bloqueó el PR #5 (run 43959398712).
- La mejora real de v2 está en lo que un atacante puede usar: 83 % menos tamaño, 63 % menos paquetes, sin SSH, sin compiladores y sin root.

Referencia de la lámina 13 (estimaciones típicas, **no** son nuestras cifras): ~45 → ≤ 3 vulnerabilidades, ~780 → ~120 MB, ~150 → ~35 paquetes.

**Por qué cambia cada métrica:**
- **Vulnerabilidades:** suben de 8 a 49 por la base y no por lo que instalamos (ver 2.1). `apt-get upgrade` aplica los parches publicados después de la imagen base; los que quedan no tienen versión corregida.
- **Tamaño y paquetes:** sin compiladores ni herramientas, con build multi-etapa (las dependencias se instalan en `deps` y solo se copia el resultado) y sin cachés de apt/pip.
- **Usuario:** `USER 10001:10001` en vez de root. Si alguien explota la app, no es root dentro del contenedor.
- **Puertos:** v1 expone el 22 (SSH); v2 solo el 8000 de la app.

## 3. Checklist del entregable (6 buenas prácticas)

| # | Buena práctica | v1 (problema) | v2-secure (cambio aplicado) |
| :-: | :-- | :-- | :-- |
| BP1 | Imagen base mínima y versionada | `FROM ubuntu:latest`: completa y con tag que cambia | `python:3.11.18-slim-trixie` (Debian 13) con versión de parche fija en las dos etapas. Dependabot (`.github/dependabot.yml`) propone las actualizaciones por PR. |
| BP2 | Sin paquetes ni cachés innecesarios | SSH, compiladores, vim y curl, con la caché de apt dentro | Solo `tini`, `--no-install-recommends`, `rm -rf /var/lib/apt/lists/*`, `PIP_NO_CACHE_DIR=1`. Etapa `deps` separada: nada de la instalación queda en la imagen final. |
| BP3 | Usuario no privilegiado | `USER root` | `useradd --uid 10001` sin shell ni home, `USER 10001:10001` (el mismo UID que exige el Deployment de K8s). |
| BP4 | Capas en orden de caché | `COPY . .` antes de instalar | `requirements.txt` primero, luego el código: cambiar código no reinstala dependencias. |
| BP5 | `.dockerignore` sin secretos ni basura | Sin `.dockerignore`: `.git`, `.env`, tests y reportes terminan dentro | `.dockerignore` excluye `.env*`, llaves, `.git`, `.github`, tests, docs, infra y reportes. Solo se copia `src/`, y queda en propiedad de root (appuser no puede modificar el código). |
| BP6 | Solo el puerto de la app | `EXPOSE 22 8000` | `EXPOSE 8000` |

Extra en v2: `tini` como PID 1 (señales y procesos zombie), `HEALTHCHECK`, gunicorn en vez del servidor de desarrollo con `--debug` (que permite ejecutar código remoto desde el navegador), escritura solo en `/data` y `/dev/shm` (compatible con `read_only: true` en compose y `readOnlyRootFilesystem` en K8s), y `SECUREBANK_JWT_SECRET` inyectado al ejecutar, nunca en la imagen.

## 4. Riesgos residuales

- **47 CVE High de Debian 13.7 sin parche disponible:** Trivy los reporta, pero no hay versión corregida. El gate (Sesión 9) solo bloquea los que tienen parche; los demás se revisan cuando Dependabot sube la imagen base.
- **2 CVE High con parche (`jaraco.context` 5.3.0 y `wheel` 0.45.1, que vienen con `setuptools`):** están en el límite de la política. `setuptools` y `pip` no se usan al ejecutar la API; quitarlos de la imagen final queda en el backlog y dejaría el contador en 0.
- **El tag de la base no es inmutable:** `3.11.18-slim-trixie` puede reconstruirse upstream. La imagen que se publica sí queda fijada por **digest** y firmada (Sesión 13).
- **Python e intérprete dentro de la imagen:** una imagen *distroless* reduciría aún más la superficie, pero hoy complica el healthcheck y la depuración. Queda en el backlog.
- **SQLite dentro del contenedor:** sirve para el laboratorio. En producción la BD es RDS (Sesión 11).
