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

El job `image` genera la tabla con las cifras **reales** del run (`scripts/comparar_imagenes.py`) en el resumen del run y en el artefacto `image-scan-<sha>` (`comparacion-imagenes.md`, junto con las salidas de `trivy image` de ambas imágenes). Copiar aquí la tabla del último run de `main`:

| Métrica | securebank:v1 | securebank:v2-secure | Δ mejora |
| :-- | --: | --: | :-- |
| Vulnerabilidades (HIGH + CRITICAL) | _del run_ | _del run_ | |
| Tamaño de la imagen | _del run_ | _del run_ | |
| Paquetes instalados | _del run_ | _del run_ | |
| Usuario de ejecución | root (uid 0) | 10001:10001 | ✓ mínimo privilegio |
| Puertos expuestos | 22/tcp, 8000/tcp | 8000/tcp | ✓ solo la app |

Referencia de la lámina 13 (estimaciones típicas, **no** son nuestras cifras): ~45 → ≤ 3 vulnerabilidades, ~780 → ~120 MB, ~150 → ~35 paquetes.

**Por qué cambia cada métrica:**
- **Vulnerabilidades:** `ubuntu:latest` + `build-essential`, `openssh-server`, `vim` y `curl` traen cientos de paquetes con CVE que la API no usa; `slim` solo trae lo necesario para Python, y `apt-get upgrade` aplica los parches de seguridad publicados después de la imagen base.
- **Tamaño y paquetes:** sin compiladores ni herramientas, con build multi-etapa (las dependencias se instalan en `deps` y solo se copia el resultado) y sin cachés de apt/pip.
- **Usuario:** `USER 10001:10001` en vez de root. Si alguien explota la app, no es root dentro del contenedor.
- **Puertos:** v1 expone el 22 (SSH); v2 solo el 8000 de la app.

## 3. Checklist del entregable (6 buenas prácticas)

| # | Buena práctica | v1 (problema) | v2-secure (cambio aplicado) |
| :-: | :-- | :-- | :-- |
| BP1 | Imagen base mínima y versionada | `FROM ubuntu:latest`: completa y con tag que cambia | `python:3.11.13-slim-bookworm` con versión fija en las dos etapas. Dependabot (`.github/dependabot.yml`) propone las actualizaciones por PR. |
| BP2 | Sin paquetes ni cachés innecesarios | SSH, compiladores, vim y curl, con la caché de apt dentro | Solo `tini`, `--no-install-recommends`, `rm -rf /var/lib/apt/lists/*`, `PIP_NO_CACHE_DIR=1`. Etapa `deps` separada: nada de la instalación queda en la imagen final. |
| BP3 | Usuario no privilegiado | `USER root` | `useradd --uid 10001` sin shell ni home, `USER 10001:10001` (el mismo UID que exige el Deployment de K8s). |
| BP4 | Capas en orden de caché | `COPY . .` antes de instalar | `requirements.txt` primero, luego el código: cambiar código no reinstala dependencias. |
| BP5 | `.dockerignore` sin secretos ni basura | Sin `.dockerignore`: `.git`, `.env`, tests y reportes terminan dentro | `.dockerignore` excluye `.env*`, llaves, `.git`, `.github`, tests, docs, infra y reportes. Solo se copia `src/`, y queda en propiedad de root (appuser no puede modificar el código). |
| BP6 | Solo el puerto de la app | `EXPOSE 22 8000` | `EXPOSE 8000` |

Extra en v2: `tini` como PID 1 (señales y procesos zombie), `HEALTHCHECK`, gunicorn en vez del servidor de desarrollo con `--debug` (que permite ejecutar código remoto desde el navegador), escritura solo en `/data` y `/dev/shm` (compatible con `read_only: true` en compose y `readOnlyRootFilesystem` en K8s), y `SECUREBANK_JWT_SECRET` inyectado al ejecutar, nunca en la imagen.

## 4. Riesgos residuales

- **CVE de la imagen base sin parche disponible:** Trivy los reporta, pero no hay versión corregida en Debian. El gate (Sesión 9) solo bloquea los que tienen parche; los demás se revisan cuando Dependabot sube la imagen base.
- **El tag de la base no es inmutable:** `3.11.13-slim-bookworm` puede reconstruirse upstream. La imagen que se publica sí queda fijada por **digest** y firmada (Sesión 13).
- **Python e intérprete dentro de la imagen:** una imagen *distroless* reduciría aún más la superficie, pero hoy complica el healthcheck y la depuración. Queda en el backlog.
- **SQLite dentro del contenedor:** sirve para el laboratorio. En producción la BD es RDS (Sesión 11).
