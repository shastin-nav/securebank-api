# SecureBank API · SecurePipeline

[![CI](https://github.com/4Noisy/POL-REPO-001/actions/workflows/ci.yml/badge.svg)](https://github.com/4Noisy/POL-REPO-001/actions/workflows/ci.yml)

Proyecto transversal del ramo **Sistemas Automatizados DevSecOps** (UBO · Ingeniería Informática, 2026). SecureBank API es una API bancaria didáctica en Python/Flask: login con JWT, cuentas, transferencias, reportes y calculadora de tasas. Sobre ella se construye, sesión a sesión, un pipeline CI/CD seguro.

**Equipo:** Benjamín Garrido · Abdiel Ortiz · Justin Navarro · Emilio Santibáñez

## Entregables por sesión

| Sesión | Entregable | Dónde está |
| :-: | :-- | :-- |
| 1 | Diagrama del ciclo DevSecOps propuesto | [`docs/sesion-01/ciclo-devsecops.pdf`](docs/sesion-01/ciclo-devsecops.pdf) |
| 2 | Política de repositorios seguros | [`POL-REPO-001.md`](POL-REPO-001.md) + protección de `main` + [`CODEOWNERS`](.github/CODEOWNERS) |
| 3 | Threat model (14 amenazas), DFD y security stories | [`docs/threat-model.md`](docs/threat-model.md) · [`docs/security-stories.md`](docs/security-stories.md) |
| 4 | Pipeline CI v1.0 | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| 5 | SAST con Semgrep + reporte antes/después | Job `sast` en el pipeline · [`docs/sast/reporte-sast.md`](docs/sast/reporte-sast.md) |

## Pipeline

```
push / PR ──► build ──► unit-tests ──► SAST (Semgrep) ──► package ──► artefacto dist-<sha> (7 días)
```

- Se dispara con cada push a cualquier rama y con cada PR a `main`.
- `permissions: contents: read`: el token del pipeline solo tiene lectura.
- Dependencias con versión fijada (`requirements.txt`); ningún secreto en el YAML.
- **SAST:** Semgrep con `p/owasp-top-ten` y reglas propias ([`.semgrep/`](.semgrep/securebank.yml)); los hallazgos HIGH/CRITICAL detienen el pipeline y el reporte SARIF queda como artefacto.
- El estado del pipeline es un *status check* obligatorio para mergear a `main`.

## Estructura

```
securebank-api/
├── src/securebank/       # código de la API (Flask)
├── tests/                # pruebas unitarias e integración
├── docs/                 # threat model, DFD, diagramas por sesión
├── .semgrep/            # reglas SAST propias
├── scripts/             # utilidades (resumen de SARIF)
├── .github/
│   ├── CODEOWNERS
│   └── workflows/ci.yml  # pipeline CI
├── Dockerfile            # imagen sin root
├── requirements.txt      # dependencias con versión fijada
└── POL-REPO-001.md       # política de repositorios seguros
```

## Cómo ejecutarlo localmente

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest                       # pruebas
export SECUREBANK_JWT_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"
flask --app "securebank:create_app()" run   # con PYTHONPATH=src
```

Endpoints: `POST /login` · `POST /users` · `GET /users/me` · `GET /accounts` · `GET /accounts/<id>` · `GET /accounts/<id>/movements` · `POST /transfer` · `GET /reportes/<nombre>` · `GET /tasas/calcular` · `GET /bienvenida` · `GET /health`

> ⚠️ SecureBank es una aplicación **deliberadamente vulnerable** con fines académicos: contiene fallos que se detectan y corrigen en las sesiones del curso. No la despliegues en un entorno real.
