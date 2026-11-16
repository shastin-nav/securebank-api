# SecureBank API · SecurePipeline

[![CI](https://github.com/shastin-nav/securebank-api/actions/workflows/ci.yml/badge.svg)](https://github.com/shastin-nav/securebank-api/actions/workflows/ci.yml)

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
| 6 | SCA con Trivy, SBOM (CycloneDX/SPDX) y semáforo CVSS | Job `sca` · [`docs/sca/politica-cvss.md`](docs/sca/politica-cvss.md) · [`reports/`](reports/) |
| 7 | Secret scanning con Gitleaks + procedimiento de rotación | Job `secret-scan` · [`.gitleaks.toml`](.gitleaks.toml) · [`docs/SECRETS.md`](docs/SECRETS.md) |
| 8 | DAST con ZAP Baseline + reporte y plan de mitigación | Job `dast` · [`docker-compose.yml`](docker-compose.yml) · [`.zap/rules.tsv`](.zap/rules.tsv) · [`docs/dast/reporte-dast.md`](docs/dast/reporte-dast.md) |
| 9 | Security gate con Policy as Code (OPA/Rego) · Security Policy v1.0 | Job `security-gate` · [`policy/`](policy/) ([README](policy/README.md)) |
| 10 | Dockerfile inseguro vs endurecido + reporte comparativo Trivy | Job `image` · [`docker/`](docker/) ([REPORT.md](docker/REPORT.md)) |
| 11 | SecureBank-Infra en Terraform + Checkov + pipeline IaC (Security Score 38,7 % → 99,2 %) | [`.github/workflows/iac.yml`](.github/workflows/iac.yml) · [`infra/`](infra/) ([README](infra/README.md)) · [`reports/iac/`](reports/iac/) |
| 12 | Deployment de Kubernetes endurecido | [`k8s/hardened/`](k8s/hardened/) ([README](k8s/README.md)) · job `k8s-scan` |
| 13 | Imagen firmada con Cosign + SBOM Syft + verificación que bloquea el deploy | Jobs `publish` · `verify` · `deploy` · [`verify-image.yml`](.github/workflows/verify-image.yml) · [`docs/supply-chain/`](docs/supply-chain/README.md) |

## Pipeline

```
push / PR ──► secret-scan ──► build ─┬─► unit-tests + coverage ──► SAST (Semgrep) ──────┐
                                     ├─► SCA (Trivy + SBOM + CVSS) ──► [aprobación] ─────┤
                                     └─► image (v1 vs v2-secure, Trivy) ──► DAST (ZAP) ──┤
                                                                                         ▼
                      security-gate (findings.json → OPA · security-policy-v1.rego) ──► package ──► dist-<sha>
                                                                                         │
                                         solo en main: publish (ghcr.io + SBOM + cosign sign) ──► verify ──► deploy

infra/** o k8s/** ──► iac.yml: Checkov + gate (score ≥ 85 %) ──► terraform plan ──► [aprobación] ──► apply
                               kube-score + Checkov sobre k8s/hardened
```

- Se dispara con cada push a cualquier rama y con cada PR a `main`.
- `permissions: contents: read`: el token del pipeline solo tiene lectura. Solo `publish` recibe `packages: write` e `id-token: write`.
- Acciones fijadas por SHA, binarios (Gitleaks, OPA, kube-score) verificados por SHA-256 y dependencias con versión fijada. Dependabot propone las actualizaciones.
- **Secret scan:** Gitleaks revisa todo el historial antes que nada; si encuentra un secreto, el pipeline se detiene. También corre como pre-commit hook (`pre-commit install`).
- **SAST:** Semgrep con `p/owasp-top-ten` y reglas propias ([`.semgrep/`](.semgrep/securebank.yml)); los hallazgos HIGH/CRITICAL detienen el pipeline.
- **SCA:** Trivy revisa las dependencias contra bases de CVE y genera el SBOM. Semáforo: CVSS ≥ 9.0 bloquea, 7.0–8.9 espera aprobación en el environment `aprobacion-seguridad`, < 7.0 va al backlog.
- **Imagen:** se construyen `securebank:v1` (inseguro) y `securebank:v2-secure`, se escanean con Trivy y se publica la tabla comparativa.
- **DAST:** ZAP Baseline contra `securebank:v2-secure` corriendo con `docker compose`. Las alertas ya corregidas están en `FAIL` y fallan el job si vuelven a aparecer.
- **Security gate:** todos los reportes se consolidan en `findings.json` y OPA aplica la política: 0 secretos, 0 Critical, High acotados, criterio de riesgo por exposición y coverage ≥ 80 %. Si falta un reporte, también bloquea.
- **Supply chain:** en `main`, la imagen se publica por digest, se firma sin llaves (Cosign + OIDC + Rekor), se le adjunta el SBOM y solo se despliega si `cosign verify` pasa.
- El estado del pipeline es un *status check* obligatorio para mergear a `main`.

## Estructura

```
securebank-api/
├── src/securebank/       # código de la API (Flask)
├── tests/                # pruebas unitarias y de regresión de seguridad
├── docs/                 # threat model, DFD, SAST, SCA, DAST, supply chain
├── .semgrep/             # reglas SAST propias
├── .zap/rules.tsv        # configuración del ZAP Baseline (Sesión 8)
├── policy/               # Security Policy v1.0 en Rego + pruebas (Sesión 9)
├── docker/               # Dockerfile.v1 (inseguro) · Dockerfile.v2 (endurecido) · REPORT.md (Sesión 10)
├── infra/                # SecureBank-Infra en Terraform + severidades de Checkov (Sesión 11)
├── k8s/                  # manifiestos vulnerables, hardened y política de admisión (Sesiones 12-13)
├── scripts/              # resumen SARIF, política CVSS, findings.json, score IaC, comparación de imágenes
├── reports/              # SBOM, vulnerabilidades y reportes Checkov antes/después
├── .github/
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   └── workflows/        # ci.yml · iac.yml · verify-image.yml
├── docker-compose.yml    # API en local o en el job DAST
├── requirements.txt      # dependencias con versión fijada
└── POL-REPO-001.md       # política de repositorios seguros
```

## Cómo ejecutarlo localmente

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest                       # pruebas
export SECUREBANK_JWT_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"   # o copiar .env.example a .env
flask --app "securebank:create_app()" run   # con PYTHONPATH=src

# o en Docker, con la imagen endurecida (http://localhost:8080)
docker compose up -d --build && curl http://localhost:8080/health

# security gate a mano
opa test policy/security-policy-v1.rego policy/security-policy-v1_test.rego -v
```

Endpoints: `POST /login` · `POST /users` · `GET /users/me` · `GET /accounts` · `GET /accounts/<id>` · `GET /accounts/<id>/movements` · `POST /transfer` · `GET /reportes/<nombre>` · `GET /tasas/calcular` · `GET /bienvenida` · `GET /health`

> ⚠️ SecureBank es una aplicación **deliberadamente vulnerable** con fines académicos: contiene fallos que se detectan y corrigen en las sesiones del curso. No la despliegues en un entorno real.
