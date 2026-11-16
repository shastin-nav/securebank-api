# Reportes del pipeline

Archivos generados por el job `sca` (artefacto `sca-reports-<sha>` de GitHub Actions):

| Archivo | Qué es |
| :-- | :-- |
| `securebank-sbom.cdx.json` | SBOM en formato CycloneDX |
| `securebank-sbom.spdx.json` | SBOM en formato SPDX |
| `securebank-vulns.html` | Reporte de componentes vulnerables con el semáforo CVSS |
| `securebank-vulns.json` | Lo mismo en JSON |
| `trivy-vulns.json` | Salida cruda de Trivy |

Se copian aquí desde el run verde de `main` después de cada cambio de dependencias.

Otros reportes versionados como evidencia (run 43973218491 de `main`):

| Archivo | Qué es |
| :-- | :-- |
| `dast/zap-report.json` | `report.json` del ZAP Baseline Scan (Sesión 8, job `dast`) |
| `image/trivy-securebank-v1.txt` y `image/trivy-securebank-v2-secure.txt` | Salida de `trivy image` de ambas imágenes (Sesión 10, job `image`) |
| | En la salida de v1 las cabeceras `BEGIN/END … PRIVATE KEY` se reemplazaron por texto: son las llaves SSH del host de la imagen v1 (Trivy ya enmascara su contenido) y Gitleaks las bloquea. |
| `image/comparacion-imagenes.md` | Tabla comparativa generada por el pipeline |
| `iac/` | Reportes de Checkov antes y después (Sesión 11) |
