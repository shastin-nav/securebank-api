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
