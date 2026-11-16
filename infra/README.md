# Sesión 11 · Infrastructure as Code y Cloud Security — SecureBank-Infra

**Proyecto:** SecureBank API · SecurePipeline · **Versión:** 1.0 · **Fecha:** 16-11-2026

Módulo Terraform del stack AWS de SecureBank (`infra/terraform/`) y pipeline que lo bloquea si trae configuraciones inseguras (`.github/workflows/iac.yml`).

## 1. Pipeline IaC

```
commit ──► iac-scan (Checkov) ──► GATE ──► terraform plan ──► [aprobación produccion-infra] ──► terraform apply
                                    │
                                    └─ ✕ ≥ 1 CRITICAL/HIGH o Security Score < 85 % → pipeline rojo, PR bloqueado
```

| Etapa | Qué hace | Dónde |
| :-- | :-- | :-- |
| **scan** | `checkov -d infra/terraform` (versión fija 3.4.5) genera el reporte JSON. Se usa `--soft-fail` porque la decisión no la toma Checkov, sino el gate. | job `iac-scan` |
| **gate** | `scripts/checkov_score.py` calcula el Security Score y clasifica cada check fallido con [`checkov-severity.json`](checkov-severity.json). Falla si hay CRITICAL/HIGH abiertos o el score es menor a 85 %. | job `iac-scan` |
| **plan** | `terraform fmt -check`, `validate` y `plan -refresh=false`. Corre **sin credenciales de AWS** (el proveedor no consulta STS ni la API, ver `versions.tf`). | job `plan` |
| **apply** | Solo con `workflow_dispatch` + `apply=true`, desde `main` y tras la aprobación del environment `produccion-infra`. Credenciales temporales por **OIDC** (rol `securebank-ci`), sin llaves estáticas. | job `apply` |

**Por qué un mapeo de severidad propio:** Checkov open source no entrega severidad (eso viene con la plataforma de pago). El equipo clasificó los checks siguiendo la lámina 9 de la sesión: puertos administrativos abiertos, buckets públicos, BD expuesta e IAM `*:*` son CRITICAL; cifrado, logging, IMDSv1 y privilegios excesivos son HIGH. Un check que no está en el mapeo cuenta como MEDIUM. El archivo se cambia solo por PR, igual que la política Rego de la Sesión 9.

**Configuración pendiente en GitHub (una vez):** `Settings → Environments → produccion-infra → Required reviewers` y la variable `AWS_ROLE_ARN` con el ARN del rol `securebank-ci` que crea el propio módulo.

## 2. Security Score antes y después

Security Score = checks aprobados / (aprobados + fallidos) × 100. Meta del ejercicio: ≥ 85 %.

| | Antes (commit `feat(iac)`) | Después (commit `fix(iac)`) |
| :-- | --: | --: |
| Recursos analizados | 26 | 76 |
| Checks aprobados / total | 55 / 142 | 262 / 264 |
| **Security Score** | **38,7 %** | **99,2 %** |
| 🔴 CRITICAL | 9 | 0 |
| 🟠 HIGH | 45 | 0 |
| 🟡 MEDIUM | 6 | 1 |
| ⚪ LOW | 27 | 1 |
| Gate | ✕ BLOQUEADO | ✓ OK |

Reportes completos: [`reports/iac/checkov-before.json`](../reports/iac/checkov-before.json) · [`reports/iac/checkov-after.json`](../reports/iac/checkov-after.json) · resúmenes `score-before.json` / `score-after.json`.

El número de recursos sube porque la remediación agrega los controles que faltaban (bloqueo de acceso público, cifrado, flow logs, WAF, rol OIDC, etc.), y cada recurso nuevo trae sus propios checks.

## 3. Los 5 hallazgos más críticos y su corrección

| # | Hallazgo | Check | Antes | Corrección |
| :-: | :-- | :-- | :-- | :-- |
| 1 | **SSH abierto a Internet** | CKV_AWS_24 · CRITICAL | `sg_public` con ingress `0.0.0.0/0 → :22` sobre las EC2 | El SG del ALB solo acepta 443. Las EC2 pasan a subred privada sin IP pública y su SG acepta 8000 **solo desde el SG del ALB** y 22 solo desde `10.0.0.0/16` (VPN). |
| 2 | **Bucket de respaldos público** | CKV_AWS_20 · CKV2_AWS_6 · CRITICAL | `acl = "public-read"` y sin bloqueo de acceso público | Se elimina la ACL, `BucketOwnerEnforced` (ACL deshabilitadas), `public_access_block` con los 4 flags, cifrado `aws:kms` con la CMK, versionado y política que exige TLS. |
| 3 | **Base de datos expuesta y sin cifrar** | CKV_AWS_17 · CRITICAL · CKV_AWS_16 · HIGH | `publicly_accessible = true`, SG con 5432 abierto, `storage_encrypted = false`, sin respaldos | Subred privada, SG que solo acepta 5432 desde el SG de la app, cifrado con KMS, respaldos de 7 días, `deletion_protection`, Multi-AZ, `rds.force_ssl`, logs a CloudWatch y autenticación IAM. La contraseña la gestiona RDS en Secrets Manager. |
| 4 | **IAM con comodines** | CKV_AWS_62 · CKV_AWS_63 · CRITICAL | Rol `admin` con `Action "*"` sobre `Resource "*"` asignado a las EC2; usuario IAM de CI con `s3:*` | Rol de la app limitado a `s3:GetObject/PutObject` en `backups/app/*`, 3 acciones de DynamoDB sobre una tabla y uso de la CMK. El usuario de CI se reemplaza por un **rol OIDC** de GitHub acotado a `repo:shastin-nav/securebank-api:ref:refs/heads/main` que solo puede publicar en el repo ECR. |
| 5 | **Trazabilidad apagada** | CKV_AWS_251 · CKV_AWS_67 · CKV2_AWS_11 · HIGH | CloudTrail con `enable_logging = false`, una sola región y sin flow logs | CloudTrail multirregión, con validación de integridad, cifrado KMS, envío a CloudWatch y alertas SNS. Flow logs de la VPC (ALL) a CloudWatch cifrado con retención de 365 días. Logs de acceso del ALB y del bucket de respaldos. |

Además: IMDSv2 obligatorio y discos cifrados en EC2/EBS, ALB con HTTPS (TLS 1.2+), redirección 80→443, cabeceras inválidas descartadas y WAF (reglas administradas de AWS + rate limiting), DynamoDB con KMS y recuperación point-in-time, ECR con tags **inmutables** (base de la Sesión 13), escaneo al subir y KMS, y Lambda en la VPC con DLQ cifrada, concurrencia reservada, X-Ray y firma de código.

## 4. Riesgos residuales (aceptados, en el backlog)

| Check | Severidad | Motivo |
| :-- | :-- | :-- |
| CKV2_AWS_76 · regla de Log4j en el WAF | MEDIUM | La API es Python, no usa Log4j. Agregar `AWSManagedRulesAnonymousIpList`/Log4j queda para el siguiente sprint. |
| CKV_AWS_144 · replicación entre regiones del bucket de respaldos | LOW | Costo fuera del alcance del ramo; hay versionado y ciclo de vida. |
| 4 checks omitidos con `#checkov:skip` | — | Cada uno tiene justificación en el código: el bucket de logs no se loguea a sí mismo (bucle) y el listener HTTP solo redirige a HTTPS. |

## 5. Cómo reproducirlo

```bash
pip install checkov==3.4.5
checkov -d infra/terraform --framework terraform --compact --soft-fail -o json > checkov.json
python scripts/checkov_score.py checkov.json --severity infra/checkov-severity.json --min-score 85
```

Para ver el estado inicial: `git checkout <commit feat(iac)> -- infra/terraform` y repetir (o abrir `reports/iac/checkov-before.json`).
