# Sesión 13 · Software Supply Chain Security — Pipeline con firma y verificación

**Proyecto:** SecureBank API · SecurePipeline · **Versión:** 1.0 · **Fecha:** 16-11-2026

## 1. Qué se agregó al pipeline

Solo en **push a `main`** y solo si el security gate aprobó (`ci.yml`):

```
security-gate ─► package ─► publish ──────────────────────────────► verify ─────────────────────────► deploy
                            build securebank:v1 (Dockerfile.v2)     cosign verify (firma + identidad)   manifiesto K8s con
                            push a ghcr.io y registra el sha256     cosign verify-attestation (SBOM)    el digest verificado
                            SBOM CycloneDX con Syft                 tag v1 == digest firmado
                            cosign sign (keyless, Rekor)
                            cosign attest --type cyclonedx
```

| Requisito del entregable | Implementación | Rúbrica |
| :-- | :-- | :-: |
| Build que produce `securebank:v1` y publica el digest | Job `publish`: `docker/build-push-action` publica `ghcr.io/shastin-nav/securebank-api:v1` (y `:sha-<commit>`). El **sha256** queda en el log y en el resumen del run. BuildKit agrega además la *provenance* SLSA (`provenance: mode=max`). | 20 % |
| SBOM CycloneDX con Syft, publicado y adjunto | `anchore/sbom-action` (Syft) sobre la imagen **por digest** → `sbom.cdx.json`, artefacto `sbom-image-<sha>` (90 días) y `cosign attest --type cyclonedx`. | 20 % |
| Firma con Cosign del digest | `cosign sign --yes <imagen>@sha256:…` en modo **keyless**: el certificado lo emite Fulcio con el token OIDC del workflow (`id-token: write`); la firma queda registrada en **Rekor** (el `logIndex` aparece en el job `verify`). Sin llaves privadas que guardar ni rotar. | 25 % |
| Verificación que bloquea el deploy | Job `verify`: `cosign verify` y `verify-attestation` exigen que la identidad sea exactamente `…/.github/workflows/ci.yml@refs/heads/main` con issuer `token.actions.githubusercontent.com`. Si falla → exit 1 → `deploy` no corre. | 25 % |
| Evidencia del bloqueo ante imagen no firmada | Workflow manual **“Sesión 13 · Verificar firma de una imagen”** (`verify-image.yml`): con `ghcr.io/shastin-nav/securebank-api:v1` termina en verde; con cualquier imagen no firmada por nosotros (ej. `nginx:1.27`) termina en **rojo**. Capturar ambos runs. | — |
| Documento de análisis | Sección 2 de este archivo. | 10 % |

**Permisos:** el workflow sigue con `contents: read` global. Solo `publish` recibe `packages: write` e `id-token: write`, y solo `verify` recibe `packages: read`.

**Configuración pendiente (una vez):** después del primer push a `main`, en `ghcr.io` → paquete `securebank-api` → *Package settings*, vincular el paquete al repositorio. Si se quiere que el profesor lo vea sin login, dejarlo público.

## 2. Análisis del caso: un atacante reemplaza `securebank:v1` en el registry

**Escenario.** Alguien con acceso de escritura al registry (credencial filtrada, cuenta comprometida) sube una imagen modificada con el mismo tag `:v1`. El tag ahora apunta a un digest distinto. ¿Cómo se detecta antes de que llegue a producción?

**Detección 01 · La firma no verifica.** La firma de Cosign está ligada al **digest** de la imagen que construyó el pipeline, no al tag. La imagen del atacante tiene otro digest y no tiene firma, o tiene una firma hecha con otra identidad. `cosign verify` exige que el certificado diga que la firmó `ci.yml` en `refs/heads/main` del repo `shastin-nav/securebank-api` con el issuer de GitHub Actions, así que responde `no matching signatures` y sale con código 1. El job `verify` falla y `deploy` no se ejecuta. Para falsificar esa identidad el atacante tendría que ejecutar código en nuestro workflow de `main`, que está protegido por el branch protection, CODEOWNERS y todo el pipeline anterior.

**Detección 02 · El digest no coincide.** El job `publish` registra en el log el digest que construyó y firmó. El job `verify` resuelve a qué digest apunta hoy `:v1` y lo compara: si alguien movió el tag (`esperado sha256:9fa1… / actual sha256:d84e…`), falla con `digest mismatch → deploy bloqueado`. Además, el job `deploy` nunca usa el tag: escribe en el manifiesto `imagen@sha256:<digest verificado>`, así que aunque el tag cambie después, el cluster sigue pidiendo exactamente la imagen firmada. Y en AWS el repositorio ECR quedó con tags **inmutables** (Sesión 11): ahí `:v1` ni siquiera se puede sobrescribir.

**Detección 03 · El admission controller la rechaza.** Si alguien se salta el pipeline y hace `kubectl apply` a mano, el `ClusterImagePolicy` de `k8s/supply-chain/` (policy-controller de Sigstore) vuelve a verificar la firma y la attestation CycloneDX dentro del cluster. Una imagen sin firma válida recibe `admission webhook "policy.sigstore.dev" denied … no valid signature` y el Pod nunca arranca.

**Defensa en capas.** La firma prueba el **origen** (quién la construyó), el digest prueba la **integridad** (que es exactamente ese contenido) y el admission controller **impide el deploy** aunque las dos primeras se salten. El SBOM adjunto permite responder, sin reconstruir nada, qué componentes trae la imagen desplegada cuando sale un CVE nuevo. Riesgo residual: GHCR permite mover tags, así que la protección real es usar siempre el digest, como hacen el job `deploy` y el `ClusterImagePolicy`.
