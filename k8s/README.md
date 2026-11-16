# Sesión 12 · Kubernetes y seguridad cloud-native — Deployment endurecido

**Proyecto:** SecureBank API · SecurePipeline · **Versión:** 1.0 · **Fecha:** 16-11-2026

| Carpeta | Contenido |
| :-- | :-- |
| [`securebank/`](securebank/) | Línea base **vulnerable** del laboratorio: `privileged`, root, `:latest`, secreto en texto plano, sin límites, `NodePort`, namespace `default`. |
| [`hardened/`](hardened/) | **Entregable.** `deployment.hardened.yaml` + namespace con Pod Security `restricted`, ServiceAccount sin token, Service `ClusterIP`, NetworkPolicy *deny by default* y PodDisruptionBudget. |
| [`supply-chain/`](supply-chain/) | Política de admisión de Sigstore que exige la firma de la imagen (Sesión 13). |

## 1. Criterios del entregable

| Criterio | Dónde está en `deployment.hardened.yaml` | ✓ |
| :-- | :-- | :-: |
| `runAsNonRoot: true` + `runAsUser` > 1000 | Pod y contenedor: `runAsNonRoot: true`, `runAsUser: 10001` (mismo UID del `Dockerfile.v2`) | ✓ |
| `readOnlyRootFilesystem: true` | Contenedor. Solo se escribe en `/data` y `/tmp` (volúmenes `emptyDir` con `sizeLimit`) | ✓ |
| `capabilities.drop: ["ALL"]` | Contenedor. No se agrega ninguna | ✓ |
| `resources.limits` (cpu y memoria) | `500m` / `256Mi` (requests `100m` / `128Mi`), más `ephemeral-storage` | ✓ |
| `allowPrivilegeEscalation: false` | Contenedor, junto con `privileged: false` y `seccompProfile: RuntimeDefault` | ✓ |
| Imagen por digest, no `:latest` | `ghcr.io/shastin-nav/securebank-api@sha256:…`. El job `deploy` del pipeline pone el digest que Cosign firmó y verificó | ✓ |
| Secretos vía `secretKeyRef` | `SECUREBANK_JWT_SECRET` desde el Secret `securebank-jwt` | ✓ |
| Validación automática | Job `k8s-scan` de `.github/workflows/iac.yml`: **kube-score** y **Checkov** fallan el pipeline ante cualquier hallazgo en `hardened/` | ✓ |

Además: `automountServiceAccountToken: false` (la API no habla con el API server), 2 réplicas con anti-afinidad y PDB, probes de readiness y liveness, y `imagePullPolicy: Always`.

## 2. Resultado de los escáneres

| | `k8s/securebank/` (antes) | `k8s/hardened/` (después) |
| :-- | :-- | :-- |
| **kube-score** | Deployment 💥 con 8 CRITICAL (NetworkPolicy, UID/GID, readOnlyRootFilesystem, image tag, resources, ephemeral storage, probes, privileged) y 2 WARNING | Deployment, NetworkPolicies, PDB y Service ✅ sin hallazgos |
| **Checkov** (`--framework kubernetes`) | 69 aprobados · **22 fallidos** | 91 aprobados · **0 fallidos** · 1 omitido con justificación |

El check omitido es `CKV_K8S_35` ("preferir secretos como archivo en vez de variable de entorno"). La rúbrica pide `secretKeyRef` y la app lee la clave del entorno; montarla como archivo queda en el backlog. La justificación está en la anotación `checkov.io/skip1` del Deployment.

## 3. Los seis riesgos del laboratorio y cómo se cierran

| Riesgo (`securebank/deployment.yaml`) | Control (`hardened/`) |
| :-- | :-- |
| [R1] `image: securebank:latest` | Imagen por digest firmado + `ClusterImagePolicy` |
| [R2] `privileged: true` | `privileged: false`, `capabilities.drop: ALL`, PSA `restricted` en el namespace (el API server rechaza el Pod aunque alguien lo pida) |
| [R3] `runAsUser: 0` | `runAsNonRoot: true`, `runAsUser: 10001` |
| [R4] Secreto en `env.value` y en un ConfigMap | Secret `securebank-jwt` referenciado con `secretKeyRef`; nunca se versiona su valor |
| [R5] Sin límites de recursos | `requests`/`limits` de CPU, memoria y almacenamiento efímero |
| [R6] Sistema de archivos escribible | `readOnlyRootFilesystem: true` + `emptyDir` solo para `/data` y `/tmp` |

## 4. Desplegar en minikube

```bash
minikube start --driver=docker
kubectl apply -f k8s/hardened/namespace.yaml
kubectl -n securebank create secret generic securebank-jwt \
  --from-literal=jwt-secret="$(python -c 'import secrets;print(secrets.token_hex(32))')"

# Opción A: la imagen firmada del registry (digest del artefacto deploy-manifests-<sha> del pipeline)
kubectl apply -f deploy/                      # manifiestos ya renderizados por el job deploy

# Opción B: imagen construida en minikube (solo laboratorio local)
minikube image build -t securebank:v2-secure -f docker/Dockerfile.v2 .
kubectl apply -f k8s/hardened/
kubectl -n securebank set image deployment/securebank-api api=securebank:v2-secure
kubectl -n securebank patch deployment securebank-api --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]'

# Validar
kubectl -n securebank get pods
kubectl -n securebank exec deploy/securebank-api -- id            # uid=10001
kubectl -n securebank exec deploy/securebank-api -- touch /app/x  # Read-only file system
kubectl -n securebank port-forward svc/securebank-api 8080:80 && curl localhost:8080/health
```

Prueba de la defensa en el namespace: con `kubectl apply -n securebank -f k8s/securebank/deployment.yaml` el API server muestra la advertencia de Pod Security y **los Pods nunca se crean** (`kubectl -n securebank describe rs` → `violates PodSecurity "restricted:latest": privileged, runAsNonRoot != true…`).
