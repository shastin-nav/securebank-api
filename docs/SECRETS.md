# Procedimiento de gestión y rotación de secretos · SecureBank API

**Sesión 7 · Secret Management** · **Versión:** 1.0 · **Fecha:** 02-11-2026 · **Dueño del documento:** Justin Navarro (líder técnico)

Regla base del proyecto: **ningún secreto vive en el código**. Si aparece uno, no es un bug, es un incidente, y se sigue la sección 5.

---

## §1. Inventario de secretos

| # | Secreto | Para qué sirve | Dónde vive hoy | ¿Está en el repo? |
| :-: | :-- | :-- | :-- | :-: |
| S1 | `SECUREBANK_JWT_SECRET` | Firma y valida los JWT (HS256) de todos los usuarios | Variable de entorno. Local: `.env` (ignorado por git). Servidor/contenedor: se inyecta al levantar (`docker run -e`). | No |
| S2 | `GITHUB_TOKEN` del pipeline | Que el pipeline lea el repo | Lo crea GitHub en cada ejecución y expira al terminar el job. Permiso solo `contents: read`. | No |
| S3 | Contraseñas de usuarios | Login en `POST /login` | En la BD solo se guarda el **hash scrypt con sal** (`password_hash`), nunca la contraseña. | No |
| S4 | `SECUREBANK_DB` (ruta de la BD) | Ubicación del archivo SQLite | Variable de entorno. Hoy no lleva credenciales; si se migra a PostgreSQL la cadena de conexión pasa a ser secreto (ver §2). | No |
| S5 | Credenciales de las pruebas | Usuarios falsos para `pytest` | Se arman en tiempo de ejecución dentro de `tests/` (`"clave-de-pruebas-" + "x" * 32`). No sirven fuera de las pruebas. | Sí, a propósito (son falsas) |

Si `SECUREBANK_JWT_SECRET` no está definido, la app genera una clave aleatoria al arrancar (`secrets.token_hex(32)`). Así nunca corre con una clave fija o conocida. El costo es que los tokens dejan de valer al reiniciar.

Plantilla para desarrollo: [`.env.example`](../.env.example) (sin valores).

## §2. Alternativas elegidas

| Caso | Alternativa | Por qué |
| :-- | :-- | :-- |
| Desarrollo local | Variables de entorno desde `.env` (fuera de git) | Es lo más simple para 4 personas y no deja nada en el repo. `.gitignore` bloquea `.env`, `.env.*`, `*.pem`, `id_rsa*` y `credentials.json`. |
| Pipeline CI | **GitHub Secrets** + `GITHUB_TOKEN` efímero | Hoy el pipeline no necesita ningún secreto propio. Si algún job lo necesita (por ejemplo, DAST en la Sesión 8), se guarda en `Settings → Secrets and variables → Actions` y se pasa solo a ese job con `env:`. GitHub lo oculta en los logs. |
| Despliegue (futuro) | **OIDC** de GitHub Actions hacia la nube | No hay que guardar llaves de nube en ningún lado: el job pide un token que dura minutos. Sigue el principio de la sesión de preferir credenciales temporales a permanentes. |
| Producción real (fuera del alcance del curso) | HashiCorp Vault o el KMS de la nube | Rotación automática y auditoría de cada lectura. No lo montamos porque el proyecto no tiene un ambiente productivo. |

**Descartado:** guardar secretos en `config.py`, en el `Dockerfile` o en el YAML del pipeline. El `Dockerfile` recibe la clave en tiempo de ejecución, nunca en la imagen.

## §3. Configuración de Gitleaks

Hay tres capas. La misma configuración (`.gitleaks.toml`) se usa en las tres.

**a) Reglas: [`.gitleaks.toml`](../.gitleaks.toml)**

- `useDefault = true`: las reglas oficiales de Gitleaks (AWS, GitHub, Slack, llaves privadas, `generic-api-key`, etc.).
- `securebank-jwt-secret`: detecta `SECUREBANK_JWT_SECRET = "..."` con un valor de 16 caracteres o más.
- `securebank-hardcoded-password`: detecta `password|pwd|contraseña|clave = "..."` con un valor literal de 8 caracteres o más. No salta con `os.environ`, `data.get("password")` ni `"$VARIABLE"`.
- Excepciones: los reportes que genera el pipeline (`reports/*.json`, SARIF), que contienen hashes de paquetes, y la carpeta `tests/` solo para la regla de contraseñas.

Las reglas se probaron con casos positivos (4 de 4 detectados) y negativos (`os.environ.get(...)`, `export X="$(...)"`, `"$DB_PASSWORD"` no saltan).

**b) Pre-commit hook: [`.pre-commit-config.yaml`](../.pre-commit-config.yaml)**

Revisa lo que está en *stage* antes de cada commit, así el secreto no llega ni siquiera al historial local.

```bash
pip install pre-commit
pre-commit install            # una vez por clon
pre-commit run --all-files    # prueba manual
```

Si el hook encuentra algo, el commit no se crea. Saltarse el hook (`--no-verify`) no sirve de mucho porque el pipeline vuelve a revisar.

**c) Job `secret-scan` en el pipeline** ([`ci.yml`](../.github/workflows/ci.yml))

```
secret-scan ──► build ─┬─► unit-tests ──► sast ──────────────────┐
                       └─► sca ──► [aprobacion-seguridad] ───────┴─► package
```

- Es la **primera etapa**. Si encuentra un secreto, falla con exit code 1 y no corre nada más (fail fast).
- `fetch-depth: 0` + `--log-opts=HEAD`: revisa **todo el historial** del commit, no solo el último cambio. Un secreto que se "borró" en un commit posterior igual se detecta.
- `--redact`: el valor nunca aparece en el log del pipeline.
- Gitleaks se descarga como binario oficial v8.21.2 y se verifica su SHA-256 antes de ejecutarlo (mismo criterio que fijar las acciones por SHA).
- El reporte queda como artefacto `secret-scan-<sha>` en formato SARIF.

## §4. Política de rotación

| Secreto | Frecuencia | Rotación inmediata si... | Responsable | Cómo se rota |
| :-- | :-- | :-- | :-- | :-- |
| `SECUREBANK_JWT_SECRET` | Cada 90 días | Aparece en un commit, log o chat; se va alguien del equipo con acceso | Líder técnico | Ver procedimiento abajo |
| GitHub Secrets (futuros) | Cada 90 días o lo que exija el proveedor | Igual que arriba | Dueño del servicio | Regenerar en el proveedor y actualizar en `Settings → Secrets` |
| `GITHUB_TOKEN` | No aplica (expira solo al terminar el job) | — | GitHub | — |
| Contraseñas de usuarios | Las cambia cada usuario | Se sospecha filtración de la BD: forzar cambio a todos | Equipo | Endpoint de cambio de clave (pendiente) |
| Tokens personales (PAT) del equipo | Máximo 90 días de vigencia al crearlos | Laptop perdida o token visto por otro | Cada integrante | Revocar en GitHub → Developer settings |

**Rotar `SECUREBANK_JWT_SECRET` (paso a paso):**

```bash
# 1. Generar la clave nueva
python -c "import secrets; print(secrets.token_hex(32))"

# 2. Reemplazarla donde se usa
#    - local: editar .env
#    - contenedor: volver a levantar con -e SECUREBANK_JWT_SECRET=<nueva>
#    - si está en GitHub Secrets: Settings → Secrets → editar

# 3. Reiniciar la API y comprobar
curl -s localhost:8000/health
```

Efecto: todos los tokens firmados con la clave vieja dejan de valer y los usuarios vuelven a iniciar sesión. Como los tokens duran 15 minutos (`JWT_EXP_MINUTES`), el impacto es bajo y no requiere downtime.

Cada rotación se anota en la tabla de registro de la §6.

## §5. Procedimiento de respuesta ante una fuga

Orden obligatorio: **Detectar → Revocar → Rotar → Limpiar → Notificar.** Revocar va antes que limpiar porque borrar el commit no invalida el secreto: sigue en forks, clones, caches y logs.

| Paso | Tiempo | Qué se hace | Responsable | Evidencia |
| :-- | :-- | :-- | :-- | :-- |
| 1. Detectar | Minuto 0 | Alerta de Gitleaks (pipeline o pre-commit) o aviso de alguien. Confirmar qué secreto es, en qué commit está y si la rama es pública. | Quien lo detecta + líder técnico | Enlace al run o captura del hallazgo |
| 2. Revocar | ≤ 15 min | Invalidar la credencial en su origen. Si es la clave JWT, cambiarla deja inválidos todos los tokens. Si es un token de GitHub o de la nube, revocarlo en el proveedor. | Dueño del servicio | Captura de la revocación |
| 3. Rotar | Mismo día | Generar el secreto nuevo (§4), guardarlo en su lugar correcto (`.env` / GitHub Secrets) y redesplegar. | Líder técnico | Run verde del pipeline después del cambio |
| 4. Limpiar historial | Coordinado con el equipo | Sacar el secreto del historial con `git filter-repo --replace-text` (o BFG), hacer `push --force` y pedir que todos vuelvan a clonar. Si el repo es público, pedir a GitHub Support que limpie caches. | Maintainer del repo | Gitleaks sobre el historial nuevo sin hallazgos |
| 5. Notificar | ≤ 48 h | Avisar al equipo y al profesor; revisar si alguien usó el secreto mientras estuvo expuesto; escribir qué falló y qué se cambia para que no se repita. | Líder técnico | Nota del incidente en esta carpeta |

```bash
# Paso 4 · ejemplo de limpieza (después de revocar y rotar)
pip install git-filter-repo
echo 'VALOR_FILTRADO==>***REMOVED***' > reemplazos.txt
git filter-repo --replace-text reemplazos.txt
./gitleaks git --config .gitleaks.toml .   # debe decir "no leaks found"
git push --force --all
```

## §6. Evidencia de un ciclo real

**Prueba de bloqueo.** En la rama `feat/secret-antes` se agregó a propósito un archivo con una clave JWT inventada escrita en el código (`src/securebank/config_local.py`). La clave nunca se usó en ningún ambiente.

| Prueba | Rama | Resultado esperado | Run |
| :-- | :-- | :-- | :-- |
| Clave JWT hardcodeada | `feat/secret-antes` | 🔴 `secret-scan` falla (regla `securebank-jwt-secret`, exit 1). `build`, `sast`, `sca` y `package` no corren. | _(pegar enlace del run)_ |
| Repo sin secretos | `feat/s07-secret-scanning` | 🟢 `secret-scan` pasa y el resto del pipeline sigue | _(pegar enlace del run)_ |
| Pre-commit local | — | El commit con la clave no se crea (`leaks found: 1`) | _(captura)_ |

**Ciclo de respuesta aplicado a la prueba:**

1. Detectar: el pipeline falló en `secret-scan` con la regla `securebank-jwt-secret` en `src/securebank/config_local.py`.
2. Revocar: no aplica en la práctica (la clave era inventada), pero se registra como si fuera real: la clave queda en la lista de valores prohibidos.
3. Rotar: se generó una clave nueva con `secrets.token_hex(32)` y se dejó solo como variable de entorno.
4. Limpiar: la rama `feat/secret-antes` nunca se mergea a `main` y se borra después de la entrega.
5. Notificar: este documento.

**Registro de rotaciones e incidentes**

| Fecha | Secreto | Motivo | Quién | Run / evidencia |
| :-- | :-- | :-- | :-- | :-- |
| 02-11-2026 | `SECUREBANK_JWT_SECRET` (prueba) | Ejercicio de la Sesión 7 | Equipo | _(enlace)_ |
