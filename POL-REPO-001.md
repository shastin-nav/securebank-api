# POL-REPO-001: Política de Repositorios Seguros

**Versión:** 1.1 · **Fecha:** 24 de septiembre de 2026 · **Próxima revisión:** marzo de 2027
**Integrantes:** Benjamín Garrido · Abdiel Ortiz · Justin Navarro · Emilio Santibáñez

**Escenario:** empresa fintech con 40 desarrolladores en 5 equipos, 1 lead de seguridad, 1 SRE y 2 revisores externos. Repositorio de referencia: `securebank-api`.

---

## § 1. Alcance
Aplica a todo repositorio de código productivo o pre-productivo (desarrollo, pruebas y staging), a sus workflows de CI/CD (`.github/workflows/`) y a toda cuenta humana o de servicio con acceso a ellos, incluidos proveedores y revisores externos.

## § 2. Roles y responsabilidades

| Rol | Quién (escenario) | Responsabilidades verificables |
| :-- | :-- | :-- |
| **Developer** | 40 devs (5 equipos) | Trabaja en `feature/*` o `fix/*`. Firma sus commits (GPG/SSH). Tiene MFA activo. Abre un PR sin alertas de linter ni de SAST. |
| **Reviewer** | 1 senior por equipo + 2 externos | Revisa calidad y seguridad. Confirma que no haya secretos. Responde en menos de 24 h. Los externos solo pueden comentar y aprobar; nunca hacen merge. |
| **Code Owner** | Tech lead de cada equipo; lead de seguridad para `.github/` | Mantiene `.github/CODEOWNERS` y aprueba cambios en los módulos críticos que tiene a cargo. |
| **Release Manager** | SRE + 1 suplente | Crea tags y releases firmados. Verifica que el artefacto venga de un build en verde. |
| **Secret Custodian** | Lead de seguridad + SRE (2 personas nombradas) | Administra GitHub Secrets por entorno. Rota credenciales cada 90 días o ante un incidente. Monitorea el secret scanning. |

## § 3. Reglas técnicas obligatorias
1. **MFA obligatorio** (FIDO2 o TOTP) para toda la organización. Quien no lo tenga activo pierde el acceso de forma automática.
2. **`main` protegida:** sin push directo, sin `--force` y **sin borrado de la rama**. Las reglas también aplican a los administradores (*Do not allow bypassing*).
3. **PR con ≥1 aprobación + Code Owner.** Un nuevo push invalida las aprobaciones anteriores (*dismiss stale reviews*). Todas las conversaciones deben quedar resueltas antes del merge.
4. **Commits firmados:** se bloquea todo commit sin firma verificada.
5. **Secret scanning + push protection** activos, más `.gitignore` para `.env`, `*.pem` y `credentials.json`.
6. **Status checks obligatorios:** pipeline CI en verde (build, tests y SAST) para poder mergear.
7. **PRs desde forks:** sus workflows necesitan la aprobación de un maintainer antes de ejecutarse y **no reciben secretos**. Las acciones de terceros se fijan por versión o SHA.
8. **Mínimo privilegio y revisión de accesos:** se revisan cada trimestre. El *offboarding* se hace el mismo día. Los accesos de externos expiran a los 90 días.

## § 4. Cobertura de riesgos

| # | Riesgo (Sesión 2) | Control aplicado (regla §3) |
| :-: | :-- | :-- |
| R1 | Exposición de secretos | 5 (scanning + push protection), Secret Custodian, rotación |
| R2 | Modificación maliciosa de código | 3 (revisión + CODEOWNERS), 6 (CI obligatorio) |
| R3 | Eliminación de ramas | 2 (sin force push ni borrado de `main`) |
| R4 | Commits no autorizados | 1 (MFA), 4 (commits firmados) |
| R5 | Colaboradores externos | 8 (mínimo privilegio, expiración, offboarding) |
| R6 | PRs hostiles / pipelines alterados | 7 (forks sin secretos), CODEOWNERS de `.github/` |
| R7 | Repositorio como activo de negocio | Todas las anteriores + auditoría del historial y de los logs de la organización |

## § 5. Matriz "quién puede qué"

| Pregunta | Developer | Reviewer | Code Owner | Release Mgr. | Secret Custodian |
| :-- | :-: | :-: | :-: | :-: | :-: |
| **Q1 · Hacer merge a `main`** (tras ≥1 aprobación + CI verde) | ❌ | ❌ | ✅ | ✅ | ❌ |
| **Q2 · Modificar pipelines** (`.github/workflows/`) | Propone vía PR | ❌ | ✅ (lead de seguridad) | ❌ | ❌ |
| **Q3 · Crear releases** (tag firmado, ventana semanal) | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Q4 · Modificar secretos** (por entorno) | ❌ | ❌ | ❌ | ❌ | ✅ (solo 2 personas) |

- **Q1:** el auto-merge solo se permite en PRs de Dependabot de tipo *patch* con el CI en verde. Los PRs desde forks nunca se mergean de forma automática.
- **Q2:** todo cambio en `.github/workflows/` necesita una aprobación extra del lead de seguridad y se prohíben las acciones no verificadas.
- **Q3:** cada release va con un checklist previo (CI verde, SAST sin hallazgos altos, changelog) y trazabilidad hasta su ticket.
- **Q4:** cada acceso a un secreto queda auditado y los secretos de dev y prod están separados. Si hay que rotar de urgencia, se sigue §6.

## § 6. Excepciones y revisión
- **Hotfix / emergencia (P1):** se registra un ticket de incidente. Requiere la aprobación del Code Owner **y** del lead de seguridad. La excepción dura 4 h como máximo, y luego hay que abrir un PR retroactivo y hacer un post-mortem dentro de 24 h.
- **Otras excepciones:** se solicitan por *issue* con la etiqueta `excepcion-politica`, con justificación y fecha de término, y las aprueba el lead de seguridad.
- **Revisión:** la política se revisa cada 6 meses o después de cualquier incidente o auditoría relevante.
