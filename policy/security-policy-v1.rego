# SecurePipeline · Security Policy v1.0
# Grupo: Benjamín Garrido · Abdiel Ortiz · Justin Navarro · Emilio Santibáñez · Fecha: 16-11-2026
#
# Entrada: findings.json (scripts/consolidar_findings.py). Decisión: allow = true solo si deny está vacío.
# No hay reglas "de aviso": cada regla que se cumple agrega un motivo de bloqueo (Sesión 9, lámina 7).
# Justificación de cada umbral: policy/README.md
package securepipeline.gate

import rego.v1

default allow := false

allow if count(deny) == 0

# ---------- umbrales (un solo lugar para cambiarlos, siempre vía PR) ----------
umbral := {
	"sca_high_max": 2,
	"sca_medium_max": 10,
	"container_fixable_high_max": 2,
	"coverage_min": 80,
}

scanners_requeridos := {"secrets", "sast", "sca", "container", "dast", "coverage"}

# ---------- 0 · auditabilidad: todo control obligatorio debe haber corrido ----------
deny contains msg if {
	some scanner in scanners_requeridos
	object.get(input, [scanner, "status"], "missing") != "ok"
	msg := sprintf("%s: el reporte no existe o no se pudo leer (un control que no corrió no aprueba)", [scanner])
}

# ---------- 1 · no secrets (tolerancia cero) ----------
deny contains msg if {
	input.secrets.total > 0
	msg := sprintf("Secret scan: %d secreto(s) detectado(s) · máximo 0", [input.secrets.total])
}

# ---------- 2 · CRITICAL = 0 en todos los scanners ----------
deny contains msg if {
	input.sast.critical > 0
	msg := sprintf("SAST Critical: %d · máximo 0", [input.sast.critical])
}

deny contains msg if {
	input.sca.critical > 0
	msg := sprintf("SCA Critical: %d · máximo 0", [input.sca.critical])
}

deny contains msg if {
	input.container.fixable_critical > 0
	msg := sprintf("Imagen: %d CVE Critical con versión corregida disponible · máximo 0", [input.container.fixable_critical])
}

# ---------- 3 · HIGH acotado ----------
# SAST: un High en NUESTRO código siempre es corregible por nosotros → 0 (mismo criterio de la Sesión 5)
deny contains msg if {
	input.sast.high > 0
	msg := sprintf("SAST High: %d · máximo 0", [input.sast.high])
}

# SCA: deuda controlada de dependencias (≤ 2), igual que la lámina 7. Los CVSS 7.0–8.9 además
# pasan por el environment aprobacion-seguridad (semáforo de la Sesión 6).
deny contains msg if {
	input.sca.high > umbral.sca_high_max
	msg := sprintf("SCA High: %d · máximo %d", [input.sca.high, umbral.sca_high_max])
}

# Imagen: solo cuentan los High que YA tienen parche (exploitability accionable).
deny contains msg if {
	input.container.fixable_high > umbral.container_fixable_high_max
	msg := sprintf("Imagen High con parche disponible: %d · máximo %d", [input.container.fixable_high, umbral.container_fixable_high_max])
}

deny contains msg if {
	input.dast.high > 0
	msg := sprintf("DAST High: %d · máximo 0", [input.dast.high])
}

# ---------- 4 · MEDIUM ----------
deny contains msg if {
	input.sca.medium > umbral.sca_medium_max
	msg := sprintf("SCA Medium: %d · máximo %d", [input.sca.medium, umbral.sca_medium_max])
}

# ---------- 5 · criterio de riesgo: exposición × criticidad del negocio ----------
# La misma alerta Medium pesa distinto en una API bancaria pública que en un job interno (lámina 14).
dast_medium_max := 0 if {
	input.context.exposure_level == "internet"
	input.context.business_criticality == "alta"
} else := 2

deny contains msg if {
	input.dast.medium > dast_medium_max
	msg := sprintf(
		"DAST Medium: %d · máximo %d (exposure_level=%s, business_criticality=%s)",
		[input.dast.medium, dast_medium_max, object.get(input.context, "exposure_level", "?"), object.get(input.context, "business_criticality", "?")],
	)
}

# ---------- 6 · calidad = seguridad: coverage mínima ----------
deny contains msg if {
	input.coverage.line_rate < umbral.coverage_min
	msg := sprintf("Coverage: %.2f%% · mínimo %d%%", [input.coverage.line_rate, umbral.coverage_min])
}

# Resumen legible para el log del pipeline y el artefacto gate-decision.json
decision := {
	"allow": allow,
	"policy": "security-policy-v1",
	"deny": deny,
}
