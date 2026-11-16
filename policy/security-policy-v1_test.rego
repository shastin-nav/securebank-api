# Pruebas automáticas de la política (opa test policy/*.rego -v).
# Caso verde = commit que debe pasar · caso rojo = commit que debe bloquearse.
package securepipeline.gate_test

import rego.v1

import data.securepipeline.gate

verde := {
	"context": {"business_criticality": "alta", "exposure_level": "internet"},
	"secrets": {"status": "ok", "total": 0},
	"sast": {"status": "ok", "critical": 0, "high": 0, "medium": 1, "low": 0},
	"sca": {"status": "ok", "critical": 0, "high": 1, "medium": 3, "low": 2, "fixable_critical": 0, "fixable_high": 1},
	"container": {"status": "ok", "critical": 1, "high": 6, "medium": 20, "low": 40, "fixable_critical": 0, "fixable_high": 1},
	"dast": {"status": "ok", "high": 0, "medium": 0, "low": 2, "info": 3},
	"coverage": {"status": "ok", "line_rate": 97.9},
}

con(ruta, valor) := json.patch(verde, [{"op": "replace", "path": ruta, "value": valor}])

# ---------- caso verde ----------
test_commit_verde_pasa if {
	gate.allow with input as verde
	count(gate.deny) == 0 with input as verde
}

test_cve_de_imagen_sin_parche_no_bloquea if {
	# 1 Critical y 6 High de la imagen base sin versión corregida: se reportan, no bloquean
	gate.allow with input as verde
}

test_sca_high_en_el_limite_pasa if {
	gate.allow with input as con("/sca/high", 2)
}

test_coverage_en_el_limite_pasa if {
	gate.allow with input as con("/coverage/line_rate", 80)
}

test_dast_medium_permitido_si_el_servicio_es_interno if {
	interno := json.patch(con("/dast/medium", 2), [{"op": "replace", "path": "/context/exposure_level", "value": "intranet"}])
	gate.allow with input as interno
}

# ---------- caso rojo ----------
test_commit_rojo_bloquea_con_todos_los_motivos if {
	rojo := json.patch(verde, [
		{"op": "replace", "path": "/secrets/total", "value": 1},
		{"op": "replace", "path": "/sca/high", "value": 4},
		{"op": "replace", "path": "/coverage/line_rate", "value": 72.5},
	])
	not gate.allow with input as rojo
	count(gate.deny) == 3 with input as rojo
}

test_un_secreto_bloquea if {
	not gate.allow with input as con("/secrets/total", 1)
}

test_sast_critical_bloquea if {
	not gate.allow with input as con("/sast/critical", 1)
}

test_sast_high_bloquea if {
	not gate.allow with input as con("/sast/high", 1)
}

test_sca_critical_bloquea if {
	not gate.allow with input as con("/sca/critical", 1)
}

test_sca_high_sobre_el_umbral_bloquea if {
	not gate.allow with input as con("/sca/high", 3)
}

test_sca_medium_sobre_el_umbral_bloquea if {
	not gate.allow with input as con("/sca/medium", 11)
}

test_imagen_critical_con_parche_bloquea if {
	not gate.allow with input as con("/container/fixable_critical", 1)
}

test_imagen_high_con_parche_sobre_el_umbral_bloquea if {
	not gate.allow with input as con("/container/fixable_high", 3)
}

test_dast_high_bloquea if {
	not gate.allow with input as con("/dast/high", 1)
}

test_dast_medium_bloquea_en_api_publica_critica if {
	not gate.allow with input as con("/dast/medium", 1)
}

test_coverage_bajo_minimo_bloquea if {
	not gate.allow with input as con("/coverage/line_rate", 79.9)
}

test_scanner_que_no_corrio_bloquea if {
	sin_dast := json.remove(verde, ["dast"])
	not gate.allow with input as sin_dast
	some msg in gate.deny with input as sin_dast
	startswith(msg, "dast:")
}

test_scanner_con_reporte_ilegible_bloquea if {
	not gate.allow with input as con("/sca/status", "missing")
}
