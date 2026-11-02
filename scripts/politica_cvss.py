"""Política de umbrales CVSS de SecureBank (Sesión 6, semáforo).

Lee el reporte JSON de Trivy, clasifica cada CVE y genera el reporte de
componentes vulnerables en JSON y HTML.

    CVSS >= 9.0        -> BLOQUEO     (el pipeline falla, no se empaqueta)
    7.0 <= CVSS < 9.0  -> APROBACION  (el pipeline pausa hasta que un revisor apruebe)
    CVSS < 7.0         -> REGISTRO    (continúa; se anota en el backlog de deuda)

Uso:
    python scripts/politica_cvss.py reports/trivy-vulns.json reports/securebank-vulns

Códigos de salida: 0 = sin bloqueos, 1 = hay al menos un CVE crítico.
Si existe la variable GITHUB_OUTPUT, escribe requiere_aprobacion=true|false.
"""
import html
import json
import os
import sys
from datetime import datetime, timezone

BLOQUEO, APROBACION, REGISTRO = "BLOQUEO", "APROBACION", "REGISTRO"

# Si Trivy no trae puntaje CVSS, se usa el piso de su severidad.
PISO_POR_SEVERIDAD = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.1, "UNKNOWN": 0.0}

ACCION = {
    BLOQUEO: "Pipeline bloqueado: actualizar a la versión corregida antes de continuar.",
    APROBACION: "Requiere aprobación del líder técnico (environment aprobacion-seguridad).",
    REGISTRO: "Se registra en el backlog de deuda de seguridad para el próximo sprint.",
}


def puntaje_cvss(vuln):
    """Devuelve (puntaje, fuente). Prioridad: NVD, GHSA, el resto; v3 antes que v4."""
    cvss = vuln.get("CVSS") or {}
    fuentes = ["nvd", "ghsa"] + sorted(k for k in cvss if k not in ("nvd", "ghsa"))
    for campo in ("V3Score", "V40Score"):
        for fuente in fuentes:
            valor = (cvss.get(fuente) or {}).get(campo)
            if isinstance(valor, (int, float)) and valor > 0:
                return float(valor), f"{fuente} {campo}"
    sev = (vuln.get("Severity") or "UNKNOWN").upper()
    return PISO_POR_SEVERIDAD.get(sev, 0.0), f"severidad {sev}"


def clasificar(puntaje):
    if puntaje >= 9.0:
        return BLOQUEO
    if puntaje >= 7.0:
        return APROBACION
    return REGISTRO


def evaluar(reporte_trivy):
    hallazgos, vistos = [], set()
    for resultado in reporte_trivy.get("Results") or []:
        for v in resultado.get("Vulnerabilities") or []:
            clave = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
            if clave in vistos:
                continue
            vistos.add(clave)
            puntaje, fuente = puntaje_cvss(v)
            nivel = clasificar(puntaje)
            hallazgos.append({
                "cve": v.get("VulnerabilityID"),
                "componente": v.get("PkgName"),
                "version_instalada": v.get("InstalledVersion"),
                "version_corregida": v.get("FixedVersion") or "sin parche",
                "cvss": puntaje,
                "fuente_cvss": fuente,
                "severidad_trivy": v.get("Severity"),
                "cwe": v.get("CweIDs") or [],
                "clasificacion": nivel,
                "decision": ACCION[nivel],
                "referencia": v.get("PrimaryURL"),
            })
    hallazgos.sort(key=lambda h: (-h["cvss"], h["componente"] or "", h["cve"] or ""))
    resumen = {n: sum(1 for h in hallazgos if h["clasificacion"] == n) for n in (BLOQUEO, APROBACION, REGISTRO)}
    if resumen[BLOQUEO]:
        estado = "BLOQUEADO"
    elif resumen[APROBACION]:
        estado = "REQUIERE APROBACION"
    else:
        estado = "APROBADO"
    return {
        "generado": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "politica": {"bloqueo": "CVSS >= 9.0", "aprobacion": "7.0 <= CVSS < 9.0", "registro": "CVSS < 7.0"},
        "estado_pipeline": estado,
        "resumen": {"total": len(hallazgos), **{k.lower(): v for k, v in resumen.items()}},
        "hallazgos": hallazgos,
    }


COLOR = {BLOQUEO: "#c0392b", APROBACION: "#d68910", REGISTRO: "#2e7d32"}

# Plantilla fija; todo dato que viene del reporte pasa por html.escape() antes de insertarse.
PLANTILLA_HTML = """<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Reporte SCA SecureBank</title>
<style>body{{font-family:Arial,sans-serif;margin:24px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #999;padding:4px 6px;font-size:13px;text-align:left}}th{{background:#ddd}}</style></head><body>
<h1>Reporte de componentes vulnerables · SecureBank API</h1>
<p>Generado por el pipeline el {generado} con Trivy.</p>
<p><b>Estado del pipeline:</b> {estado} · Total: {total} · Bloqueo: {bloqueo} · Aprobación: {aprobacion} · Registro: {registro}</p>
<p><b>Política:</b> CVSS ≥ 9.0 bloquea · 7.0 a 8.9 requiere aprobación · menor a 7.0 se registra en el backlog.</p>
<table><tr><th>CVE</th><th>Componente</th><th>Versión</th><th>Corregida en</th><th>CVSS</th><th>Semáforo</th><th>Decisión</th></tr>{filas}</table>
</body></html>"""

FILA_HTML = ("<tr><td>{cve}</td><td>{componente}</td><td>{instalada}</td><td>{corregida}</td><td>{cvss:.1f}</td>"
             "<td style='color:{color};font-weight:bold'>{nivel}</td><td>{decision}</td></tr>")


def a_html(r):
    esc = lambda valor: html.escape(str(valor or ""))  # noqa: E731
    filas = "".join(
        FILA_HTML.format(cve=esc(h["cve"]), componente=esc(h["componente"]), instalada=esc(h["version_instalada"]),
                         corregida=esc(h["version_corregida"]), cvss=h["cvss"], color=COLOR[h["clasificacion"]],
                         nivel=h["clasificacion"], decision=esc(h["decision"]))
        for h in r["hallazgos"]
    ) or "<tr><td colspan='7'>Sin vulnerabilidades conocidas en las dependencias.</td></tr>"
    s = r["resumen"]
    pagina = PLANTILLA_HTML.format(generado=esc(r["generado"]), estado=esc(r["estado_pipeline"]), filas=filas,
                                   total=s["total"], bloqueo=s["bloqueo"], aprobacion=s["aprobacion"],
                                   registro=s["registro"])
    return pagina


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    entrada, salida = argv[1], argv[2]
    with open(entrada, encoding="utf-8") as fh:
        reporte = evaluar(json.load(fh))
    os.makedirs(os.path.dirname(salida) or ".", exist_ok=True)
    with open(salida + ".json", "w", encoding="utf-8") as fh:
        json.dump(reporte, fh, ensure_ascii=False, indent=2)
    with open(salida + ".html", "w", encoding="utf-8") as fh:
        fh.write(a_html(reporte))

    s = reporte["resumen"]
    print(f"Estado: {reporte['estado_pipeline']} | total={s['total']} bloqueo={s['bloqueo']} "
          f"aprobacion={s['aprobacion']} registro={s['registro']}")
    for h in reporte["hallazgos"]:
        print(f"  [{h['clasificacion']:10}] {h['cvss']:4.1f} {h['cve']} {h['componente']} {h['version_instalada']}")

    salida_gh = os.environ.get("GITHUB_OUTPUT")
    if salida_gh:
        with open(salida_gh, "a", encoding="utf-8") as fh:
            fh.write(f"requiere_aprobacion={'true' if s['aprobacion'] else 'false'}\n")
    return 1 if s["bloqueo"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
