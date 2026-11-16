"""Consolida los reportes de los scanners en un único findings.json para el security gate (Sesión 9).

Cada scanner del pipeline deja su reporte como artefacto; este script los normaliza a conteos
por severidad para que OPA evalúe policy/security-policy-v1.rego con una sola entrada.

    secrets    ← gitleaks.sarif          (Gitleaks, Sesión 7)
    sast       ← sast.sarif              (Semgrep, Sesión 5)
    sca        ← trivy-vulns.json        (Trivy sobre dependencias, Sesión 6)
    container  ← trivy-image.json        (Trivy sobre securebank:v2-secure, Sesión 10)
    dast       ← zap-report.json         (ZAP Baseline, Sesión 8)
    coverage   ← coverage.xml            (pytest-cov, formato Cobertura)

Uso:
    python scripts/consolidar_findings.py --out findings.json \
        --secrets gitleaks.sarif --sast sast.sarif --sca trivy-vulns.json \
        --container trivy-image.json --dast zap-report.json --coverage coverage.xml \
        --context policy/context.json

Si un reporte no existe, el scanner queda con status "missing" y la política lo bloquea:
un control que no corrió no puede contarse como aprobado.
"""
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

SEVERIDADES = ("critical", "high", "medium", "low")


def _vacio(**extra):
    return {"status": "ok", **{s: 0 for s in SEVERIDADES}, **extra}


def _faltante():
    return {"status": "missing"}


def _leer_json(ruta):
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)


def secrets_desde_sarif(sarif):
    total = sum(len(run.get("results") or []) for run in sarif.get("runs") or [])
    return {"status": "ok", "total": total}


def sast_desde_sarif(sarif):
    """Semgrep: error → high (critical si security-severity ≥ 9.0) · warning → medium · note → low."""
    out = _vacio()
    for run in sarif.get("runs") or []:
        reglas = {}
        for regla in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            reglas[regla.get("id")] = regla
        for res in run.get("results") or []:
            regla = reglas.get(res.get("ruleId")) or {}
            nivel = res.get("level") or (regla.get("defaultConfiguration") or {}).get("level") or "warning"
            try:
                puntaje = float((regla.get("properties") or {}).get("security-severity", 0))
            except (TypeError, ValueError):
                puntaje = 0.0
            if nivel == "error":
                out["critical" if puntaje >= 9.0 else "high"] += 1
            elif nivel == "warning":
                out["medium"] += 1
            else:
                out["low"] += 1
    return out


def trivy_vulns(reporte):
    """Cuenta CVE únicos por severidad; fixable_* = los que ya tienen versión corregida."""
    out = _vacio(fixable_critical=0, fixable_high=0)
    vistos = set()
    for resultado in reporte.get("Results") or []:
        for v in resultado.get("Vulnerabilities") or []:
            clave = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
            if clave in vistos:
                continue
            vistos.add(clave)
            sev = (v.get("Severity") or "UNKNOWN").lower()
            if sev not in SEVERIDADES:
                sev = "low"
            out[sev] += 1
            if sev in ("critical", "high") and v.get("FixedVersion"):
                out["fixable_" + sev] += 1
    return out


def dast_desde_zap(reporte):
    """ZAP: riskcode 3=High, 2=Medium, 1=Low, 0=Informational. Cuenta tipos de alerta, no instancias."""
    out = {"status": "ok", "high": 0, "medium": 0, "low": 0, "info": 0, "alerts": []}
    nombres = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    for sitio in reporte.get("site") or []:
        for alerta in sitio.get("alerts") or []:
            nivel = nombres.get(str(alerta.get("riskcode")), "info")
            out[nivel] += 1
            out["alerts"].append({"id": str(alerta.get("pluginid")), "name": alerta.get("name"), "risk": nivel})
    return out


def coverage_desde_cobertura(ruta):
    raiz = ET.parse(ruta).getroot()
    return {"status": "ok", "line_rate": round(float(raiz.get("line-rate", 0)) * 100, 2)}


def consolidar(rutas, contexto=None, metadata=None):
    lectores = {
        "secrets": lambda r: secrets_desde_sarif(_leer_json(r)),
        "sast": lambda r: sast_desde_sarif(_leer_json(r)),
        "sca": lambda r: trivy_vulns(_leer_json(r)),
        "container": lambda r: trivy_vulns(_leer_json(r)),
        "dast": lambda r: dast_desde_zap(_leer_json(r)),
        "coverage": coverage_desde_cobertura,
    }
    findings = {"metadata": metadata or {}, "context": contexto or {}}
    for scanner, leer in lectores.items():
        ruta = rutas.get(scanner)
        findings[scanner] = leer(ruta) if ruta and os.path.exists(ruta) else _faltante()
    return findings


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", required=True)
    for scanner in ("secrets", "sast", "sca", "container", "dast", "coverage"):
        p.add_argument("--" + scanner)
    p.add_argument("--context", help="metadatos de negocio versionados (policy/context.json)")
    a = p.parse_args(argv)

    contexto = _leer_json(a.context) if a.context else {}
    metadata = {
        "commit": os.environ.get("GITHUB_SHA", "local"),
        "ref": os.environ.get("GITHUB_REF", "local"),
        "run": os.environ.get("GITHUB_RUN_ID", "local"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    rutas = {k: getattr(a, k) for k in ("secrets", "sast", "sca", "container", "dast", "coverage")}
    findings = consolidar(rutas, contexto, metadata)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    for scanner in rutas:
        datos = {k: v for k, v in findings[scanner].items() if k != "alerts"}
        print(f"{scanner:<10} {datos}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
