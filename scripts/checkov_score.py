"""Security Score y gate IaC sobre el reporte JSON de Checkov (Sesión 11).

    Security Score = checks_passed / (checks_passed + checks_failed) × 100

Checkov open source no entrega severidad, así que cada check se clasifica con el mapeo
versionado infra/checkov-severity.json (los no listados cuentan como MEDIUM).

Uso:
    python scripts/checkov_score.py checkov.json --severity infra/checkov-severity.json \
        --min-score 85 [--markdown resumen.md]

Códigos de salida: 0 = gate verde · 1 = hay CRITICAL/HIGH abiertos o el score es menor al mínimo.
"""
import argparse
import json
import sys
from collections import Counter

ORDEN = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def cargar_reporte(ruta):
    with open(ruta, encoding="utf-8") as f:
        datos = json.load(f)
    # Checkov devuelve un objeto (un framework) o una lista (varios frameworks)
    return datos if isinstance(datos, list) else [datos]


def severidad(check_id, mapa):
    for sev in ("CRITICAL", "HIGH", "LOW"):
        if check_id in mapa.get(sev, []):
            return sev
    return "MEDIUM"


def evaluar(reportes, mapa):
    passed, failed = 0, []
    for rep in reportes:
        res = rep.get("results") or {}
        passed += len(res.get("passed_checks") or [])
        for c in res.get("failed_checks") or []:
            failed.append({"id": c["check_id"], "resource": c["resource"], "name": c.get("check_name", ""),
                           "file": c.get("file_path", ""), "severity": severidad(c["check_id"], mapa)})
    total = passed + len(failed)
    score = round(passed / total * 100, 1) if total else 100.0
    conteo = Counter(f["severity"] for f in failed)
    return {"passed": passed, "failed": len(failed), "total": total, "score": score,
            "by_severity": {s: conteo.get(s, 0) for s in ORDEN}, "failed_checks": failed}


def markdown(r, min_score):
    lineas = [
        f"**Security Score:** {r['score']} % ({r['passed']} / {r['total']} checks) · mínimo {min_score} %",
        "",
        "| Severidad | Fallidos |", "| :-- | --: |",
        *[f"| {s} | {r['by_severity'][s]} |" for s in ORDEN],
        "",
    ]
    if r["failed_checks"]:
        lineas += ["| Severidad | Check | Recurso | Descripción |", "| :-- | :-- | :-- | :-- |"]
        for f in sorted(r["failed_checks"], key=lambda f: (ORDEN.index(f["severity"]), f["id"])):
            lineas.append(f"| {f['severity']} | {f['id']} | `{f['resource']}` | {f['name']} |")
    return "\n".join(lineas) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("reporte")
    p.add_argument("--severity", required=True)
    p.add_argument("--min-score", type=float, default=85.0)
    p.add_argument("--markdown")
    p.add_argument("--json-out")
    a = p.parse_args(argv)

    with open(a.severity, encoding="utf-8") as f:
        mapa = json.load(f)
    r = evaluar(cargar_reporte(a.reporte), mapa)
    texto = markdown(r, a.min_score)
    print(texto)
    if a.markdown:
        with open(a.markdown, "w", encoding="utf-8") as f:
            f.write(texto)
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2, ensure_ascii=False)

    bloqueantes = r["by_severity"]["CRITICAL"] + r["by_severity"]["HIGH"]
    if bloqueantes or r["score"] < a.min_score:
        print(f"GATE IaC: BLOQUEADO · {bloqueantes} CRITICAL/HIGH abiertos · score {r['score']} %")
        return 1
    print("GATE IaC: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
