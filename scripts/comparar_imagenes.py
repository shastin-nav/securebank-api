"""Tabla comparativa securebank:v1 vs securebank:v2-secure (Sesión 10).

Lee, para cada imagen, el reporte JSON de Trivy (generado con --list-all-pkgs) y la salida de
`docker image inspect`, y escribe la tabla de la lámina 13 en Markdown.

Uso:
    python scripts/comparar_imagenes.py \
        --v1-trivy trivy-image-v1.json --v1-inspect inspect-v1.json \
        --v2-trivy trivy-image-v2.json --v2-inspect inspect-v2.json \
        --out comparacion-imagenes.md
"""
import argparse
import json
import sys


def _leer(ruta):
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)


def metricas(trivy, inspect):
    if isinstance(inspect, list):
        inspect = inspect[0]
    vulns, paquetes = set(), set()
    for res in trivy.get("Results") or []:
        for p in res.get("Packages") or []:
            paquetes.add((p.get("Name"), p.get("Version")))
        for v in res.get("Vulnerabilities") or []:
            if (v.get("Severity") or "").upper() in ("HIGH", "CRITICAL"):
                vulns.add((v.get("VulnerabilityID"), v.get("PkgName")))
    config = inspect.get("Config") or {}
    usuario = config.get("User") or "root"
    if usuario in ("0", "0:0", "root"):
        usuario = "root (uid 0)"
    return {
        "vulns": len(vulns),
        "tamano_mb": round(inspect.get("Size", 0) / 1_000_000),
        "paquetes": len(paquetes),
        "usuario": usuario,
        "puertos": ", ".join(sorted(config.get("ExposedPorts") or {})) or "ninguno",
        "base": (trivy.get("Metadata") or {}).get("OS", {}).get("Name", "?"),
        "familia": (trivy.get("Metadata") or {}).get("OS", {}).get("Family", "?"),
    }


def delta(antes, despues):
    if not antes:
        return "—"
    return f"↓ {round((antes - despues) / antes * 100)} %" if despues <= antes else f"↑ {round((despues - antes) / antes * 100)} %"


def tabla(m1, m2):
    filas = [
        "| Métrica | securebank:v1 | securebank:v2-secure | Δ mejora |",
        "| :-- | --: | --: | :-- |",
        f"| Vulnerabilidades (HIGH + CRITICAL) | {m1['vulns']} | {m2['vulns']} | {delta(m1['vulns'], m2['vulns'])} |",
        f"| Tamaño de la imagen | {m1['tamano_mb']} MB | {m2['tamano_mb']} MB | {delta(m1['tamano_mb'], m2['tamano_mb'])} |",
        f"| Paquetes instalados | {m1['paquetes']} | {m2['paquetes']} | {delta(m1['paquetes'], m2['paquetes'])} |",
        f"| Usuario de ejecución | {m1['usuario']} | {m2['usuario']} | {'✓ mínimo privilegio' if 'root' not in m2['usuario'] else '✕'} |",
        f"| Puertos expuestos | {m1['puertos']} | {m2['puertos']} | {'✓ solo la app' if '22/tcp' not in m2['puertos'] else '✕'} |",
        f"| Sistema base | {m1['familia']} {m1['base']} | {m2['familia']} {m2['base']} | |",
    ]
    return "\n".join(filas) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser()
    for v in ("v1", "v2"):
        p.add_argument(f"--{v}-trivy", required=True)
        p.add_argument(f"--{v}-inspect", required=True)
    p.add_argument("--out")
    a = p.parse_args(argv)
    m1 = metricas(_leer(a.v1_trivy), _leer(a.v1_inspect))
    m2 = metricas(_leer(a.v2_trivy), _leer(a.v2_inspect))
    texto = tabla(m1, m2)
    print(texto)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
