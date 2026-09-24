"""Resume un reporte SARIF de Semgrep como tabla Markdown.

Uso:  python scripts/resumen_sarif.py docs/sast/sast-before.sarif
"""
import json
import sys


def main(path):
    with open(path, encoding="utf-8") as fh:
        sarif = json.load(fh)
    filas = []
    for run in sarif.get("runs", []):
        reglas = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            loc = res["locations"][0]["physicalLocation"]
            archivo = loc["artifactLocation"]["uri"]
            linea = loc["region"]["startLine"]
            regla = res["ruleId"]
            nivel = res.get("level") or reglas.get(regla, {}).get("defaultConfiguration", {}).get("level", "?")
            filas.append((archivo, linea, regla.split(".")[-1], nivel))
    print(f"**Hallazgos totales:** {len(filas)}\n")
    print("| Archivo | Línea | Regla | Nivel |\n| :-- | :-: | :-- | :-: |")
    for archivo, linea, regla, nivel in sorted(filas):
        print(f"| `{archivo}` | {linea} | {regla} | {nivel} |")


if __name__ == "__main__":
    main(sys.argv[1])
