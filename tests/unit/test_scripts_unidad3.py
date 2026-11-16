"""Pruebas de los scripts de la Unidad III: gate IaC (Sesión 11) y comparación de imágenes (Sesión 10)."""
import json
import os
import tempfile
import unittest

from scripts import checkov_score, comparar_imagenes

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SEVERIDAD = os.path.join(RAIZ, "infra", "checkov-severity.json")


class TestGateIaC(unittest.TestCase):
    """Criterio de aceptación de la Sesión 11: un commit con violación CRITICAL bloquea el pipeline."""

    def test_reporte_inicial_bloquea(self):
        codigo = checkov_score.main([os.path.join(RAIZ, "reports/iac/checkov-before.json"), "--severity", SEVERIDAD])
        self.assertEqual(codigo, 1)

    def test_reporte_corregido_pasa_con_score_mayor_a_85(self):
        with tempfile.TemporaryDirectory() as tmp:
            salida = os.path.join(tmp, "score.json")
            codigo = checkov_score.main([
                os.path.join(RAIZ, "reports/iac/checkov-after.json"), "--severity", SEVERIDAD, "--json-out", salida,
            ])
            r = json.load(open(salida, encoding="utf-8"))
        self.assertEqual(codigo, 0)
        self.assertGreaterEqual(r["score"], 85)
        self.assertEqual(r["by_severity"]["CRITICAL"] + r["by_severity"]["HIGH"], 0)

    def test_check_no_mapeado_es_medium(self):
        self.assertEqual(checkov_score.severidad("CKV_AWS_99999", {"HIGH": []}), "MEDIUM")

    def test_score_bajo_el_minimo_bloquea_aunque_no_haya_high(self):
        rep = {"results": {"passed_checks": [{}] * 7, "failed_checks": [
            {"check_id": "CKV_AWS_23", "resource": "r", "check_name": "x"} for _ in range(3)
        ]}}
        with tempfile.TemporaryDirectory() as tmp:
            ruta = os.path.join(tmp, "c.json")
            json.dump(rep, open(ruta, "w"))
            self.assertEqual(checkov_score.main([ruta, "--severity", SEVERIDAD, "--min-score", "85"]), 1)


class TestComparacionImagenes(unittest.TestCase):
    def test_tabla_con_mejoras(self):
        v1 = {"Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}}, "Results": [{
            "Packages": [{"Name": f"p{i}", "Version": "1"} for i in range(150)],
            "Vulnerabilities": [{"VulnerabilityID": f"CVE-{i}", "PkgName": "p", "Severity": "HIGH"} for i in range(40)],
        }]}
        v2 = {"Metadata": {"OS": {"Family": "debian", "Name": "12.11"}}, "Results": [{
            "Packages": [{"Name": f"p{i}", "Version": "1"} for i in range(35)],
            "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "p", "Severity": "CRITICAL"}],
        }]}
        i1 = [{"Size": 780_000_000, "Config": {"User": "root", "ExposedPorts": {"22/tcp": {}, "8000/tcp": {}}}}]
        i2 = [{"Size": 120_000_000, "Config": {"User": "10001:10001", "ExposedPorts": {"8000/tcp": {}}}}]
        texto = comparar_imagenes.tabla(comparar_imagenes.metricas(v1, i1), comparar_imagenes.metricas(v2, i2))
        self.assertIn("| Vulnerabilidades (HIGH + CRITICAL) | 40 | 1 | ↓ 98 % |", texto)
        self.assertIn("| Tamaño de la imagen | 780 MB | 120 MB | ↓ 85 % |", texto)
        self.assertIn("root (uid 0) | 10001:10001 | ✓ mínimo privilegio", texto)
        self.assertIn("✓ solo la app", texto)
