"""Pruebas de la política de umbrales CVSS (Sesión 6)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
import politica_cvss as pc  # noqa: E402


def vuln(cve, pkg, score=None, severity="HIGH", fuente="nvd", campo="V3Score"):
    v = {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": "1.0", "FixedVersion": "2.0",
         "Severity": severity, "CweIDs": ["CWE-20"], "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}"}
    if score is not None:
        v["CVSS"] = {fuente: {campo: score}}
    return v


def reporte(*vulns):
    return {"SchemaVersion": 2, "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs",
                                              "Type": "pip", "Vulnerabilities": list(vulns)}]}


class TestClasificacion(unittest.TestCase):
    def test_limites_del_semaforo(self):
        self.assertEqual(pc.clasificar(10.0), pc.BLOQUEO)
        self.assertEqual(pc.clasificar(9.0), pc.BLOQUEO)
        self.assertEqual(pc.clasificar(8.9), pc.APROBACION)
        self.assertEqual(pc.clasificar(7.0), pc.APROBACION)
        self.assertEqual(pc.clasificar(6.9), pc.REGISTRO)
        self.assertEqual(pc.clasificar(0.0), pc.REGISTRO)

    def test_prefiere_nvd_sobre_ghsa(self):
        v = vuln("CVE-1", "x")
        v["CVSS"] = {"ghsa": {"V3Score": 5.0}, "nvd": {"V3Score": 9.8}}
        self.assertEqual(pc.puntaje_cvss(v)[0], 9.8)

    def test_usa_ghsa_y_cvss4_si_no_hay_nvd(self):
        self.assertEqual(pc.puntaje_cvss(vuln("CVE-1", "x", 7.5, fuente="ghsa"))[0], 7.5)
        self.assertEqual(pc.puntaje_cvss(vuln("CVE-1", "x", 9.3, fuente="ghsa", campo="V40Score"))[0], 9.3)

    def test_sin_cvss_usa_el_piso_de_la_severidad(self):
        self.assertEqual(pc.puntaje_cvss(vuln("CVE-1", "x", severity="CRITICAL"))[0], 9.0)
        self.assertEqual(pc.puntaje_cvss(vuln("CVE-1", "x", severity="MEDIUM"))[0], 4.0)


class TestEvaluacion(unittest.TestCase):
    def test_estado_bloqueado_con_un_critico(self):
        r = pc.evaluar(reporte(vuln("CVE-A", "urllib3", 9.8), vuln("CVE-B", "urllib3", 7.5), vuln("CVE-C", "urllib3", 4.2)))
        self.assertEqual(r["estado_pipeline"], "BLOQUEADO")
        self.assertEqual(r["resumen"], {"total": 3, "bloqueo": 1, "aprobacion": 1, "registro": 1})
        self.assertEqual(r["hallazgos"][0]["cve"], "CVE-A")  # ordenado por CVSS

    def test_estado_aprobacion_y_aprobado(self):
        self.assertEqual(pc.evaluar(reporte(vuln("CVE-B", "x", 7.5)))["estado_pipeline"], "REQUIERE APROBACION")
        self.assertEqual(pc.evaluar(reporte(vuln("CVE-C", "x", 3.1)))["estado_pipeline"], "APROBADO")
        self.assertEqual(pc.evaluar({"Results": [{"Target": "x"}]})["estado_pipeline"], "APROBADO")

    def test_no_duplica_el_mismo_cve(self):
        r = pc.evaluar({"Results": [{"Vulnerabilities": [vuln("CVE-A", "x", 9.8)]},
                                    {"Vulnerabilities": [vuln("CVE-A", "x", 9.8)]}]})
        self.assertEqual(r["resumen"]["total"], 1)


class TestSalida(unittest.TestCase):
    def ejecutar(self, rep):
        tmp = tempfile.mkdtemp()
        entrada = os.path.join(tmp, "trivy.json")
        with open(entrada, "w") as fh:
            json.dump(rep, fh)
        salida_gh = os.path.join(tmp, "gh_output")
        os.environ["GITHUB_OUTPUT"] = salida_gh
        try:
            codigo = pc.main(["x", entrada, os.path.join(tmp, "reports", "securebank-vulns")])
        finally:
            del os.environ["GITHUB_OUTPUT"]
        return codigo, tmp, open(salida_gh).read()

    def test_critico_sale_con_codigo_1_y_genera_reportes(self):
        codigo, tmp, gh = self.ejecutar(reporte(vuln("CVE-2018-20060", "urllib3", 9.8)))
        self.assertEqual(codigo, 1)
        self.assertTrue(os.path.exists(os.path.join(tmp, "reports", "securebank-vulns.json")))
        html = open(os.path.join(tmp, "reports", "securebank-vulns.html"), encoding="utf-8").read()
        self.assertIn("CVE-2018-20060", html)
        self.assertIn("requiere_aprobacion=false", gh)

    def test_alto_sale_con_0_y_pide_aprobacion(self):
        codigo, _, gh = self.ejecutar(reporte(vuln("CVE-B", "x", 7.5)))
        self.assertEqual(codigo, 0)
        self.assertIn("requiere_aprobacion=true", gh)

    def test_html_escapa_contenido(self):
        r = pc.evaluar(reporte(vuln("<script>", "x", 1.0)))
        self.assertNotIn("<script>", pc.a_html(r))
