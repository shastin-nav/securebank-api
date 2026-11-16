"""Pruebas del consolidador de reportes del security gate (Sesión 9)."""
import json
import os
import tempfile
import unittest

from scripts import consolidar_findings as cf

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestNormalizacion(unittest.TestCase):
    def test_sarif_de_gitleaks_cuenta_secretos(self):
        sarif = {"runs": [{"results": [{"ruleId": "aws"}, {"ruleId": "jwt"}]}]}
        self.assertEqual(cf.secrets_desde_sarif(sarif), {"status": "ok", "total": 2})

    def test_sarif_de_semgrep_mapea_niveles(self):
        sarif = {"runs": [{
            "tool": {"driver": {"rules": [
                {"id": "sqli", "properties": {"security-severity": "9.8"}},
                {"id": "xss", "properties": {"security-severity": "7.5"}},
            ]}},
            "results": [
                {"ruleId": "sqli", "level": "error"},
                {"ruleId": "xss", "level": "error"},
                {"ruleId": "otro", "level": "warning"},
                {"ruleId": "otro", "level": "note"},
            ],
        }]}
        out = cf.sast_desde_sarif(sarif)
        self.assertEqual((out["critical"], out["high"], out["medium"], out["low"]), (1, 1, 1, 1))

    def test_trivy_cuenta_unicos_y_fixables(self):
        v = {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "3.0", "Severity": "HIGH", "FixedVersion": "3.1"}
        reporte = {"Results": [
            {"Vulnerabilities": [v, dict(v)]},  # duplicado en dos targets
            {"Vulnerabilities": [{"VulnerabilityID": "CVE-2", "PkgName": "zlib", "InstalledVersion": "1", "Severity": "CRITICAL"}]},
        ]}
        out = cf.trivy_vulns(reporte)
        self.assertEqual(out["high"], 1)
        self.assertEqual(out["critical"], 1)
        self.assertEqual(out["fixable_high"], 1)
        self.assertEqual(out["fixable_critical"], 0)

    def test_zap_usa_riskcode(self):
        reporte = {"site": [{"alerts": [
            {"pluginid": "10038", "name": "CSP", "riskcode": "2"},
            {"pluginid": "10021", "name": "XCTO", "riskcode": "1"},
            {"pluginid": "10049", "name": "Cache", "riskcode": "0"},
        ]}]}
        out = cf.dast_desde_zap(reporte)
        self.assertEqual((out["high"], out["medium"], out["low"], out["info"]), (0, 1, 1, 1))

    def test_reportes_reales_del_repo(self):
        """Los SARIF y el JSON de Trivy que ya están versionados se leen sin error."""
        out = cf.sast_desde_sarif(json.load(open(os.path.join(RAIZ, "docs/sast/sast-after.sarif"), encoding="utf-8")))
        self.assertEqual(out["status"], "ok")
        out = cf.trivy_vulns(json.load(open(os.path.join(RAIZ, "reports/trivy-vulns.json"), encoding="utf-8")))
        self.assertEqual(out["critical"], 0)


class TestConsolidar(unittest.TestCase):
    def test_reporte_faltante_queda_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cov = os.path.join(tmp, "coverage.xml")
            with open(cov, "w") as f:
                f.write('<?xml version="1.0" ?><coverage line-rate="0.9512"></coverage>')
            out = cf.consolidar({"coverage": cov, "dast": os.path.join(tmp, "no-existe.json")})
        self.assertEqual(out["coverage"], {"status": "ok", "line_rate": 95.12})
        self.assertEqual(out["dast"], {"status": "missing"})
        self.assertEqual(out["secrets"], {"status": "missing"})

    def test_cli_escribe_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            sarif = os.path.join(tmp, "gitleaks.sarif")
            with open(sarif, "w") as f:
                json.dump({"runs": [{"results": []}]}, f)
            salida = os.path.join(tmp, "findings.json")
            cf.main(["--out", salida, "--secrets", sarif, "--context", os.path.join(RAIZ, "policy/context.json")])
            findings = json.load(open(salida, encoding="utf-8"))
        self.assertEqual(findings["secrets"]["total"], 0)
        self.assertEqual(findings["context"]["exposure_level"], "internet")
