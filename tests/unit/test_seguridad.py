"""Pruebas de regresión de seguridad (Sesión 5): cada corrección SAST queda protegida por un test."""
import urllib.parse

from securebank import users
from tests.unit.test_api import PASS_ANA, SecureBankTestCase


class TestCorreccionesSAST(SecureBankTestCase):
    def test_sqli_en_login_no_permite_bypass(self):
        """SS-04: una comilla en el usuario no altera la consulta."""
        r = self.client.post("/login", json={"username": "ana' OR '1'='1", "password": "x"})
        self.assertEqual(r.status_code, 401)

    def test_nombre_de_reporte_con_separador_es_400(self):
        """SS-12: el nombre del reporte no puede encadenar comandos ni salir del directorio."""
        for nombre in ("x.csv;ls", "..%2Fapp.py", "reporte.txt"):
            r = self.client.get("/reportes/" + nombre, headers=self.auth())
            self.assertIn(r.status_code, (400, 404), nombre)
            self.assertNotEqual(r.status_code, 200, nombre)

    def test_reporte_inexistente_es_404(self):
        r = self.client.get("/reportes/no-existe.csv", headers=self.auth())
        self.assertEqual(r.status_code, 404)

    def test_calculadora_rechaza_expresiones(self):
        """SS-12: solo se aceptan números, nunca expresiones."""
        r = self.client.get("/tasas/calcular?monto=" + urllib.parse.quote("1+1") + "&tasa=2&meses=12")
        self.assertEqual(r.status_code, 400)

    def test_calculadora_rechaza_fuera_de_rango(self):
        r = self.client.get("/tasas/calcular?monto=-5&tasa=2&meses=12")
        self.assertEqual(r.status_code, 400)

    def test_bienvenida_escapa_html(self):
        """SS-13: la entrada del usuario se escapa en la salida HTML."""
        r = self.client.get("/bienvenida?name=" + urllib.parse.quote("<b>Ana</b>"))
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b"<b>Ana</b>", r.data)
        self.assertIn(b"&lt;b&gt;", r.data)

    def test_hash_no_es_md5_y_tiene_sal(self):
        """SS-14: hash adaptativo con sal; dos registros de la misma clave dan hashes distintos."""
        with self.app.app_context():
            h1 = users.find_by_id(self.ana_id)["password_hash"]
            from securebank import auth
            h2 = auth.hash_password(PASS_ANA)
        self.assertNotRegex(h1, r"^[0-9a-f]{32}$")
        self.assertNotEqual(h1, h2)
