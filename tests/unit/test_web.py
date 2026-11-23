"""MVP web: la página /app, la cuenta que se abre al registrarse y los datos de demo."""
from securebank.db import get_db
from tests.unit.test_api import SecureBankTestCase


class TestPaginaBanca(SecureBankTestCase):
    def test_app_responde_html_con_sus_recursos(self):
        r = self.client.get("/app")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"/static/app.js", r.data)
        for recurso in ("/static/app.js", "/static/app.css"):
            self.assertEqual(self.client.get(recurso).status_code, 200, recurso)

    def test_csp_solo_permite_recursos_propios(self):
        csp = self.client.get("/app").headers["Content-Security-Policy"]
        for directiva in ("default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"):
            self.assertIn(directiva, csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)

    def test_resto_de_cabeceras_se_mantienen(self):
        r = self.client.get("/app")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertNotIn("Server", r.headers)

    def test_api_sigue_con_csp_estricta(self):
        self.assertTrue(self.client.get("/health").headers["Content-Security-Policy"].startswith("default-src 'none'"))

    def test_js_no_usa_innerhtml_ni_localstorage(self):
        js = self.client.get("/static/app.js").get_data(as_text=True)
        for peligroso in ("innerHTML", "outerHTML", "localStorage", "eval("):
            self.assertNotIn(peligroso, js)


class TestRegistroAbreCuenta(SecureBankTestCase):
    def test_registro_abre_cuenta_con_saldo_cero(self):
        r = self.client.post("/users", json={"username": "carla", "password": "carla-contraseña-ok", "nombre": "Carla"})
        self.assertEqual(r.status_code, 201)
        cuenta = r.get_json()["account"]
        headers = self.auth("carla", "carla-contraseña-ok")
        self.assertEqual(self.client.get("/accounts", headers=headers).get_json(), {"accounts": [{"id": cuenta, "balance": 0}]})

    def test_cuenta_nueva_puede_recibir_transferencias(self):
        cuenta = self.client.post(
            "/users", json={"username": "carla", "password": "carla-contraseña-ok", "nombre": "Carla"}
        ).get_json()["account"]
        r = self.client.post("/transfer", json={"originAccount": "1001", "targetAccount": cuenta, "amount": 2500}, headers=self.auth())
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.balance(cuenta), 2500)


class TestSeedDemo(SecureBankTestCase):
    def setUp(self):
        super().setUp()
        with self.app.app_context():  # base limpia: el seed crea ana y benja
            conn = get_db()
            conn.executescript("DELETE FROM accounts; DELETE FROM users;")

    def test_seed_crea_usuarios_con_clave_aleatoria(self):
        salida = self.app.test_cli_runner().invoke(args=["seed-demo"]).output
        lineas = salida.splitlines()
        self.assertEqual(len(lineas), 2)
        password = lineas[0].split(" / ")[1].split(" ")[0]
        self.assertGreaterEqual(len(password), 12)
        self.assertEqual(self.balance("1001"), 500_000)
        self.assertEqual(self.client.post("/login", json={"username": "ana", "password": password}).status_code, 200)

    def test_seed_es_idempotente(self):
        runner = self.app.test_cli_runner()
        runner.invoke(args=["seed-demo"])
        self.assertIn("ya existe", runner.invoke(args=["seed-demo"]).output)
