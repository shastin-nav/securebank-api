"""Pruebas de regresión de la Sesión 8 (DAST): cada hallazgo de ZAP cerrado queda protegido por un test."""
from securebank.app import SECURITY_HEADERS
from tests.unit.test_api import PASS_BENJA, SecureBankTestCase


class TestCabecerasDeSeguridad(SecureBankTestCase):
    RUTAS = ("/health", "/bienvenida?name=ana", "/no-existe", "/tasas/calcular?monto=1&tasa=1&meses=1")

    def test_todas_las_respuestas_traen_las_cabeceras(self):
        """ZAP 10038 / 10020 / 10021 / 10035 / 10063 / 90004: cabeceras ausentes."""
        for ruta in self.RUTAS:
            r = self.client.get(ruta)
            for nombre, valor in SECURITY_HEADERS.items():
                self.assertEqual(r.headers.get(nombre), valor, f"{ruta} · {nombre}")

    def test_respuestas_autenticadas_no_se_cachean(self):
        r = self.client.get("/accounts", headers=self.auth())
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_csp_no_permite_scripts_ni_frames(self):
        csp = self.client.get("/bienvenida").headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_no_se_anuncia_el_servidor(self):
        self.assertNotIn("Server", self.client.get("/health").headers)

    def test_sin_cors_permisivo(self):
        """Configuración incorrecta: la API no debe responder Access-Control-Allow-Origin: *."""
        r = self.client.get("/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("Access-Control-Allow-Origin", r.headers)


class TestErroresSinDetalles(SecureBankTestCase):
    def test_404_es_json_sin_html(self):
        r = self.client.get("/admin")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json(), {"error": "no encontrado"})

    def test_405_es_json(self):
        r = self.client.delete("/health")
        self.assertEqual(r.status_code, 405)
        self.assertEqual(r.get_json(), {"error": "método no permitido"})

    def test_rutas_sensibles_no_expuestas(self):
        """Endpoints que ZAP prueba por defecto (/admin, /actuator) no existen."""
        for ruta in ("/admin", "/actuator", "/actuator/env", "/.env", "/.git/config"):
            self.assertEqual(self.client.get(ruta).status_code, 404, ruta)


class TestBOLA(SecureBankTestCase):
    """Ejercicio BOLA de la Sesión 8: Alice cambia el id del path y no debe ver datos de Bob."""

    def test_movimientos_de_cuenta_ajena_es_403(self):
        r = self.client.get("/accounts/2001/movements", headers=self.auth())
        self.assertEqual(r.status_code, 403)

    def test_detalle_de_cuenta_ajena_no_filtra_saldo(self):
        r = self.client.get("/accounts/2001", headers=self.auth())
        self.assertEqual(r.status_code, 403)
        self.assertNotIn(b"10000", r.data)

    def test_dueno_si_ve_su_cuenta(self):
        r = self.client.get("/accounts/2001", headers=self.auth("benja", PASS_BENJA))
        self.assertEqual(r.status_code, 200)

    def test_perfil_solo_por_token(self):
        """No hay GET /users/<id>: el perfil se obtiene de /users/me con el sub del JWT."""
        self.assertEqual(self.client.get("/users/2", headers=self.auth()).status_code, 404)
        r = self.client.get("/users/me", headers=self.auth())
        self.assertEqual(r.get_json()["username"], "ana")
