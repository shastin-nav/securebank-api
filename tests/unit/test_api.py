"""Pruebas unitarias de SecureBank API (se ejecutan con pytest o unittest)."""
import datetime
import os
import shutil
import tempfile
import unittest

import jwt

from securebank import create_app
from securebank import users
from securebank.db import get_db

SECRET = "clave-de-pruebas-" + "x" * 32
PASS_ANA = "ana-contraseña-segura"
PASS_BENJA = "benja-contraseña-segura"


class SecureBankTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({
            "TESTING": True,
            "DATABASE": os.path.join(self.tmp, "test.sqlite"),
            "JWT_SECRET": SECRET,
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            self.ana_id = users.create_user("ana", PASS_ANA, "Ana Pérez")
            self.benja_id = users.create_user("benja", PASS_BENJA, "Benjamín Soto")
            conn = get_db()
            conn.execute("INSERT INTO accounts (id, owner_id, balance) VALUES ('1001', ?, 500000)", (self.ana_id,))
            conn.execute("INSERT INTO accounts (id, owner_id, balance) VALUES ('2001', ?, 10000)", (self.benja_id,))
            conn.commit()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- utilidades ---
    def token(self, username, password):
        r = self.client.post("/login", json={"username": username, "password": password})
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["access_token"]

    def auth(self, username="ana", password=PASS_ANA):
        return {"Authorization": "Bearer " + self.token(username, password)}

    def balance(self, account_id):
        with self.app.app_context():
            return get_db().execute("SELECT balance FROM accounts WHERE id = ?", (account_id,)).fetchone()[0]


class TestSaludYLogin(SecureBankTestCase):
    def test_health(self):
        self.assertEqual(self.client.get("/health").get_json(), {"status": "ok"})

    def test_login_correcto_entrega_jwt(self):
        r = self.client.post("/login", json={"username": "ana", "password": PASS_ANA})
        self.assertEqual(r.status_code, 200)
        claims = jwt.decode(r.get_json()["access_token"], SECRET, algorithms=["HS256"])
        self.assertEqual(claims["sub"], str(self.ana_id))

    def test_login_contraseña_incorrecta_es_401(self):
        r = self.client.post("/login", json={"username": "ana", "password": "mala"})
        self.assertEqual(r.status_code, 401)

    def test_login_usuario_inexistente_es_401(self):
        r = self.client.post("/login", json={"username": "nadie", "password": "x"})
        self.assertEqual(r.status_code, 401)

    def test_contraseña_no_se_guarda_en_texto_plano(self):
        with self.app.app_context():
            stored = users.find_by_id(self.ana_id)["password_hash"]
        self.assertNotEqual(stored, PASS_ANA)

    def test_registro_valida_datos(self):
        r = self.client.post("/users", json={"username": "x", "password": "corta", "nombre": ""})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/users", json={"username": "carla", "password": "carla-contraseña-ok", "nombre": "Carla"})
        self.assertEqual(r.status_code, 201)
        r = self.client.post("/users", json={"username": "carla", "password": "carla-contraseña-ok", "nombre": "Carla"})
        self.assertEqual(r.status_code, 409)


class TestTokens(SecureBankTestCase):
    """SS-02 / SS-11: solo JWT HS256 válidos; el rol sale de la BD."""

    def test_sin_token_es_401(self):
        self.assertEqual(self.client.get("/accounts").status_code, 401)

    def test_token_alg_none_es_401(self):
        forged = jwt.encode({"sub": str(self.ana_id)}, key=None, algorithm="none")
        r = self.client.get("/accounts", headers={"Authorization": "Bearer " + forged})
        self.assertEqual(r.status_code, 401)

    def test_token_con_otra_clave_es_401(self):
        forged = jwt.encode({"sub": str(self.ana_id)}, "otra-clave-" + "y" * 32, algorithm="HS256")
        r = self.client.get("/accounts", headers={"Authorization": "Bearer " + forged})
        self.assertEqual(r.status_code, 401)

    def test_token_expirado_es_401(self):
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        old = jwt.encode({"sub": str(self.ana_id), "exp": past}, SECRET, algorithm="HS256")
        r = self.client.get("/accounts", headers={"Authorization": "Bearer " + old})
        self.assertEqual(r.status_code, 401)

    def test_claim_role_admin_inyectado_no_da_privilegios(self):
        forged = jwt.encode({"sub": str(self.benja_id), "role": "admin"}, SECRET, algorithm="HS256")
        r = self.client.get("/accounts/1001", headers={"Authorization": "Bearer " + forged})
        self.assertEqual(r.status_code, 403)


class TestCuentas(SecureBankTestCase):
    def test_lista_solo_cuentas_propias(self):
        r = self.client.get("/accounts", headers=self.auth())
        self.assertEqual(r.get_json(), {"accounts": [{"id": "1001", "balance": 500000}]})

    def test_detalle_de_cuenta_propia(self):
        r = self.client.get("/accounts/1001", headers=self.auth())
        self.assertEqual(r.status_code, 200)

    def test_cuenta_ajena_es_403(self):
        """SS-06 · IDOR."""
        r = self.client.get("/accounts/2001", headers=self.auth())
        self.assertEqual(r.status_code, 403)

    def test_cuenta_inexistente_es_404(self):
        self.assertEqual(self.client.get("/accounts/9999", headers=self.auth()).status_code, 404)


class TestTransferencias(SecureBankTestCase):
    def test_transferencia_correcta_mueve_saldos(self):
        r = self.client.post("/transfer", headers=self.auth(),
                             json={"originAccount": "1001", "targetAccount": "2001", "amount": 15000})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.balance("1001"), 485000)
        self.assertEqual(self.balance("2001"), 25000)
        mov = self.client.get("/accounts/1001/movements", headers=self.auth()).get_json()["movements"]
        self.assertEqual(mov[0]["amount"], 15000)

    def test_transfer_desde_cuenta_ajena_es_403(self):
        """SS-10 · BOLA: benja intenta debitar la cuenta 1001 de ana."""
        r = self.client.post("/transfer", headers=self.auth("benja", PASS_BENJA),
                             json={"originAccount": "1001", "targetAccount": "2001", "amount": 500000})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.balance("1001"), 500000)

    def test_monto_invalido_es_400(self):
        """SS-03 · el monto se valida en el servidor."""
        for amount in (-500, 0, 10.5, "100", True, 10_000_000, None):
            r = self.client.post("/transfer", headers=self.auth(),
                                 json={"originAccount": "1001", "targetAccount": "2001", "amount": amount})
            self.assertEqual(r.status_code, 400, amount)
        self.assertEqual(self.balance("1001"), 500000)

    def test_saldo_insuficiente_es_409(self):
        r = self.client.post("/transfer", headers=self.auth("benja", PASS_BENJA),
                             json={"originAccount": "2001", "targetAccount": "1001", "amount": 20000})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.balance("2001"), 10000)

    def test_payload_masivo_es_413(self):
        """SS-09 · límite de tamaño del request."""
        r = self.client.post("/transfer", headers=self.auth(), data="x" * 20000,
                             content_type="application/json")
        self.assertEqual(r.status_code, 413)


class TestOtrosEndpoints(SecureBankTestCase):
    def test_exportar_reporte(self):
        r = self.client.get("/reportes/movimientos-ejemplo.csv", headers=self.auth())
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"fecha,origen,destino,monto", r.data)

    def test_exportar_requiere_login(self):
        self.assertEqual(self.client.get("/reportes/movimientos-ejemplo.csv").status_code, 401)

    def test_calcular_interes_compuesto(self):
        r = self.client.get("/tasas/calcular?monto=1000&tasa=2&meses=12")
        self.assertEqual(r.status_code, 200)
        self.assertAlmostEqual(r.get_json()["total"], 1268.24, places=2)

    def test_bienvenida_saluda_por_nombre(self):
        r = self.client.get("/bienvenida?name=Justin")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Hola Justin", r.data)


if __name__ == "__main__":
    unittest.main()
