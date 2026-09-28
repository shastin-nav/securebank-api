# Reporte SAST · antes y después

**Sesión 05:** SAST (Static Application Security Testing) · Sistemas Automatizados DevSecOps (UBO)
**Herramienta:** Semgrep 1.95.0 · reglas `p/owasp-top-ten` + reglas propias [`.semgrep/securebank.yml`](../../.semgrep/securebank.yml)
**Equipo:** Benjamín Garrido · Abdiel Ortiz · Justin Navarro · Emilio Santibáñez

## 1. Pipeline v1.2

```
build ──► unit-tests ──► SAST (Semgrep) ✦ ──► package
                              │
                              └─ severidad ERROR (HIGH/CRITICAL) ⇒ pipeline detenido
```

- El job `sast` publica el reporte `sast.sarif` como artefacto `sast-report-<sha>` (7 días).
- El paso *Security gate* falla si hay hallazgos de severidad ERROR, y `package` no se ejecuta.
- Desde la v1.2 las acciones de GitHub están fijadas por SHA de commit (ver §3.1).

## 2. Evidencia de ejecución

| | Commit | Resultado | Run del pipeline | SARIF |
| :-- | :-- | :-: | :-- | :-- |
| **Antes** | `b20d8ae` (rama `feat/sast-antes`) | ❌ FAIL | [run 36476277170](https://github.com/shastin-nav/securebank-api/actions/runs/36476277170) | [`sast-before.sarif`](sast-before.sarif) |
| **Después** | `c0ecf28` (rama `main`) | ✅ PASS | [run 36476238534](https://github.com/shastin-nav/securebank-api/actions/runs/36476238534) | [`sast-after.sarif`](sast-after.sarif) |
| **Después v1.2** | PR `fix/sesion5-entrega` (acciones por SHA) | ✅ PASS | `PEGAR_URL_DEL_RUN_DEL_PR` | artefacto `sast-report-<sha>` del run |


## 3. Hallazgos y clasificación

| # | Archivo:línea (antes) | Vulnerabilidad | OWASP Top 10 | CWE | Severidad | Amenaza | Regla |
| :-: | :-- | :-- | :-- | :-: | :-: | :-: | :-- |
| 1 | `users.py:16` | SQL Injection en `/login` | A03 · Injection | CWE-89 | CRITICAL | AM-04 | `securebank-sql-string-concat` |
| 2 | `export.py:17` | Command Injection en el exportador de reportes | A03 · Injection | CWE-78 | CRITICAL | AM-12 | `securebank-command-injection-shell-true` |
| 3 | `view.py:10` | Cross-Site Scripting en la plantilla de bienvenida | A03 · Injection | CWE-79 | HIGH | AM-13 | `securebank-xss-fstring-html` |
| 4 | `auth.py:13` | Hash MD5 en contraseñas | A02 · Cryptographic Failures | CWE-327 | HIGH | AM-14 | `securebank-weak-hash-md5` |
| 5 | `calc.py:12` | `eval()` sobre entrada del usuario | A03 · Injection (API peligrosa) | CWE-95 | CRITICAL | AM-12 | `securebank-dangerous-eval` |

**Antes:** 5 hallazgos (3 CRITICAL, 2 HIGH) → ❌ FAIL
**Después:** 0 hallazgos de las reglas propias → ✅ PASS

### 3.1 Todos los hallazgos del SARIF

Además de nuestras 5 reglas, el registro `p/owasp-top-ten` reporta otros hallazgos. Este es el total de cada SARIF:

| Origen | Antes | Después (v1.1) | Después (v1.2) |
| :-- | :-: | :-: | :-: |
| Reglas propias (`.semgrep/`), nivel error | 5 | 0 | 0 |
| Registro OWASP sobre las mismas 5 líneas vulnerables (`eval-injection`, `subprocess-shell-true`, `md5-used-as-password`, `insecure-hash-algorithm-md5`, `raw-html-format` ×2, `directly-returned-format-string`) | 7 | 0 | 0 |
| `github-actions-mutable-action-tag` en `ci.yml`, nivel warning | 10 | 10 | 0 (esperado) |
| **Total** | **22** | **10** | **0** |

Los 10 avisos de `mutable-action-tag` no bloqueaban el pipeline (son warning), pero señalan un riesgo real de cadena de suministro: un tag como `@v4` puede moverse a otro commit. En la v1.2 fijamos cada acción por su SHA (`actions/checkout@11d5960… # v4.4.0`, `actions/setup-python@a26af69… # v5.6.0`, `actions/upload-artifact@ea165f8… # v4.6.2`), que es la recomendación de la lámina 13 de la Sesión 4.

## 4. Correcciones aplicadas

| # | Archivo | Antes | Después | Por qué es seguro |
| :-: | :-- | :-- | :-- | :-- |
| 1 | `users.py` | `"... WHERE username='" + username + "'"` | `"... WHERE username = ?", (username,)` | El driver separa el código SQL de los datos; la entrada nunca se interpreta como SQL. |
| 2 | `export.py` | `subprocess.check_output("cat " + ruta, shell=True)` | Allowlist `^[a-z0-9_-]{1,64}\.csv$` + `send_from_directory` | No se invoca ninguna shell, y el nombre solo puede referirse a un CSV dentro del directorio de reportes. |
| 3 | `view.py` | `return f"<h1>Hola {name}</h1>..."` | `render_template("bienvenida.html", name=name)` | Jinja escapa automáticamente `<`, `>`, `&` y comillas. |
| 4 | `auth.py` | `hashlib.md5(password)` | `generate_password_hash(password)` | Hash adaptativo (scrypt) con sal aleatoria por usuario; resistente a tablas rainbow y fuerza bruta. |
| 5 | `calc.py` | `eval(monto + " * (1 + " + tasa ...)` | `float()` / `int()` + validación de rango | Solo se aceptan números y el cálculo usa operadores de Python, sin evaluar texto. |

**Diferencias con la solución de referencia de la clase:**
- En (2) se eliminó la shell por completo en vez de usar `subprocess.run(args, shell=False)`. Leer el archivo directamente es más simple y no ejecuta procesos.
- En (4) se usa scrypt (`werkzeug.security`, ya incluido con Flask) en vez de bcrypt. Ofrece la misma protección (hash adaptativo con sal) sin agregar dependencias.
- En (5) se usa una conversión numérica estricta en vez de `ast.literal_eval`, porque la calculadora solo necesita tres números.

## 5. Diff del código corregido

```diff
--- a/src/securebank/users.py
+++ b/src/securebank/users.py
 def find_by_username(username):
-    cursor = get_db().cursor()
-    query = "SELECT id, username, password_hash, nombre, role FROM users WHERE username='" + username + "'"
-    cursor.execute(query)
-    return cursor.fetchone()
+    # SS-04 · consulta parametrizada: el driver separa código SQL de datos
+    return get_db().execute(
+        "SELECT id, username, password_hash, nombre, role FROM users WHERE username = ?", (username,)
+    ).fetchone()

--- a/src/securebank/export.py
+++ b/src/securebank/export.py
-    salida = subprocess.check_output("cat " + os.path.join(REPORTS_DIR, nombre), shell=True)
-    return Response(salida, mimetype="text/csv")
+    if not NOMBRE_VALIDO.fullmatch(nombre):
+        return jsonify(error="nombre de reporte inválido"), 400
+    return send_from_directory(REPORTS_DIR, nombre, mimetype="text/csv")

--- a/src/securebank/view.py
+++ b/src/securebank/view.py
-    return f"<h1>Hola {name}</h1><p>Bienvenido a SecureBank</p>"
+    return render_template("bienvenida.html", name=name)

--- a/src/securebank/auth.py
+++ b/src/securebank/auth.py
 def hash_password(password):
-    return hashlib.md5(password.encode()).hexdigest()
+    return generate_password_hash(password)

 def verify_password(password, stored_hash):
-    return hash_password(password) == stored_hash
+    return check_password_hash(stored_hash, password)

--- a/src/securebank/calc.py
+++ b/src/securebank/calc.py
-    monto = request.args.get("monto", "0")
-    tasa = request.args.get("tasa", "0")
-    meses = request.args.get("meses", "1")
-    total = eval(monto + " * (1 + " + tasa + " / 100) ** " + meses)
+    try:
+        monto = float(request.args.get("monto", "0"))
+        tasa = float(request.args.get("tasa", "0"))
+        meses = int(request.args.get("meses", "1"))
+    except (TypeError, ValueError):
+        return jsonify(error="parámetros numéricos inválidos"), 400
+    if monto < 0 or tasa < 0 or not 0 < meses <= 600:
+        return jsonify(error="parámetros fuera de rango"), 400
+    total = monto * (1 + tasa / 100) ** meses
```

El diff completo se ve en el PR o con `git diff feat/sast-antes feat/sast`.

## 6. Pruebas de regresión

Cada corrección quedó protegida por un test en [`tests/unit/test_seguridad.py`](../../tests/unit/test_seguridad.py). Si alguien reintroduce el fallo, fallan tanto `unit-tests` como `sast`.

| Test | Verifica |
| :-- | :-- |
| `test_sqli_en_login_no_permite_bypass` | Una comilla en el usuario no altera la consulta (401) |
| `test_nombre_de_reporte_con_separador_es_400` | Nombres con `;`, `../` u otra extensión se rechazan |
| `test_calculadora_rechaza_expresiones` | `monto=1+1` se rechaza (400): solo números |
| `test_bienvenida_escapa_html` | `<b>` se devuelve como `&lt;b&gt;` |
| `test_hash_no_es_md5_y_tiene_sal` | El hash no tiene formato MD5 y cambia con cada registro |

## 7. Checklist del PR de entrega

- [x] ① `sast-before.sarif` y `sast-after.sarif` en `docs/sast/`
- [x] ② Tabla de clasificación por categoría OWASP (§3)
- [x] ③ Diff del código corregido (§5 y el propio PR)
- [x] ④ URL del run del pipeline en verde (§2)
- [x] Entrega mediante Pull Request (`fix/sesion5-entrega` → `main`)
