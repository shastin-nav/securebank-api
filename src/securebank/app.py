"""Fábrica de la aplicación Flask."""
import os
import secrets

from flask import Flask, jsonify

from . import db


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("SECUREBANK_DB", os.path.join(app.instance_path, "securebank.sqlite")),
        # La clave de firma JWT viene del entorno (GitHub Secrets / gestor de secretos).
        # Si no existe se genera una aleatoria por proceso: nunca hay una clave fija en el código.
        JWT_SECRET=os.environ.get("SECUREBANK_JWT_SECRET") or secrets.token_hex(32),
        JWT_EXP_MINUTES=15,
        TRANSFER_LIMIT=1_000_000,
        MAX_CONTENT_LENGTH=16 * 1024,  # AM-09: rechaza payloads masivos (413)
    )
    if config:
        app.config.update(config)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    from . import accounts, auth, calc, export, transfers, users, view

    for module in (auth, users, accounts, transfers, export, calc, view):
        app.register_blueprint(module.bp)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    register_security_headers(app)
    register_error_handlers(app)
    return app


# Sesión 8 · DAST: cabeceras que el ZAP Baseline Scan reportó como ausentes.
# Equivalente en Flask a helmet() de Express (plan de mitigación, docs/dast/reporte-dast.md).
SECURITY_HEADERS = {
    # La API solo entrega JSON y una página sin scripts: nada se carga desde ningún origen.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Frame-Options": "DENY",  # anti-clickjacking (ZAP 10020)
    "X-Content-Type-Options": "nosniff",  # ZAP 10021
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",  # ZAP 10035 (detrás de TLS)
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",  # ZAP 10063
    "Cross-Origin-Resource-Policy": "same-origin",  # ZAP 90004 (Spectre / site isolation)
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",  # datos bancarios: nunca en caché (ZAP 10049)
}


def register_security_headers(app):
    @app.after_request
    def add_security_headers(response):
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        # No anunciar el servidor ni su versión (configuraciones incorrectas · ZAP 10036)
        response.headers.pop("Server", None)
        return response


def register_error_handlers(app):
    """Errores en JSON y sin detalles internos (ZAP: verbose errors / application error disclosure)."""

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify(error="no encontrado"), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify(error="método no permitido"), 405

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify(error="payload demasiado grande"), 413

    @app.errorhandler(500)
    def internal_error(_e):
        return jsonify(error="error interno"), 500
