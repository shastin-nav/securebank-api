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

    return app
