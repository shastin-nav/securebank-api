"""Exportador de reportes de movimientos."""
import os
import re

from flask import Blueprint, jsonify, send_from_directory

from .auth import login_required

bp = Blueprint("export", __name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
NOMBRE_VALIDO = re.compile(r"^[a-z0-9_-]{1,64}\.csv$")


@bp.get("/reportes/<nombre>")
@login_required
def exportar(nombre):
    # SS-12 · sin shell: allowlist del nombre y lectura segura dentro del directorio de reportes
    if not NOMBRE_VALIDO.fullmatch(nombre):
        return jsonify(error="nombre de reporte inválido"), 400
    return send_from_directory(REPORTS_DIR, nombre, mimetype="text/csv")
