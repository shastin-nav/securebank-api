"""Exportador de reportes de movimientos."""
import os
import subprocess

from flask import Blueprint, Response

from .auth import login_required

bp = Blueprint("export", __name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


@bp.get("/reportes/<nombre>")
@login_required
def exportar(nombre):
    salida = subprocess.check_output("cat " + os.path.join(REPORTS_DIR, nombre), shell=True)
    return Response(salida, mimetype="text/csv")
