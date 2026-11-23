"""MVP web: banca en línea mínima sobre la misma API (login, saldo, movimientos, transferir)."""
from flask import Blueprint, make_response, render_template

bp = Blueprint("web", __name__)

# La página necesita su JS y CSS propios: se permite 'self' y nada más (sin inline, sin CDNs).
# El resto de la API mantiene default-src 'none' (app.SECURITY_HEADERS).
APP_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


@bp.get("/app")
def banca():
    response = make_response(render_template("app.html"))
    response.headers["Content-Security-Policy"] = APP_CSP
    return response
