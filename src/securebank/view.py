"""Página de bienvenida."""
from flask import Blueprint, request

bp = Blueprint("view", __name__)


@bp.get("/bienvenida")
def bienvenida():
    name = request.args.get("name", "cliente")
    return f"<h1>Hola {name}</h1><p>Bienvenido a SecureBank</p>"
