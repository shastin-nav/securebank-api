"""Página de bienvenida."""
from flask import Blueprint, render_template, request

bp = Blueprint("view", __name__)


@bp.get("/bienvenida")
def bienvenida():
    name = request.args.get("name", "cliente")
    # SS-13 · plantilla Jinja con autoescape: la entrada del usuario se escapa sola
    return render_template("bienvenida.html", name=name)
