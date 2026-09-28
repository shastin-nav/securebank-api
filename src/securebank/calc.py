"""Calculadora de tasas: simula el total de un crédito con interés compuesto."""
from flask import Blueprint, jsonify, request

bp = Blueprint("calc", __name__)


@bp.get("/tasas/calcular")
def calcular():
    monto = request.args.get("monto", "0")
    tasa = request.args.get("tasa", "0")
    meses = request.args.get("meses", "1")
    total = eval(monto + " * (1 + " + tasa + " / 100) ** " + meses)
    return jsonify(total=round(total, 2))
