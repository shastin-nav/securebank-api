"""Calculadora de tasas: simula el total de un crédito con interés compuesto."""
from flask import Blueprint, jsonify, request

bp = Blueprint("calc", __name__)


@bp.get("/tasas/calcular")
def calcular():
    # SS-12 · sin eval: se convierte cada parámetro a número y se calcula con operadores
    try:
        monto = float(request.args.get("monto", "0"))
        tasa = float(request.args.get("tasa", "0"))
        meses = int(request.args.get("meses", "1"))
    except (TypeError, ValueError):
        return jsonify(error="parámetros numéricos inválidos"), 400
    if monto < 0 or tasa < 0 or not 0 < meses <= 600:
        return jsonify(error="parámetros fuera de rango"), 400
    total = monto * (1 + tasa / 100) ** meses
    return jsonify(total=round(total, 2))
