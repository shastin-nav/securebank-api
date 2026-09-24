"""Transferencias entre cuentas (caso BOLA de la Sesión 3)."""
from flask import Blueprint, current_app, g, jsonify, request

from .accounts import get_account
from .auth import login_required
from .db import get_db

bp = Blueprint("transfers", __name__)


@bp.post("/transfer")
@login_required
def transfer():
    data = request.get_json(silent=True) or {}
    origin = str(data.get("originAccount", ""))
    target = str(data.get("targetAccount", ""))
    amount = data.get("amount")

    # AM-03 · el monto se valida en el servidor
    if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount <= current_app.config["TRANSFER_LIMIT"]:
        return jsonify(error="monto inválido"), 400
    if origin == target:
        return jsonify(error="cuentas de origen y destino iguales"), 400

    source = get_account(origin)
    dest = get_account(target)
    if source is None or dest is None:
        return jsonify(error="cuenta no encontrada"), 404

    # AM-10 · BOLA: el usuario autenticado debe ser dueño de la cuenta de origen
    if source["owner_id"] != g.user["id"]:
        current_app.logger.warning(
            "BOLA bloqueado: user=%s intentó debitar la cuenta %s", g.user["id"], origin
        )
        return jsonify(error="prohibido"), 403

    if source["balance"] < amount:
        return jsonify(error="saldo insuficiente"), 409

    conn = get_db()
    with conn:  # transacción atómica: o se aplica todo o nada
        conn.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, origin))
        conn.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, target))
        conn.execute(
            "INSERT INTO movements (user_id, origin, target, amount) VALUES (?, ?, ?, ?)",
            (g.user["id"], origin, target, amount),
        )
    current_app.logger.info("transferencia: user=%s %s -> %s monto=%s", g.user["id"], origin, target, amount)
    return jsonify(status="ok", originAccount=origin, targetAccount=target, amount=amount), 201
