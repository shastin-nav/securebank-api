"""Cuentas: consulta de saldos y movimientos (con autorización por recurso)."""
from flask import Blueprint, current_app, g, jsonify

from .auth import login_required
from .db import get_db

bp = Blueprint("accounts", __name__)


def get_account(account_id):
    return get_db().execute("SELECT id, owner_id, balance FROM accounts WHERE id = ?", (account_id,)).fetchone()


def can_access(account):
    return account["owner_id"] == g.user["id"] or g.user["role"] == "admin"


@bp.get("/accounts")
@login_required
def list_accounts():
    rows = get_db().execute("SELECT id, balance FROM accounts WHERE owner_id = ? ORDER BY id", (g.user["id"],)).fetchall()
    return jsonify(accounts=[dict(r) for r in rows])


@bp.get("/accounts/<account_id>")
@login_required
def account_detail(account_id):
    account = get_account(account_id)
    if account is None:
        return jsonify(error="cuenta no encontrada"), 404
    if not can_access(account):  # AM-06 · IDOR
        current_app.logger.warning("acceso denegado: user=%s cuenta=%s", g.user["id"], account_id)
        return jsonify(error="prohibido"), 403
    return jsonify(id=account["id"], balance=account["balance"])


@bp.get("/accounts/<account_id>/movements")
@login_required
def movements(account_id):
    account = get_account(account_id)
    if account is None:
        return jsonify(error="cuenta no encontrada"), 404
    if not can_access(account):
        return jsonify(error="prohibido"), 403
    rows = get_db().execute(
        "SELECT origin, target, amount, created_at FROM movements WHERE origin = ? OR target = ? ORDER BY id DESC",
        (account_id, account_id),
    ).fetchall()
    return jsonify(movements=[dict(r) for r in rows])
