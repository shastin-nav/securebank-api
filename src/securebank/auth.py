"""Autenticación: hash de contraseñas, login y verificación de JWT."""
import datetime
import functools
import hashlib

import jwt
from flask import Blueprint, current_app, g, jsonify, request

bp = Blueprint("auth", __name__)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash


def issue_token(user):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "iat": now,
        "exp": now + datetime.timedelta(minutes=current_app.config["JWT_EXP_MINUTES"]),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")


def login_required(view):
    """Exige un JWT válido y carga al usuario desde la BD (el rol no se toma del token)."""

    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="token requerido"), 401
        from . import users

        try:
            claims = jwt.decode(header[7:], current_app.config["JWT_SECRET"], algorithms=["HS256"])
            user = users.find_by_id(int(claims["sub"]))
        except (jwt.InvalidTokenError, KeyError, ValueError):
            return jsonify(error="token inválido"), 401
        if user is None:
            return jsonify(error="token inválido"), 401
        g.user = user
        return view(*args, **kwargs)

    return wrapped


@bp.post("/login")
def login():
    from . import users

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    user = users.find_by_username(username)
    if user is None or not verify_password(password, user["password_hash"]):
        return jsonify(error="credenciales inválidas"), 401
    return jsonify(access_token=issue_token(user), token_type="Bearer")
