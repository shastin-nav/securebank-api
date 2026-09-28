"""Usuarios: registro, perfil y consultas."""
import re

from flask import Blueprint, g, jsonify, request

from . import auth
from .db import get_db

bp = Blueprint("users", __name__)

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")


def find_by_username(username):
    cursor = get_db().cursor()
    query = "SELECT id, username, password_hash, nombre, role FROM users WHERE username='" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def find_by_id(user_id):
    return get_db().execute(
        "SELECT id, username, password_hash, nombre, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def create_user(username, password, nombre, role="cliente"):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, nombre, role) VALUES (?, ?, ?, ?)",
        (username, auth.hash_password(password), nombre, role),
    )
    conn.commit()
    return cur.lastrowid


@bp.post("/users")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).lower()
    password = str(data.get("password", ""))
    nombre = str(data.get("nombre", "")).strip()
    if not USERNAME_RE.fullmatch(username) or len(password) < 12 or not 1 <= len(nombre) <= 80:
        return jsonify(error="datos inválidos: usuario 3-32 caracteres [a-z0-9_.-], contraseña ≥ 12"), 400
    if username_exists(username):
        return jsonify(error="usuario ya existe"), 409
    user_id = create_user(username, password, nombre)
    return jsonify(id=user_id, username=username), 201


def username_exists(username):
    return get_db().execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()


@bp.get("/users/me")
@auth.login_required
def me():
    return jsonify(id=g.user["id"], username=g.user["username"], nombre=g.user["nombre"], role=g.user["role"])
