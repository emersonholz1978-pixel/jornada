import csv
import io
import os
import re
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, send_from_directory, Response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SQLITE_PATH = os.getenv("SQLITE_PATH", "/tmp/oab_facil.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def connection():
    if DATABASE_URL:
        import psycopg
        return psycopg.connect(DATABASE_URL)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema():
    conn = connection()
    try:
        if DATABASE_URL:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS registrations (
                        id BIGSERIAL PRIMARY KEY,
                        name VARCHAR(120) NOT NULL,
                        email VARCHAR(254) NOT NULL UNIQUE,
                        consent_at TIMESTAMPTZ NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS registrations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    consent_at TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        conn.commit()
    finally:
        conn.close()


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not ADMIN_TOKEN:
            return jsonify({"error": "Painel administrativo ainda não configurado."}), 503
        supplied = request.headers.get("X-Admin-Token", "")
        if supplied != ADMIN_TOKEN:
            return jsonify({"error": "Acesso não autorizado."}), 401
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def prepare_database():
    if request.endpoint not in {"static_file", "health"}:
        ensure_schema()


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/<path:filename>", endpoint="static_file")
def static_file(filename):
    return send_from_directory(BASE_DIR, filename)


@app.post("/api/cadastros")
def register_student():
    payload = request.get_json(silent=True) or request.form
    name = str(payload.get("name", "")).strip()
    email = str(payload.get("email", "")).strip().lower()
    consent = payload.get("consent")
    consent_ok = consent is True or str(consent).lower() in {"true", "1", "on", "yes"}

    if not name or len(name) > 120:
        return jsonify({"ok": False, "message": "Informe seu nome."}), 400
    if not EMAIL_RE.match(email) or len(email) > 254:
        return jsonify({"ok": False, "message": "Informe um e-mail válido."}), 400
    if not consent_ok:
        return jsonify({"ok": False, "message": "É necessário aceitar a Política de Privacidade."}), 400

    consent_at = datetime.now(timezone.utc)
    conn = connection()
    try:
        if DATABASE_URL:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO registrations (name, email, consent_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, consent_at = EXCLUDED.consent_at
                    RETURNING id
                    """,
                    (name, email, consent_at),
                )
                registration_id = cur.fetchone()[0]
        else:
            cur = conn.execute(
                "INSERT OR REPLACE INTO registrations (name, email, consent_at) VALUES (?, ?, ?)",
                (name, email, consent_at.isoformat()),
            )
            registration_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    return jsonify({"ok": True, "id": registration_id, "message": f"Obrigado, {name.split()[0]}! Seu cadastro foi recebido."}), 201


@app.get("/api/admin/cadastros.csv")
@admin_required
def registrations_csv():
    conn = connection()
    try:
        if DATABASE_URL:
            with conn.cursor() as cur:
                cur.execute("SELECT id, name, email, consent_at, created_at FROM registrations ORDER BY created_at DESC")
                rows = cur.fetchall()
        else:
            rows = conn.execute(
                "SELECT id, name, email, consent_at, created_at FROM registrations ORDER BY created_at DESC"
            ).fetchall()
    finally:
        conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "nome", "email", "aceite_lgpd_em", "cadastrado_em"])
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=oab-facil-cadastros.csv"},
    )


@app.get("/api/admin/resumo")
@admin_required
def registrations_summary():
    conn = connection()
    try:
        if DATABASE_URL:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM registrations")
                total = cur.fetchone()[0]
        else:
            total = conn.execute("SELECT COUNT(*) FROM registrations").fetchone()[0]
    finally:
        conn.close()
    return jsonify({"total": total})


if __name__ == "__main__":
    ensure_schema()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
