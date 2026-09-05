import csv
import io
import os
import re
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, send_from_directory, Response, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SQLITE_PATH = os.getenv("SQLITE_PATH", "/tmp/oab_facil.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "") or secrets.token_hex(32)

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
app.secret_key = SESSION_SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=True)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def is_postgres():
    return bool(DATABASE_URL)


def connection():
    if is_postgres():
        import psycopg
        return psycopg.connect(DATABASE_URL)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def execute(conn, sql, params=()):
    if is_postgres():
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur
    return conn.execute(sql.replace("%s", "?"), params)


def fetch_one(conn, sql, params=()):
    cur = execute(conn, sql, params)
    row = cur.fetchone()
    if row is None:
        return None
    return tuple(row) if not isinstance(row, tuple) else row


def fetch_all(conn, sql, params=()):
    cur = execute(conn, sql, params)
    rows = cur.fetchall()
    return [tuple(row) if not isinstance(row, tuple) else row for row in rows]


def ensure_schema():
    conn = connection()
    try:
        if is_postgres():
            statements = [
                """CREATE TABLE IF NOT EXISTS registrations (
                    id BIGSERIAL PRIMARY KEY, name VARCHAR(120) NOT NULL,
                    email VARCHAR(254) NOT NULL UNIQUE, consent_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY, name VARCHAR(120) NOT NULL,
                    email VARCHAR(254) NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                    consent_at TIMESTAMPTZ NOT NULL, plan_days INTEGER NOT NULL DEFAULT 30,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS study_tasks (
                    id BIGSERIAL PRIMARY KEY, plan_days INTEGER NOT NULL,
                    day_number INTEGER NOT NULL, title VARCHAR(180) NOT NULL,
                    description TEXT NOT NULL, UNIQUE(plan_days, day_number))""",
                """CREATE TABLE IF NOT EXISTS progress (
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    task_id BIGINT NOT NULL REFERENCES study_tasks(id) ON DELETE CASCADE,
                    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY(user_id, task_id))""",
            ]
        else:
            statements = [
                """CREATE TABLE IF NOT EXISTS registrations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE, consent_at TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
                """CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                    consent_at TEXT NOT NULL, plan_days INTEGER NOT NULL DEFAULT 30,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
                """CREATE TABLE IF NOT EXISTS study_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, plan_days INTEGER NOT NULL,
                    day_number INTEGER NOT NULL, title TEXT NOT NULL,
                    description TEXT NOT NULL, UNIQUE(plan_days, day_number))""",
                """CREATE TABLE IF NOT EXISTS progress (
                    user_id INTEGER NOT NULL, task_id INTEGER NOT NULL,
                    completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(user_id, task_id))""",
            ]
        for statement in statements:
            execute(conn, statement)

        for days in (30, 60, 90):
            existing = fetch_one(conn, "SELECT COUNT(*) FROM study_tasks WHERE plan_days = %s", (days,))[0]
            if existing == 0:
                rows = []
                for day in range(1, days + 1):
                    if day == 1:
                        title, description = "Diagnóstico e organização", "Defina sua fase, separe os materiais e faça um diagnóstico inicial."
                    elif day == 2:
                        title, description = "Ética e Estatuto da OAB", "Estude os princípios essenciais e anote os pontos que geram mais dúvidas."
                    elif day == 3:
                        title, description = "Revisão ativa", "Revise o conteúdo anterior e resolva questões relacionadas."
                    elif day == 7:
                        title, description = "Simulado da semana", "Faça um bloco de questões e registre seu desempenho."
                    else:
                        title, description = f"Estudo orientado — etapa {day}", "Leia o material indicado, faça anotações e resolva questões do tema."
                    rows.append((days, day, title, description))
                if is_postgres():
                    with conn.cursor() as cur:
                        cur.executemany("INSERT INTO study_tasks (plan_days, day_number, title, description) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING", rows)
                else:
                    conn.executemany("INSERT OR IGNORE INTO study_tasks (plan_days, day_number, title, description) VALUES (?, ?, ?, ?)", rows)
        conn.commit()
    finally:
        conn.close()


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not ADMIN_TOKEN:
            return jsonify({"error": "Painel administrativo ainda não configurado."}), 503
        if request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN:
            return jsonify({"error": "Acesso não autorizado."}), 401
        return view(*args, **kwargs)
    return wrapped


def logged_user_id():
    return session.get("user_id")


def user_row(user_id):
    conn = connection()
    try:
        return fetch_one(conn, "SELECT id, name, email, plan_days FROM users WHERE id = %s", (user_id,))
    finally:
        conn.close()


@app.before_request
def prepare_database():
    if request.endpoint not in {"static_file", "health"}:
        ensure_schema()


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/aluno")
def student_area():
    return send_from_directory(BASE_DIR, "student.html")


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
    password = str(payload.get("password", ""))
    consent = payload.get("consent")
    consent_ok = consent is True or str(consent).lower() in {"true", "1", "on", "yes"}

    if not name or len(name) > 120:
        return jsonify({"ok": False, "message": "Informe seu nome."}), 400
    if not EMAIL_RE.match(email) or len(email) > 254:
        return jsonify({"ok": False, "message": "Informe um e-mail válido."}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "message": "A senha precisa ter pelo menos 8 caracteres."}), 400
    if not consent_ok:
        return jsonify({"ok": False, "message": "É necessário aceitar a Política de Privacidade."}), 400

    now = datetime.now(timezone.utc)
    conn = connection()
    try:
        existing = fetch_one(conn, "SELECT id FROM users WHERE email = %s", (email,))
        if existing:
            return jsonify({"ok": False, "message": "Já existe uma conta com este e-mail. Use a tela de entrada."}), 409
        password_hash = generate_password_hash(password)
        if is_postgres():
            with conn.cursor() as cur:
                cur.execute("INSERT INTO registrations (name, email, consent_at) VALUES (%s, %s, %s) ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, consent_at = EXCLUDED.consent_at", (name, email, now))
                cur.execute("INSERT INTO users (name, email, password_hash, consent_at) VALUES (%s, %s, %s, %s) RETURNING id", (name, email, password_hash, now))
                user_id = cur.fetchone()[0]
        else:
            conn.execute("INSERT OR REPLACE INTO registrations (name, email, consent_at) VALUES (?, ?, ?)", (name, email, now.isoformat()))
            cur = conn.execute("INSERT INTO users (name, email, password_hash, consent_at) VALUES (?, ?, ?, ?)", (name, email, password_hash, now.isoformat()))
            user_id = cur.lastrowid
        conn.commit()
        session["user_id"] = user_id
    finally:
        conn.close()
    return jsonify({"ok": True, "message": f"Acesso criado. Bem-vindo(a), {name.split()[0]}!"}), 201


@app.post("/api/login")
def login():
    payload = request.get_json(silent=True) or request.form
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    conn = connection()
    try:
        row = fetch_one(conn, "SELECT id, name, email, password_hash, plan_days FROM users WHERE email = %s", (email,))
    finally:
        conn.close()
    if not row or not check_password_hash(row[3], password):
        return jsonify({"ok": False, "message": "E-mail ou senha inválidos."}), 401
    session.clear()
    session["user_id"] = row[0]
    return jsonify({"ok": True, "message": "Login realizado."})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    row = user_row(logged_user_id()) if logged_user_id() else None
    if not row:
        return jsonify({"ok": False, "message": "Faça login para continuar."}), 401
    return jsonify({"ok": True, "user": {"id": row[0], "name": row[1], "email": row[2], "plan_days": row[3]}})


@app.post("/api/plan")
def choose_plan():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    days = int((request.get_json(silent=True) or {}).get("days", 0))
    if days not in {30, 60, 90}:
        return jsonify({"message": "Escolha um plano válido."}), 400
    conn = connection()
    try:
        execute(conn, "UPDATE users SET plan_days = %s WHERE id = %s", (days, user_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "days": days})


@app.get("/api/tasks")
def tasks():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    row = user_row(user_id)
    requested = request.args.get("days", type=int) or row[3]
    days = requested if requested in {30, 60, 90} else row[3]
    conn = connection()
    try:
        rows = fetch_all(conn, """SELECT t.id, t.day_number, t.title, t.description,
            CASE WHEN p.user_id IS NULL THEN 0 ELSE 1 END AS completed
            FROM study_tasks t LEFT JOIN progress p ON p.task_id = t.id AND p.user_id = %s
            WHERE t.plan_days = %s ORDER BY t.day_number""", (user_id, days))
    finally:
        conn.close()
    items = [{"id": r[0], "day_number": r[1], "title": r[2], "description": r[3], "completed": bool(r[4])} for r in rows]
    return jsonify({"ok": True, "days": days, "total": len(items), "completed": sum(1 for item in items if item["completed"]), "tasks": items})


@app.post("/api/tasks/<int:task_id>/complete")
def complete_task(task_id):
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    completed = bool((request.get_json(silent=True) or {}).get("completed"))
    conn = connection()
    try:
        if completed:
            if is_postgres():
                execute(conn, "INSERT INTO progress (user_id, task_id) VALUES (%s, %s) ON CONFLICT DO NOTHING", (user_id, task_id))
            else:
                execute(conn, "INSERT OR IGNORE INTO progress (user_id, task_id) VALUES (%s, %s)", (user_id, task_id))
        else:
            execute(conn, "DELETE FROM progress WHERE user_id = %s AND task_id = %s", (user_id, task_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.get("/api/admin/cadastros.csv")
@admin_required
def registrations_csv():
    conn = connection()
    try:
        rows = fetch_all(conn, "SELECT id, name, email, consent_at, created_at FROM registrations ORDER BY created_at DESC")
    finally:
        conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "nome", "email", "aceite_lgpd_em", "cadastrado_em"])
    writer.writerows(rows)
    return Response(output.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=oab-facil-cadastros.csv"})


@app.get("/api/admin/resumo")
@admin_required
def registrations_summary():
    conn = connection()
    try:
        total = fetch_one(conn, "SELECT COUNT(*) FROM registrations")[0]
        users = fetch_one(conn, "SELECT COUNT(*) FROM users")[0]
    finally:
        conn.close()
    return jsonify({"total": total, "users": users})


if __name__ == "__main__":
    ensure_schema()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
