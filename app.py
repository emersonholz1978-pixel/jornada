import csv
import io
import json
import os
import re
import sqlite3
import secrets
import hashlib
import smtplib
import time
from collections import defaultdict, deque
from email.message import EmailMessage
from datetime import date, datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, request, send_from_directory, Response, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SQLITE_PATH = os.getenv("SQLITE_PATH", "/tmp/oab_facil.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "") or secrets.token_hex(32)
PUBLIC_URL = os.getenv("PUBLIC_URL", "https://oab-facil.onrender.com").rstrip("/")
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER).strip()
RATE_BUCKETS = defaultdict(deque)

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


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def send_reset_email(email, token):
    if not (SMTP_HOST and MAIL_FROM):
        return False
    message = EmailMessage()
    message["Subject"] = "Recuperação de senha — OAB FÁCIL"
    message["From"] = MAIL_FROM
    message["To"] = email
    message.set_content(f"Solicitação de recuperação de senha do OAB FÁCIL. Acesse {PUBLIC_URL}/login.html?token={token} para criar uma nova senha. Este link expira em 30 minutos. Se você não solicitou, ignore esta mensagem.")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.starttls()
        if SMTP_USER and SMTP_PASSWORD:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(message)
    return True


def limited(bucket, limit, window_seconds):
    now = time.monotonic()
    events = RATE_BUCKETS[bucket]
    while events and now - events[0] >= window_seconds:
        events.popleft()
    if len(events) >= limit:
        return True
    events.append(now)
    return False


def client_key(prefix):
    return f"{prefix}:{request.remote_addr or 'unknown'}"


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
                """CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(128) NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL,
                    used_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS phase2_mock_attempts (
                    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    subject_id BIGINT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                    piece_id BIGINT NOT NULL,
                    answers_json TEXT NOT NULL, score INTEGER NOT NULL, max_score INTEGER NOT NULL,
                    duration_seconds INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS phase2_review_items (
                    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    subject_id BIGINT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                    title VARCHAR(180) NOT NULL, detail TEXT NOT NULL,
                    completed BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS study_tasks (
                    id BIGSERIAL PRIMARY KEY, plan_days INTEGER NOT NULL,
                    day_number INTEGER NOT NULL, title VARCHAR(180) NOT NULL,
                    description TEXT NOT NULL, UNIQUE(plan_days, day_number))""",
                """CREATE TABLE IF NOT EXISTS progress (
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    task_id BIGINT NOT NULL REFERENCES study_tasks(id) ON DELETE CASCADE,
                    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY(user_id, task_id))""",
                """CREATE TABLE IF NOT EXISTS subjects (
                    id BIGSERIAL PRIMARY KEY, name VARCHAR(120) NOT NULL UNIQUE,
                    phase VARCHAR(20) NOT NULL, question_weight INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 0)""",
                """CREATE TABLE IF NOT EXISTS lessons (
                    id BIGSERIAL PRIMARY KEY, subject_id BIGINT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                    title VARCHAR(180) NOT NULL, summary TEXT NOT NULL,
                    source_note TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(subject_id, title))""",
                """CREATE TABLE IF NOT EXISTS questions (
                    id BIGSERIAL PRIMARY KEY, subject_id BIGINT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                    prompt TEXT NOT NULL, options_json TEXT NOT NULL, answer_index INTEGER NOT NULL,
                    explanation TEXT NOT NULL, source_note TEXT NOT NULL)""",
                """CREATE TABLE IF NOT EXISTS quiz_attempts (
                    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    subject_id BIGINT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                    score INTEGER NOT NULL, total INTEGER NOT NULL, answers_json TEXT NOT NULL,
                    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS calendar_events (
                    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    title VARCHAR(180) NOT NULL, event_date DATE NOT NULL, category VARCHAR(40) NOT NULL,
                    completed BOOLEAN NOT NULL DEFAULT FALSE)""",
                """CREATE TABLE IF NOT EXISTS review_items (
                    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    question_id BIGINT NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
                    title VARCHAR(180) NOT NULL, detail TEXT NOT NULL,
                    completed BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE(user_id, question_id))""",
                """CREATE TABLE IF NOT EXISTS practical_pieces (
                    id BIGSERIAL PRIMARY KEY, subject_id BIGINT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                    title VARCHAR(180) NOT NULL, scenario TEXT NOT NULL, structure TEXT NOT NULL,
                    checklist TEXT NOT NULL, source_note TEXT NOT NULL, UNIQUE(subject_id, title))""",
                """CREATE TABLE IF NOT EXISTS discursive_questions (
                    id BIGSERIAL PRIMARY KEY, subject_id BIGINT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                    prompt TEXT NOT NULL, model_answer TEXT NOT NULL, source_note TEXT NOT NULL,
                    UNIQUE(subject_id, prompt))""",
                """CREATE TABLE IF NOT EXISTS discursive_attempts (
                    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    subject_id BIGINT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                    question_id BIGINT NOT NULL REFERENCES discursive_questions(id) ON DELETE CASCADE,
                    answer TEXT NOT NULL, score INTEGER NOT NULL, feedback TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
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
                """CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
                    used_at TEXT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
                """CREATE TABLE IF NOT EXISTS phase2_mock_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    subject_id INTEGER NOT NULL, piece_id INTEGER NOT NULL,
                    answers_json TEXT NOT NULL, score INTEGER NOT NULL, max_score INTEGER NOT NULL,
                    duration_seconds INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
                """CREATE TABLE IF NOT EXISTS phase2_review_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    subject_id INTEGER NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
                """CREATE TABLE IF NOT EXISTS study_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, plan_days INTEGER NOT NULL,
                    day_number INTEGER NOT NULL, title TEXT NOT NULL,
                    description TEXT NOT NULL, UNIQUE(plan_days, day_number))""",
                """CREATE TABLE IF NOT EXISTS progress (
                    user_id INTEGER NOT NULL, task_id INTEGER NOT NULL,
                    completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(user_id, task_id))""",
                """CREATE TABLE IF NOT EXISTS subjects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
                    phase TEXT NOT NULL, question_weight INTEGER NOT NULL DEFAULT 0,
                    sort_order INTEGER NOT NULL DEFAULT 0)""",
                """CREATE TABLE IF NOT EXISTS lessons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id INTEGER NOT NULL,
                    title TEXT NOT NULL, summary TEXT NOT NULL,
                    source_note TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(subject_id, title))""",
                """CREATE TABLE IF NOT EXISTS questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id INTEGER NOT NULL,
                    prompt TEXT NOT NULL, options_json TEXT NOT NULL, answer_index INTEGER NOT NULL,
                    explanation TEXT NOT NULL, source_note TEXT NOT NULL)""",
                """CREATE TABLE IF NOT EXISTS quiz_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    subject_id INTEGER NOT NULL, score INTEGER NOT NULL, total INTEGER NOT NULL,
                    answers_json TEXT NOT NULL, completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
                """CREATE TABLE IF NOT EXISTS calendar_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    title TEXT NOT NULL, event_date TEXT NOT NULL, category TEXT NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0)""",
                """CREATE TABLE IF NOT EXISTS review_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    question_id INTEGER NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, question_id))""",
                """CREATE TABLE IF NOT EXISTS practical_pieces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id INTEGER NOT NULL,
                    title TEXT NOT NULL, scenario TEXT NOT NULL, structure TEXT NOT NULL,
                    checklist TEXT NOT NULL, source_note TEXT NOT NULL, UNIQUE(subject_id, title))""",
                """CREATE TABLE IF NOT EXISTS discursive_questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id INTEGER NOT NULL,
                    prompt TEXT NOT NULL, model_answer TEXT NOT NULL, source_note TEXT NOT NULL,
                    UNIQUE(subject_id, prompt))""",
                """CREATE TABLE IF NOT EXISTS discursive_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    subject_id INTEGER NOT NULL, question_id INTEGER NOT NULL,
                    answer TEXT NOT NULL, score INTEGER NOT NULL, feedback TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
            ]
        for statement in statements:
            execute(conn, statement)

        subject_rows = [
            ("Ética e Estatuto da OAB", "1ª fase", 8, 1),
            ("Direito Civil", "1ª fase", 6, 2),
            ("Processo Civil", "1ª fase", 6, 3),
            ("Direito Constitucional", "1ª fase", 6, 4),
            ("Direito Penal", "1ª fase", 6, 5),
            ("Processo Penal", "1ª fase", 6, 6),
            ("Direito Administrativo", "1ª fase", 5, 7),
            ("Direito do Trabalho", "1ª fase", 5, 8),
            ("Processo do Trabalho", "1ª fase", 5, 9),
            ("Direito Tributário", "1ª fase", 5, 10),
            ("Direito Empresarial", "1ª fase", 4, 11),
            ("Direitos Humanos", "1ª fase", 2, 12),
            ("Direito do Consumidor", "1ª fase", 2, 13),
            ("ECA", "1ª fase", 2, 14),
            ("Direito Ambiental", "1ª fase", 2, 15),
            ("Direito Internacional", "1ª fase", 2, 16),
            ("Filosofia do Direito", "1ª fase", 2, 17),
            ("Direito Eleitoral", "1ª fase", 2, 18),
            ("Direito Financeiro", "1ª fase", 2, 19),
            ("Direito Previdenciário", "1ª fase", 2, 20),
            ("2ª fase — Direito Administrativo", "2ª fase", 0, 101),
            ("2ª fase — Direito Civil", "2ª fase", 0, 102),
            ("2ª fase — Direito Constitucional", "2ª fase", 0, 103),
            ("2ª fase — Direito do Trabalho", "2ª fase", 0, 104),
            ("2ª fase — Direito Empresarial", "2ª fase", 0, 105),
            ("2ª fase — Direito Penal", "2ª fase", 0, 106),
            ("2ª fase — Direito Tributário", "2ª fase", 0, 107),
        ]
        if is_postgres():
            with conn.cursor() as cur:
                cur.executemany("INSERT INTO subjects (name, phase, question_weight, sort_order) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING", subject_rows)
        else:
            conn.executemany("INSERT OR IGNORE INTO subjects (name, phase, question_weight, sort_order) VALUES (?, ?, ?, ?)", subject_rows)
        ethics = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Ética e Estatuto da OAB",))[0]
        lesson_rows = [
            (ethics, "Inscrição e atividade da advocacia", "Organize os requisitos, impedimentos e incompatibilidades para iniciar a revisão do Estatuto.", "Material autoral de revisão; confira sempre o texto oficial vigente.", 1),
            (ethics, "Prerrogativas profissionais", "Estude as garantias essenciais ao exercício da advocacia e diferencie prerrogativa de privilégio.", "Material autoral de revisão; confira sempre o texto oficial vigente.", 2),
            (ethics, "Honorários advocatícios", "Revise espécies, critérios de fixação, sucumbência e cuidados éticos na cobrança.", "Material autoral de revisão; confira sempre o texto oficial vigente.", 3),
            (ethics, "Sociedade de advogados", "Mapeie as formas de organização, registro e responsabilidade profissional.", "Material autoral de revisão; confira sempre o texto oficial vigente.", 4),
            (ethics, "Publicidade na advocacia", "Identifique os limites éticos da publicidade e da divulgação profissional.", "Material autoral de revisão; confira sempre o texto oficial vigente.", 5),
            (ethics, "Infrações e sanções disciplinares", "Construa uma tabela com condutas, sanções e noções de processo disciplinar.", "Material autoral de revisão; confira sempre o texto oficial vigente.", 6),
            (ethics, "Código de Ética e deveres profissionais", "Revise sigilo, independência, urbanidade, lealdade e relação com o cliente.", "Material autoral de revisão; confira sempre o texto oficial vigente.", 7),
            (ethics, "Revisão por questões", "Faça um bloco de questões autorais e registre os pontos que precisam voltar para a revisão.", "Questões autorais do OAB FÁCIL; não reproduz questões protegidas de terceiros.", 8),
        ]
        civil = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Civil",))[0]
        constitutional = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Constitucional",))[0]
        process_civil = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Processo Civil",))[0]
        penal = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Penal",))[0]
        administrative = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Administrativo",))[0]
        labour = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito do Trabalho",))[0]
        tax = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Tributário",))[0]
        business = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Empresarial",))[0]
        process_penal = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Processo Penal",))[0]
        labour_process = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Processo do Trabalho",))[0]
        human_rights = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direitos Humanos",))[0]
        consumer = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito do Consumidor",))[0]
        eca = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("ECA",))[0]
        environmental = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Ambiental",))[0]
        international = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Internacional",))[0]
        philosophy = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Filosofia do Direito",))[0]
        electoral = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Eleitoral",))[0]
        financial = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Financeiro",))[0]
        social_security = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("Direito Previdenciário",))[0]
        phase2_admin = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("2ª fase — Direito Administrativo",))[0]
        phase2_civil = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("2ª fase — Direito Civil",))[0]
        phase2_constitutional = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("2ª fase — Direito Constitucional",))[0]
        phase2_labour = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("2ª fase — Direito do Trabalho",))[0]
        phase2_business = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("2ª fase — Direito Empresarial",))[0]
        phase2_penal = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("2ª fase — Direito Penal",))[0]
        phase2_tax = fetch_one(conn, "SELECT id FROM subjects WHERE name = %s", ("2ª fase — Direito Tributário",))[0]
        lesson_rows += [
            (civil, "Pessoas e personalidade", "Revise capacidade, direitos da personalidade e proteção jurídica da pessoa.", "Material autoral OAB FÁCIL; confira o Código Civil vigente.", 1),
            (civil, "Obrigações e responsabilidade civil", "Organize obrigação, dano, nexo causal e as hipóteses gerais de responsabilização.", "Material autoral OAB FÁCIL; confira o Código Civil vigente.", 2),
            (civil, "Contratos e boa-fé", "Estude formação, interpretação e função da boa-fé objetiva nos contratos.", "Material autoral OAB FÁCIL; confira o Código Civil vigente.", 3),
            (civil, "Revisão por questões de Civil", "Faça questões e registre os conceitos que precisam de nova revisão.", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.", 4),
            (constitutional, "Princípios fundamentais", "Revise fundamentos da República, objetivos fundamentais e princípios estruturantes.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 1),
            (constitutional, "Direitos e garantias fundamentais", "Organize direitos individuais, coletivos e instrumentos de proteção constitucional.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 2),
            (constitutional, "Organização dos Poderes", "Estude a separação funcional, controles e competências previstas na Constituição.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 3),
            (constitutional, "Controle de constitucionalidade", "Monte um quadro com noções de controle difuso, concentrado e efeitos das decisões.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 4),
            (process_civil, "Jurisdição e competência", "Revise jurisdição, competência e os critérios básicos para identificar o juízo adequado.", "Material autoral OAB FÁCIL; confira o CPC vigente.", 1),
            (process_civil, "Atos processuais e prazos", "Organize atos, comunicações e contagem de prazos processuais.", "Material autoral OAB FÁCIL; confira o CPC vigente.", 2),
            (process_civil, "Petição inicial e resposta", "Estude requisitos gerais da petição inicial, defesa e consequências processuais.", "Material autoral OAB FÁCIL; confira o CPC vigente.", 3),
            (process_civil, "Recursos e revisão", "Monte um quadro com finalidade, cabimento e efeitos dos principais recursos.", "Material autoral OAB FÁCIL; confira o CPC vigente.", 4),
            (penal, "Princípios do Direito Penal", "Revise legalidade, anterioridade, culpabilidade e limites da intervenção penal.", "Material autoral OAB FÁCIL; confira o Código Penal vigente.", 1),
            (penal, "Tipicidade e elementos do crime", "Organize fato típico, ilicitude e culpabilidade como etapas de análise.", "Material autoral OAB FÁCIL; confira o Código Penal vigente.", 2),
            (penal, "Concurso de pessoas", "Revise os conceitos gerais de autoria, participação e vínculo subjetivo.", "Material autoral OAB FÁCIL; confira o Código Penal vigente.", 3),
            (penal, "Penas e aplicação", "Estude as noções gerais de espécies de pena e critérios de aplicação.", "Material autoral OAB FÁCIL; confira o Código Penal vigente.", 4),
            (administrative, "Princípios da Administração Pública", "Revise os princípios que orientam a atuação administrativa e o interesse público.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 1),
            (administrative, "Atos administrativos", "Organize elementos, atributos e formas de controle dos atos administrativos.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (administrative, "Licitações e contratos", "Estude noções de contratação pública, planejamento e controle.", "Material autoral OAB FÁCIL; confira a Lei de Licitações vigente.", 3),
            (administrative, "Responsabilidade do Estado", "Revise a responsabilidade estatal e as hipóteses de ação regressiva.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 4),
            (labour, "Relação de emprego", "Diferencie relação de trabalho, relação de emprego e seus elementos essenciais.", "Material autoral OAB FÁCIL; confira a CLT vigente.", 1),
            (labour, "Jornada e remuneração", "Organize regras gerais de jornada, descanso e remuneração.", "Material autoral OAB FÁCIL; confira a CLT vigente.", 2),
            (labour, "Férias e encerramento do contrato", "Revise férias, verbas rescisórias e modalidades de término contratual.", "Material autoral OAB FÁCIL; confira a CLT vigente.", 3),
            (labour, "Proteção do trabalho", "Estude normas de proteção, igualdade e segurança no ambiente laboral.", "Material autoral OAB FÁCIL; confira a CLT e a Constituição vigentes.", 4),
            (tax, "Sistema tributário", "Revise espécies tributárias e a estrutura constitucional do sistema tributário.", "Material autoral OAB FÁCIL; confira a Constituição e o CTN vigentes.", 1),
            (tax, "Obrigação e crédito tributário", "Organize conceitos de obrigação, lançamento, crédito e exigibilidade.", "Material autoral OAB FÁCIL; confira o CTN vigente.", 2),
            (tax, "Limitações ao poder de tributar", "Estude legalidade, anterioridade, isonomia e imunidades em visão sistemática.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 3),
            (tax, "Revisão de Tributário", "Resolva questões e relacione conceitos constitucionais e do CTN.", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.", 4),
            (business, "Empresário e empresa", "Diferencie empresário, atividade empresarial e situações excluídas do conceito.", "Material autoral OAB FÁCIL; confira o Código Civil vigente.", 1),
            (business, "Sociedades empresárias", "Revise personalidade, responsabilidade e organização das sociedades.", "Material autoral OAB FÁCIL; confira o Código Civil vigente.", 2),
            (business, "Recuperação e falência", "Organize objetivos e conceitos básicos dos regimes de crise empresarial.", "Material autoral OAB FÁCIL; confira a Lei vigente.", 3),
            (business, "Títulos de crédito", "Estude princípios e circulação dos títulos de crédito em visão introdutória.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 4),
            (process_penal, "Inquérito e investigação", "Revise a finalidade da investigação e os limites da atuação estatal.", "Material autoral OAB FÁCIL; confira o CPP vigente.", 1),
            (process_penal, "Ação penal", "Organize condições, legitimidade e espécies de ação penal.", "Material autoral OAB FÁCIL; confira o CPP vigente.", 2),
            (process_penal, "Provas e cautelares", "Estude noções de prova, cadeia de custódia e medidas cautelares.", "Material autoral OAB FÁCIL; confira o CPP vigente.", 3),
            (process_penal, "Recursos criminais", "Monte um quadro com cabimento e efeitos dos principais recursos criminais.", "Material autoral OAB FÁCIL; confira o CPP vigente.", 4),
            (labour_process, "Organização da Justiça do Trabalho", "Revise competência e estrutura básica da Justiça do Trabalho.", "Material autoral OAB FÁCIL; confira a Constituição e a CLT vigentes.", 1),
            (labour_process, "Reclamação trabalhista", "Estude elementos gerais, pedidos e resposta na reclamação trabalhista.", "Material autoral OAB FÁCIL; confira a CLT vigente.", 2),
            (labour_process, "Provas e audiência", "Organize regras gerais de prova, audiência e participação das partes.", "Material autoral OAB FÁCIL; confira a CLT vigente.", 3),
            (labour_process, "Recursos trabalhistas", "Revise noções de recursos e prazos no processo do trabalho.", "Material autoral OAB FÁCIL; confira a CLT vigente.", 4),
            (human_rights, "Fundamentos dos Direitos Humanos", "Revise dignidade, universalidade e indivisibilidade dos direitos humanos.", "Material autoral OAB FÁCIL; confira tratados e fontes oficiais vigentes.", 1),
            (human_rights, "Sistemas de proteção", "Organize os sistemas global e interamericano de proteção.", "Material autoral OAB FÁCIL; confira as fontes oficiais vigentes.", 2),
            (human_rights, "Tratados e incorporação", "Estude noções de tratados internacionais de direitos humanos no Brasil.", "Material autoral OAB FÁCIL; confira a Constituição e os tratados vigentes.", 3),
            (human_rights, "Revisão de Direitos Humanos", "Resolva questões e relacione princípios, tratados e mecanismos de proteção.", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.", 4),
            (consumer, "Relação de consumo", "Identifique consumidor, fornecedor, produto e serviço na relação de consumo.", "Material autoral OAB FÁCIL; confira o CDC vigente.", 1),
            (consumer, "Responsabilidade pelo produto e serviço", "Revise noções de responsabilidade e proteção do consumidor.", "Material autoral OAB FÁCIL; confira o CDC vigente.", 2),
            (consumer, "Práticas abusivas e contratos", "Organize proteção contratual e limites das práticas comerciais.", "Material autoral OAB FÁCIL; confira o CDC vigente.", 3),
            (consumer, "Defesa do consumidor", "Estude instrumentos administrativos e judiciais de proteção.", "Material autoral OAB FÁCIL; confira o CDC vigente.", 4),
            (eca, "Proteção integral", "Revise a doutrina da proteção integral e a prioridade da criança e do adolescente.", "Material autoral OAB FÁCIL; confira o ECA vigente.", 1),
            (eca, "Direitos fundamentais", "Organize direitos à convivência, educação, saúde e dignidade.", "Material autoral OAB FÁCIL; confira o ECA vigente.", 2),
            (eca, "Ato infracional", "Estude noções de ato infracional e medidas socioeducativas.", "Material autoral OAB FÁCIL; confira o ECA vigente.", 3),
            (eca, "Conselho tutelar e revisão", "Revise atribuições institucionais e resolva questões do ECA.", "Material autoral OAB FÁCIL; confira o ECA vigente.", 4),
            (environmental, "Princípios ambientais", "Revise prevenção, precaução, desenvolvimento sustentável e proteção ambiental.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 1),
            (environmental, "Responsabilidade ambiental", "Organize responsabilidade civil, administrativa e penal em matéria ambiental.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (environmental, "Licenciamento ambiental", "Estude a finalidade do licenciamento e o controle de impactos.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 3),
            (environmental, "Revisão ambiental", "Relacione princípios, instrumentos e responsabilidades ambientais.", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.", 4),
            (international, "Fontes do Direito Internacional", "Revise tratados, costumes e princípios como fontes internacionais.", "Material autoral OAB FÁCIL; confira as fontes oficiais vigentes.", 1),
            (international, "Nacionalidade e condição jurídica", "Organize noções gerais de nacionalidade, estrangeiro e proteção jurídica.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 2),
            (international, "Direito Internacional Privado", "Estude conflitos de leis e critérios gerais de conexão.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 3),
            (international, "Cooperação internacional", "Revise noções de cooperação jurídica internacional e reconhecimento de decisões.", "Material autoral OAB FÁCIL; confira o CPC e as fontes vigentes.", 4),
            (philosophy, "Jusnaturalismo e positivismo", "Compare correntes clássicas e seus conceitos centrais de Direito.", "Material autoral OAB FÁCIL; material introdutório de estudo.", 1),
            (philosophy, "Justiça e equidade", "Relacione justiça, igualdade, equidade e aplicação do Direito.", "Material autoral OAB FÁCIL; material introdutório de estudo.", 2),
            (philosophy, "Direito e moral", "Estude aproximações e distinções entre normas jurídicas e morais.", "Material autoral OAB FÁCIL; material introdutório de estudo.", 3),
            (philosophy, "Revisão de Filosofia", "Faça um mapa de autores, correntes e conceitos recorrentes.", "Material autoral OAB FÁCIL; material introdutório de estudo.", 4),
            (electoral, "Direitos políticos", "Revise sufrágio, alistamento e condições gerais de participação política.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 1),
            (electoral, "Partidos e eleições", "Organize noções de partidos, candidaturas e processo eleitoral.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (electoral, "Inelegibilidades", "Estude a finalidade e as hipóteses gerais de inelegibilidade.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 3),
            (electoral, "Revisão eleitoral", "Resolva questões e confira alterações normativas e jurisprudenciais.", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.", 4),
            (financial, "Orçamento público", "Revise princípios e instrumentos básicos do orçamento público.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 1),
            (financial, "Receita e despesa pública", "Organize classificações e fases gerais da receita e da despesa.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (financial, "Responsabilidade fiscal", "Estude planejamento, transparência e limites da gestão fiscal.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 3),
            (financial, "Revisão financeira", "Relacione orçamento, finanças públicas e controle.", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.", 4),
            (social_security, "Seguridade social", "Revise saúde, previdência e assistência como componentes da seguridade.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 1),
            (social_security, "Benefícios previdenciários", "Organize noções gerais de benefícios e requisitos legais.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (social_security, "Custeio e filiação", "Estude filiação, contribuições e custeio do sistema previdenciário.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 3),
            (social_security, "Revisão previdenciária", "Resolva questões e confira a legislação previdenciária atualizada.", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.", 4),
            (phase2_admin, "Escolha da área e estrutura da peça", "Defina a estratégia da prova prático-profissional e organize a estrutura da peça administrativa.", "Material autoral OAB FÁCIL; confira o edital e os padrões oficiais vigentes.", 1),
            (phase2_admin, "Fundamentação e pedidos", "Treine fatos, fundamentos jurídicos, tutela, pedidos e fechamento da peça.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (phase2_admin, "Questão discursiva e revisão", "Pratique respostas fundamentadas, gestão de tempo e revisão final da prova.", "Material autoral OAB FÁCIL; confira o edital vigente.", 3),
            (phase2_civil, "Peças cíveis principais", "Organize identificação e estrutura das peças mais recorrentes da área cível.", "Material autoral OAB FÁCIL; confira o edital e a legislação vigente.", 1),
            (phase2_civil, "Fundamentação no caso concreto", "Treine qualificação jurídica dos fatos, preliminares, mérito e pedidos.", "Material autoral OAB FÁCIL; confira o CPC e a legislação vigente.", 2),
            (phase2_civil, "Questões discursivas cíveis", "Pratique respostas objetivas com indicação de dispositivo e conclusão.", "Material autoral OAB FÁCIL; confira o edital vigente.", 3),
            (phase2_constitutional, "Peças constitucionais", "Revise a identificação de remédios e ações constitucionais conforme o caso.", "Material autoral OAB FÁCIL; confira o edital e a Constituição vigentes.", 1),
            (phase2_constitutional, "Tese constitucional", "Estruture fundamentos, legitimidade, cabimento e pedidos constitucionais.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 2),
            (phase2_constitutional, "Discursivas e controle de constitucionalidade", "Treine respostas fundamentadas e revisão de controle constitucional.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 3),
            (phase2_labour, "Peças trabalhistas", "Estude estrutura de reclamação, defesa e outras peças conforme o enunciado.", "Material autoral OAB FÁCIL; confira o edital e a CLT vigentes.", 1),
            (phase2_labour, "Cálculos e pedidos trabalhistas", "Organize verbas, fundamentos, pedidos e valores com atenção ao caso.", "Material autoral OAB FÁCIL; confira a CLT vigente.", 2),
            (phase2_labour, "Discursivas e gestão de tempo", "Pratique respostas diretas, fundamentação e revisão em cinco horas.", "Material autoral OAB FÁCIL; confira o edital vigente.", 3),
            (phase2_business, "Peças empresariais", "Identifique a medida adequada e estruture a peça conforme o problema empresarial.", "Material autoral OAB FÁCIL; confira o edital e a legislação vigente.", 1),
            (phase2_business, "Sociedades e crise empresarial", "Aplique conceitos societários e de recuperação ao caso concreto.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (phase2_business, "Discursivas empresariais", "Treine respostas com fundamento legal, conclusão e atenção aos requisitos.", "Material autoral OAB FÁCIL; confira o edital vigente.", 3),
            (phase2_penal, "Peças penais", "Revise identificação, endereçamento, fundamentos e pedidos nas peças penais.", "Material autoral OAB FÁCIL; confira o edital e o CPP vigentes.", 1),
            (phase2_penal, "Teses defensivas", "Organize teses preliminares, mérito, nulidades e pedidos defensivos.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (phase2_penal, "Discursivas penais", "Pratique respostas fundamentadas e controle do tempo de prova.", "Material autoral OAB FÁCIL; confira o edital vigente.", 3),
            (phase2_tax, "Peças tributárias", "Identifique a medida adequada e organize fundamentos e pedidos tributários.", "Material autoral OAB FÁCIL; confira o edital, a Constituição e o CTN vigentes.", 1),
            (phase2_tax, "Tese e prova no caso tributário", "Treine lançamento, crédito, limitações e argumentos aplicáveis ao caso.", "Material autoral OAB FÁCIL; confira a legislação vigente.", 2),
            (phase2_tax, "Discursivas tributárias", "Pratique respostas objetivas com dispositivo legal e conclusão.", "Material autoral OAB FÁCIL; confira o edital vigente.", 3),
        ]
        if is_postgres():
            with conn.cursor() as cur:
                cur.executemany("INSERT INTO lessons (subject_id, title, summary, source_note, sort_order) VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING", lesson_rows)
        else:
            conn.executemany("INSERT OR IGNORE INTO lessons (subject_id, title, summary, source_note, sort_order) VALUES (?, ?, ?, ?, ?)", lesson_rows)
        question_rows = [
            (ethics, "Na publicidade profissional da advocacia, a conduta adequada é:", json.dumps(["Prometer resultado para atrair clientes.", "Divulgar informação objetiva e discreta, sem captação indevida.", "Comparar diretamente seus serviços com os de outro advogado.", "Distribuir publicidade em qualquer formato sem limites."]), 1, "A publicidade profissional deve ser informativa, discreta e compatível com a ética, sem promessa de resultado ou captação indevida.", "Questão autoral OAB FÁCIL; confira a regulamentação vigente antes da publicação definitiva."),
            (ethics, "Sobre o sigilo profissional, é correto afirmar que:", json.dumps(["É opcional quando o cliente não assina contrato.", "Só existe durante o processo judicial.", "É dever profissional e pode ter exceções justificadas previstas na regulamentação.", "Pode ser afastado sempre que houver interesse comercial."]), 2, "O sigilo é um dever profissional amplo; suas exceções devem ser justificadas e observadas conforme a legislação e a regulamentação vigente.", "Questão autoral OAB FÁCIL; confira o texto oficial vigente."),
            (ethics, "A incompatibilidade para o exercício da advocacia significa, em regra:", json.dumps(["Proibição total do exercício da advocacia.", "Apenas uma limitação territorial.", "Uma recomendação sem consequência profissional.", "Suspensão automática por trinta dias."]), 0, "A incompatibilidade representa proibição total, enquanto o impedimento é uma limitação parcial ao exercício da advocacia.", "Questão autoral OAB FÁCIL; confira o Estatuto vigente."),
            (ethics, "Conforme a regra geral sobre honorários de sucumbência:", json.dumps(["Pertencem sempre à parte vencedora.", "Não podem ser cobrados em nenhuma hipótese.", "Constituem direito do advogado, conforme a legislação aplicável.", "Pertencem automaticamente ao tribunal."]), 2, "Os honorários de sucumbência constituem direito do advogado, observados os requisitos e a disciplina legal aplicável.", "Questão autoral OAB FÁCIL; confira o Estatuto vigente."),
            (ethics, "Entre as sanções disciplinares previstas no Estatuto da Advocacia está:", json.dumps(["Censura.", "Advertência escolar.", "Interdição civil automática.", "Perda de nacionalidade."]), 0, "Censura, suspensão, exclusão e multa integram o conjunto de sanções disciplinares previsto no Estatuto, conforme o caso.", "Questão autoral OAB FÁCIL; confira o texto oficial vigente."),
            (ethics, "Prerrogativa profissional deve ser entendida como:", json.dumps(["Privilégio pessoal sem relação com a profissão.", "Garantia necessária ao exercício da advocacia, dentro dos limites legais.", "Autorização para descumprir decisões judiciais.", "Imunidade para qualquer conduta."]), 1, "Prerrogativas são garantias funcionais para o exercício independente da advocacia; não são autorização para descumprir a lei.", "Questão autoral OAB FÁCIL; confira o Estatuto vigente."),
            (ethics, "O impedimento profissional, em comparação com a incompatibilidade, é normalmente:", json.dumps(["Uma proibição parcial em situações determinadas.", "Uma proibição total em qualquer atividade.", "Uma sanção criminal.", "Uma forma de inscrição provisória."]), 0, "O impedimento limita o exercício em determinadas situações; a incompatibilidade tem alcance total enquanto durar a causa.", "Questão autoral OAB FÁCIL; confira o Estatuto vigente."),
            (ethics, "Ao revisar o Código de Ética, uma boa prática de estudo é:", json.dumps(["Memorizar frases isoladas sem conferir a fonte.", "Ignorar alterações normativas.", "Relacionar deveres, condutas, consequências e a fonte oficial vigente.", "Usar apenas resumos antigos."]), 2, "A revisão deve conectar deveres, condutas e consequências, sempre conferindo a legislação e a regulamentação atualizadas.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        civil_questions = [
            (civil, "Na responsabilidade civil, a análise geral costuma considerar:", json.dumps(["Apenas a intenção do agente.", "Conduta, dano e nexo causal, sem prejuízo das regras específicas.", "Somente a existência de contrato escrito.", "Apenas o valor econômico do pedido."]), 1, "A análise da responsabilidade civil normalmente parte da conduta, do dano e do nexo causal, observadas as hipóteses legais específicas.", "Questão autoral OAB FÁCIL; confira o Código Civil vigente."),
            (civil, "A boa-fé objetiva nos contratos está relacionada principalmente a:", json.dumps(["Deveres de lealdade, cooperação e correção na relação contratual.", "Dispensa de qualquer obrigação contratual.", "Possibilidade de ocultar informação relevante.", "Proibição de interpretar o contrato."]), 0, "A boa-fé objetiva orienta padrões de lealdade, cooperação e correção, inclusive na formação e execução contratual.", "Questão autoral OAB FÁCIL; confira o Código Civil vigente."),
            (civil, "Os direitos da personalidade protegem, entre outros aspectos:", json.dumps(["Somente bens comerciais.", "A dimensão pessoal, como honra, imagem e privacidade, conforme a lei.", "Apenas direitos políticos.", "Somente relações empresariais."]), 1, "Os direitos da personalidade protegem aspectos essenciais da pessoa, observados os limites e a disciplina legal.", "Questão autoral OAB FÁCIL; confira o Código Civil vigente."),
            (civil, "Uma revisão eficiente de Direito Civil deve:", json.dumps(["Separar conceitos sem relacioná-los a casos.", "Combinar conceitos, dispositivos, exemplos e questões.", "Usar somente material sem data.", "Ignorar exceções legais."]), 1, "A preparação deve relacionar conceitos, texto legal, exemplos e questões, com conferência da fonte vigente.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        constitutional_questions = [
            (constitutional, "O habeas corpus protege diretamente:", json.dumps(["A liberdade de locomoção, nas hipóteses constitucionais.", "Exclusivamente o patrimônio público.", "Somente direitos autorais.", "Apenas relações contratuais."]), 0, "O habeas corpus é remédio constitucional ligado à liberdade de locomoção, conforme os requisitos legais.", "Questão autoral OAB FÁCIL; confira a Constituição vigente."),
            (constitutional, "A separação de Poderes busca:", json.dumps(["Concentrar todas as funções em um único órgão.", "Organizar funções estatais com independência e controles recíprocos.", "Eliminar o Poder Judiciário.", "Impedir qualquer fiscalização institucional."]), 1, "A separação de Poderes organiza funções estatais e convive com mecanismos de independência e controle recíproco.", "Questão autoral OAB FÁCIL; confira a Constituição vigente."),
            (constitutional, "As normas definidoras dos direitos e garantias fundamentais têm, pela Constituição, regra de:", json.dumps(["Aplicação imediata, observadas as condições constitucionais e legais.", "Aplicação somente após lei municipal.", "Aplicação proibida no setor privado.", "Revogação automática após um ano."]), 0, "A Constituição estabelece a regra da aplicação imediata dos direitos e garantias fundamentais, sem afastar a análise do caso concreto.", "Questão autoral OAB FÁCIL; confira a Constituição vigente."),
            (constitutional, "Na revisão constitucional, é importante conferir:", json.dumps(["Somente comentários antigos.", "O texto constitucional vigente, a jurisprudência e as leis relacionadas.", "Apenas notícias sem fonte.", "Somente modelos de petição."]), 1, "O estudo constitucional exige conferência do texto vigente e das fontes interpretativas pertinentes.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        process_civil_questions = [
            (process_civil, "A competência no processo civil serve, em linhas gerais, para:", json.dumps(["Identificar o órgão jurisdicional adequado para a causa.", "Definir o conteúdo do contrato privado.", "Substituir a capacidade da parte.", "Eliminar a necessidade de petição."]), 0, "A competência organiza a atuação dos órgãos jurisdicionais e ajuda a identificar o juízo adequado, conforme as regras legais.", "Questão autoral OAB FÁCIL; confira o CPC vigente."),
            (process_civil, "Na contagem de prazo processual, o estudante deve primeiro:", json.dumps(["Ignorar a data de publicação.", "Conferir a regra aplicável, o marco inicial e eventuais suspensões.", "Contar apenas dias corridos em qualquer caso.", "Usar prazo de outro procedimento."]), 1, "A contagem exige conferir a regra aplicável, o marco inicial e eventos que alterem o prazo.", "Questão autoral OAB FÁCIL; confira o CPC vigente."),
            (process_civil, "A petição inicial deve ser estudada considerando:", json.dumps(["Seus requisitos, pedidos, causa de pedir e documentos pertinentes.", "Somente a assinatura do advogado.", "Apenas o valor da causa.", "Nenhuma regra de forma."]), 0, "A petição inicial reúne requisitos e elementos que delimitam a demanda, além dos documentos pertinentes.", "Questão autoral OAB FÁCIL; confira o CPC vigente."),
            (process_civil, "Uma boa revisão de recursos deve relacionar:", json.dumps(["Cabimento, prazo, requisitos e efeitos.", "Somente o nome do recurso.", "Apenas a parte final da decisão.", "Somente a matéria de fato."]), 0, "O estudo de recursos deve conectar cabimento, prazo, requisitos e efeitos, sempre conforme a legislação vigente.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        penal_questions = [
            (penal, "O princípio da legalidade penal exige, em regra:", json.dumps(["Crime e pena definidos previamente por lei.", "Punição baseada apenas em costume.", "Aplicação de pena sem previsão legal.", "Decisão administrativa sem limites."]), 0, "A legalidade impede que alguém seja punido por fato ou pena sem previsão legal anterior, observadas as regras constitucionais.", "Questão autoral OAB FÁCIL; confira o Código Penal vigente."),
            (penal, "Na análise do crime, uma organização didática comum considera:", json.dumps(["Fato típico, ilicitude e culpabilidade.", "Somente o resultado econômico.", "Apenas a confissão.", "Somente a existência de vítima."]), 0, "A estrutura tripartida é uma forma didática de organizar a análise do fato típico, da ilicitude e da culpabilidade.", "Questão autoral OAB FÁCIL; confira a doutrina e o Código Penal vigente."),
            (penal, "No concurso de pessoas, é importante analisar:", json.dumps(["A contribuição dos envolvidos e o vínculo subjetivo, conforme a lei.", "Somente quem estava no local.", "Apenas o parentesco entre os agentes.", "Somente a existência de dano civil."]), 0, "A análise considera a contribuição dos envolvidos e os requisitos legais do concurso de pessoas.", "Questão autoral OAB FÁCIL; confira o Código Penal vigente."),
            (penal, "Na aplicação da pena, o estudo deve considerar:", json.dumps(["As etapas e critérios previstos na legislação.", "A escolha livre sem fundamentação.", "Somente a opinião da vítima.", "Apenas a situação econômica do réu."]), 0, "A aplicação da pena deve observar critérios legais e fundamentação, conforme o caso concreto.", "Questão autoral OAB FÁCIL; confira o Código Penal vigente."),
        ]
        administrative_questions = [
            (administrative, "A Administração Pública deve observar, entre outros, o princípio da:", json.dumps(["Legalidade.", "Arbitrariedade sem controle.", "Inexistência de motivação.", "Preferência pessoal."]), 0, "A legalidade é princípio estruturante da atuação administrativa, junto aos demais princípios constitucionais.", "Questão autoral OAB FÁCIL; confira a Constituição vigente."),
            (administrative, "O ato administrativo deve ser estudado considerando:", json.dumps(["Competência, finalidade, forma, motivo e objeto.", "Somente a vontade pessoal do agente.", "Apenas o resultado financeiro.", "Nenhum requisito jurídico."]), 0, "Os elementos do ato ajudam a analisar sua validade e controle, conforme a legislação e o caso concreto.", "Questão autoral OAB FÁCIL; confira a legislação vigente."),
            (administrative, "A contratação pública deve buscar, em regra:", json.dumps(["Planejamento, isonomia, seleção adequada e controle.", "Escolha sem critérios.", "Ausência de publicidade.", "Dispensa de justificativa em qualquer hipótese."]), 0, "A contratação pública é orientada por planejamento, isonomia, transparência e controle, conforme a lei.", "Questão autoral OAB FÁCIL; confira a Lei de Licitações vigente."),
            (administrative, "Uma revisão eficiente de Administrativo deve:", json.dumps(["Relacionar princípios, atos, contratos e controle.", "Memorizar apenas siglas.", "Ignorar a Constituição.", "Usar legislação sem data."]), 0, "O estudo deve conectar princípios, institutos e legislação atualizada.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        labour_questions = [
            (labour, "Na análise da relação de emprego, costuma-se verificar:", json.dumps(["Pessoalidade, onerosidade, não eventualidade e subordinação.", "Somente a existência de uniforme.", "Apenas a duração do contrato.", "Somente a vontade do empregador."]), 0, "Esses elementos orientam a identificação da relação de emprego, conforme a legislação e a jurisprudência aplicáveis.", "Questão autoral OAB FÁCIL; confira a CLT vigente."),
            (labour, "O estudo da jornada de trabalho deve considerar:", json.dumps(["Regras de duração, controle, descanso e exceções legais.", "Somente o horário de entrada.", "Apenas acordo verbal.", "Nenhuma regra de intervalo."]), 0, "Jornada envolve duração, controle, descansos e exceções previstas na legislação.", "Questão autoral OAB FÁCIL; confira a CLT vigente."),
            (labour, "As férias têm como finalidade principal:", json.dumps(["Garantir período de descanso e recuperação, conforme a lei.", "Substituir todo salário.", "Eliminar o vínculo de emprego.", "Dispensar o registro contratual."]), 0, "As férias são período de descanso protegido pela legislação trabalhista, com regras próprias.", "Questão autoral OAB FÁCIL; confira a CLT vigente."),
            (labour, "Na revisão trabalhista, é essencial conferir:", json.dumps(["A Constituição, a CLT e alterações legislativas vigentes.", "Somente material antigo.", "Apenas contratos civis.", "Nenhuma fonte oficial."]), 0, "Direito do Trabalho exige conferência constante da Constituição, CLT e alterações normativas.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        tax_questions = [
            (tax, "Entre as espécies tributárias reconhecidas no sistema brasileiro está:", json.dumps(["Imposto.", "Contrato administrativo.", "Sentença.", "Alvará."]), 0, "Imposto é espécie tributária; a classificação completa deve ser estudada na Constituição e no CTN.", "Questão autoral OAB FÁCIL; confira a Constituição e o CTN vigentes."),
            (tax, "O lançamento tributário relaciona-se à:", json.dumps(["Constituição do crédito tributário, conforme a lei.", "Criação de contrato privado.", "Extinção automática de todo tributo.", "Aplicação de pena criminal."]), 0, "O lançamento integra a constituição do crédito tributário, nos termos do CTN.", "Questão autoral OAB FÁCIL; confira o CTN vigente."),
            (tax, "A anterioridade tributária é estudada como:", json.dumps(["Limitação constitucional ao poder de tributar.", "Autorização para cobrar sem lei.", "Dispensa de publicação.", "Regra exclusiva dos contratos."]), 0, "A anterioridade é uma das limitações constitucionais ao poder de tributar, com regras e exceções próprias.", "Questão autoral OAB FÁCIL; confira a Constituição vigente."),
            (tax, "Uma revisão adequada de Tributário deve:", json.dumps(["Relacionar Constituição, CTN, obrigação, crédito e limitações.", "Estudar apenas alíquotas isoladas.", "Ignorar vigência normativa.", "Usar somente exemplos sem fonte."]), 0, "A preparação deve conectar a estrutura constitucional e os conceitos do CTN.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        business_questions = [
            (business, "O empresário, em sentido jurídico, está ligado ao exercício profissional de:", json.dumps(["Atividade econômica organizada para produção ou circulação de bens ou serviços.", "Qualquer ato isolado sem organização.", "Somente atividade sem finalidade econômica.", "Apenas profissão intelectual em qualquer hipótese."]), 0, "O conceito jurídico de empresário envolve atividade econômica organizada, observadas as exceções legais.", "Questão autoral OAB FÁCIL; confira o Código Civil vigente."),
            (business, "Nas sociedades empresárias, é importante estudar:", json.dumps(["Personalidade, responsabilidade, administração e organização.", "Somente o nome fantasia.", "Apenas a publicidade.", "Nenhuma regra de registro."]), 0, "A análise societária envolve personalidade, responsabilidade, administração e registro, conforme o tipo societário.", "Questão autoral OAB FÁCIL; confira o Código Civil vigente."),
            (business, "A recuperação judicial busca, em linhas gerais:", json.dumps(["Preservar a empresa viável e organizar a superação da crise, conforme a lei.", "Punir automaticamente todos os credores.", "Dispensar qualquer controle judicial.", "Extinguir toda atividade empresarial."]), 0, "A recuperação tem finalidade de preservação da empresa viável, observados os requisitos e o procedimento legal.", "Questão autoral OAB FÁCIL; confira a Lei vigente."),
            (business, "Os títulos de crédito devem ser estudados considerando:", json.dumps(["Princípios, requisitos e circulação conforme a legislação.", "Somente o valor escrito.", "Ausência de formalidades.", "Apenas relações trabalhistas."]), 0, "Títulos de crédito possuem requisitos e princípios próprios, que variam conforme a legislação aplicável.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        process_penal_questions = [
            (process_penal, "A investigação criminal deve respeitar:", json.dumps(["Direitos fundamentais e limites legais.", "Ausência total de controle.", "Somente a vontade da autoridade.", "Nenhuma formalidade."]), 0, "A investigação deve observar direitos fundamentais, controle e limites previstos na Constituição e no CPP.", "Questão autoral OAB FÁCIL; confira o CPP vigente."),
            (process_penal, "A ação penal pública é, em regra, promovida por:", json.dumps(["Ministério Público, conforme a lei.", "Qualquer testemunha sem requisitos.", "Somente o juiz de ofício.", "A autoridade policial como parte."]), 0, "A titularidade da ação penal pública é atribuída ao Ministério Público, observadas as regras legais.", "Questão autoral OAB FÁCIL; confira a Constituição e o CPP vigentes."),
            (process_penal, "Na análise da prova penal, é importante conferir:", json.dumps(["Legalidade, pertinência e preservação da cadeia de custódia quando aplicável.", "Somente a aparência do documento.", "Apenas a opinião da acusação.", "Nenhuma regra de obtenção."]), 0, "A prova deve ser analisada segundo legalidade, pertinência e regras de preservação e produção.", "Questão autoral OAB FÁCIL; confira o CPP vigente."),
            (process_penal, "Os recursos criminais devem ser estudados por:", json.dumps(["Cabimento, prazo, requisitos e efeitos.", "Somente pelo nome.", "Apenas pela pena aplicada.", "Sem consultar a decisão."]), 0, "O método de estudo de recursos conecta cabimento, prazo, requisitos e efeitos.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        labour_process_questions = [
            (labour_process, "A Justiça do Trabalho integra o Poder Judiciário e possui competência definida:", json.dumps(["Pela Constituição e pela legislação.", "Somente por contrato entre as partes.", "Por escolha livre do empregador.", "Sem limites materiais."]), 0, "A competência trabalhista decorre da Constituição e da legislação aplicável.", "Questão autoral OAB FÁCIL; confira a Constituição e a CLT vigentes."),
            (labour_process, "A reclamação trabalhista deve delimitar, entre outros pontos:", json.dumps(["Partes, fatos, pedidos e fundamentos pertinentes.", "Somente o nome da empresa.", "Apenas a data de admissão.", "Nenhum pedido específico."]), 0, "A demanda precisa apresentar elementos que permitam compreender a controvérsia e os pedidos.", "Questão autoral OAB FÁCIL; confira a CLT vigente."),
            (labour_process, "Na audiência trabalhista, devem ser observados:", json.dumps(["Regras de comparecimento, prova e participação das partes.", "Somente a presença do advogado.", "A ausência de contraditório.", "Nenhuma formalidade."]), 0, "A audiência observa contraditório, participação e as regras processuais aplicáveis.", "Questão autoral OAB FÁCIL; confira a CLT vigente."),
            (labour_process, "O estudo dos recursos trabalhistas deve considerar:", json.dumps(["Decisão recorrível, prazo, preparo quando aplicável e efeitos.", "Apenas a vontade da parte.", "Somente recursos civis.", "Nenhum requisito."]), 0, "Recursos exigem análise de cabimento, prazo, requisitos e efeitos no processo trabalhista.", "Questão autoral OAB FÁCIL; confira a CLT vigente."),
        ]
        human_rights_questions = [
            (human_rights, "A universalidade dos Direitos Humanos significa que:", json.dumps(["Eles pertencem a todas as pessoas, sem discriminação.", "Protegem apenas nacionais.", "Dependem sempre de riqueza.", "Valem somente em tempos de paz."]), 0, "A universalidade afirma a titularidade de todas as pessoas, respeitadas as normas de proteção.", "Questão autoral OAB FÁCIL; confira as fontes oficiais vigentes."),
            (human_rights, "O sistema interamericano de proteção está relacionado à:", json.dumps(["Proteção regional de direitos humanos nas Américas.", "Regulação exclusiva de contratos privados.", "Administração tributária.", "Organização de eleições municipais."]), 0, "O sistema interamericano é mecanismo regional de proteção de direitos humanos.", "Questão autoral OAB FÁCIL; confira as fontes oficiais vigentes."),
            (human_rights, "Tratados internacionais de Direitos Humanos devem ser estudados:", json.dumps(["Conforme seu texto, procedimento de incorporação e posição normativa aplicável.", "Sem consultar a Constituição.", "Como simples notícias.", "Sem observar sua vigência."]), 0, "A análise exige conferir texto, vigência, incorporação e posição normativa.", "Questão autoral OAB FÁCIL; confira a Constituição e os tratados vigentes."),
            (human_rights, "Uma revisão de Direitos Humanos deve relacionar:", json.dumps(["Princípios, tratados e mecanismos de proteção.", "Somente datas isoladas.", "Apenas legislação municipal.", "Nenhuma fonte internacional."]), 0, "O estudo deve integrar princípios, instrumentos internacionais e mecanismos de proteção.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        consumer_questions = [
            (consumer, "Na relação de consumo, fornecedor é quem:", json.dumps(["Desenvolve atividade de produção, montagem, criação, construção, distribuição ou comercialização, conforme a lei.", "Somente compra para uso próprio.", "Nunca presta serviços.", "É sempre pessoa física sem atividade."]), 0, "O conceito legal de fornecedor é amplo e inclui diversas atividades previstas no CDC.", "Questão autoral OAB FÁCIL; confira o CDC vigente."),
            (consumer, "A proteção contratual do consumidor busca:", json.dumps(["Equilibrar a relação e impedir abusos, conforme a lei.", "Eliminar todos os contratos.", "Permitir cláusulas abusivas.", "Dispensar informação."]), 0, "O CDC protege equilíbrio, informação e boa-fé nas relações de consumo.", "Questão autoral OAB FÁCIL; confira o CDC vigente."),
            (consumer, "A responsabilidade pelo produto ou serviço deve ser analisada:", json.dumps(["Conforme os requisitos e regimes previstos no CDC.", "Somente pela intenção do fornecedor.", "Sem considerar defeitos.", "Apenas pelo preço."]), 0, "O CDC possui regimes próprios de responsabilidade, que devem ser conferidos conforme o caso.", "Questão autoral OAB FÁCIL; confira o CDC vigente."),
            (consumer, "A defesa do consumidor pode envolver:", json.dumps(["Instrumentos administrativos, individuais e coletivos.", "Somente reclamação verbal.", "Apenas ação penal.", "Nenhum órgão de proteção."]), 0, "A proteção pode ocorrer por diferentes instrumentos e órgãos, conforme a legislação.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        eca_questions = [
            (eca, "A proteção integral reconhece crianças e adolescentes como:", json.dumps(["Pessoas em desenvolvimento, titulares de direitos.", "Objetos sem direitos próprios.", "Somente dependentes civis.", "Pessoas sem prioridade."]), 0, "O ECA reconhece crianças e adolescentes como sujeitos de direitos e pessoas em desenvolvimento.", "Questão autoral OAB FÁCIL; confira o ECA vigente."),
            (eca, "A prioridade absoluta envolve:", json.dumps(["Preferência na efetivação de direitos e na formulação de políticas, conforme a lei.", "Ausência de proteção familiar.", "Exclusão da escola.", "Somente prioridade econômica."]), 0, "A prioridade absoluta orienta políticas e atendimento, nos termos constitucionais e legais.", "Questão autoral OAB FÁCIL; confira a Constituição e o ECA vigentes."),
            (eca, "Ato infracional é a conduta descrita como:", json.dumps(["Crime ou contravenção penal.", "Qualquer comportamento inadequado.", "Somente infração civil.", "Apenas falta escolar."]), 0, "O ECA define ato infracional pela prática de conduta descrita como crime ou contravenção penal.", "Questão autoral OAB FÁCIL; confira o ECA vigente."),
            (eca, "O Conselho Tutelar é órgão voltado à:", json.dumps(["Zeladoria e atendimento dos direitos da criança e do adolescente, conforme suas atribuições.", "Aplicação de pena criminal.", "Substituição do Judiciário.", "Cobrança de tributos."]), 0, "O Conselho Tutelar exerce atribuições de proteção previstas no ECA, sem substituir o Poder Judiciário.", "Questão autoral OAB FÁCIL; confira o ECA vigente."),
        ]
        environmental_questions = [
            (environmental, "O princípio da prevenção orienta:", json.dumps(["Adoção de medidas diante de riscos ambientais conhecidos.", "Dispensa de fiscalização.", "Exploração sem limites.", "Ausência de licenciamento."]), 0, "A prevenção busca evitar danos quando os riscos são conhecidos ou previsíveis.", "Questão autoral OAB FÁCIL; confira a legislação vigente."),
            (environmental, "A responsabilidade por dano ambiental pode ser:", json.dumps(["Civil, administrativa e penal, conforme o caso.", "Somente contratual.", "Apenas moral.", "Nunca civil."]), 0, "As esferas de responsabilidade podem coexistir, observados os requisitos legais.", "Questão autoral OAB FÁCIL; confira a Constituição e a legislação vigente."),
            (environmental, "O licenciamento ambiental serve para:", json.dumps(["Controlar e avaliar atividades potencialmente causadoras de impacto.", "Autorizar qualquer atividade sem análise.", "Substituir toda fiscalização.", "Eliminar a responsabilidade."]), 0, "O licenciamento é instrumento de controle e avaliação ambiental nos casos previstos.", "Questão autoral OAB FÁCIL; confira a legislação vigente."),
            (environmental, "Uma revisão ambiental deve integrar:", json.dumps(["Princípios, instrumentos e responsabilidades.", "Somente conceitos econômicos.", "Apenas notícias.", "Nenhuma fonte oficial."]), 0, "A preparação deve relacionar princípios, instrumentos e regimes de responsabilidade.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        international_questions = [
            (international, "Entre as fontes do Direito Internacional estão:", json.dumps(["Tratados, costumes e princípios gerais, conforme a disciplina aplicável.", "Somente contratos internos.", "Apenas decretos municipais.", "Somente decisões privadas."]), 0, "Tratados, costumes e princípios são fontes clássicas do Direito Internacional.", "Questão autoral OAB FÁCIL; confira as fontes oficiais vigentes."),
            (international, "Nacionalidade é vínculo jurídico-político entre:", json.dumps(["A pessoa e o Estado.", "Somente duas empresas.", "Apenas consumidor e fornecedor.", "O juiz e a testemunha."]), 0, "Nacionalidade expressa vínculo jurídico-político entre pessoa e Estado.", "Questão autoral OAB FÁCIL; confira a Constituição e a legislação vigente."),
            (international, "O Direito Internacional Privado trata, entre outros temas, de:", json.dumps(["Conflitos de leis e critérios de conexão.", "Somente crimes militares.", "Apenas tributos municipais.", "Somente eleições locais."]), 0, "O Direito Internacional Privado resolve problemas de conexão entre ordenamentos.", "Questão autoral OAB FÁCIL; confira a legislação vigente."),
            (international, "A cooperação jurídica internacional pode envolver:", json.dumps(["Auxílio entre autoridades e reconhecimento de atos ou decisões, conforme a lei.", "Ausência de comunicação oficial.", "Somente relações diplomáticas informais.", "Nenhum procedimento."]), 0, "A cooperação possui instrumentos e procedimentos previstos em fontes nacionais e internacionais.", "Questão autoral OAB FÁCIL; confira o CPC e as fontes vigentes."),
        ]
        philosophy_questions = [
            (philosophy, "O positivismo jurídico costuma enfatizar:", json.dumps(["A validade do Direito conforme critérios do sistema jurídico.", "Somente sentimentos pessoais.", "A inexistência de normas.", "Apenas costumes familiares."]), 0, "O positivismo analisa a validade jurídica a partir de critérios do sistema, sem reduzir o estudo a preferências pessoais.", "Questão autoral OAB FÁCIL; material introdutório de estudo."),
            (philosophy, "Equidade está relacionada à:", json.dumps(["Consideração justa das particularidades na aplicação do Direito.", "Ausência de igualdade.", "Decisão sem fundamentação.", "Negação da justiça."]), 0, "Equidade permite considerar particularidades para alcançar solução justa dentro dos limites jurídicos.", "Questão autoral OAB FÁCIL; material introdutório de estudo."),
            (philosophy, "A relação entre Direito e moral pode ser estudada considerando:", json.dumps(["Suas aproximações e diferenças conceituais.", "Que são sempre idênticos.", "Que não possuem qualquer relação histórica.", "Somente a economia."]), 0, "A Filosofia do Direito investiga convergências e distinções entre Direito, moral e justiça.", "Questão autoral OAB FÁCIL; material introdutório de estudo."),
            (philosophy, "Uma boa revisão de Filosofia do Direito deve:", json.dumps(["Relacionar autores, correntes e conceitos.", "Memorizar nomes sem ideias.", "Ignorar o contexto.", "Usar apenas frases soltas."]), 0, "A revisão deve conectar autores, correntes e conceitos fundamentais.", "Questão autoral OAB FÁCIL; material introdutório de estudo."),
        ]
        electoral_questions = [
            (electoral, "O sufrágio está relacionado ao:", json.dumps(["Direito de participação política, conforme a Constituição e a lei.", "Direito exclusivamente contratual.", "Poder de tributar.", "Registro empresarial."]), 0, "Sufrágio integra os direitos políticos e deve ser estudado conforme as regras constitucionais e eleitorais.", "Questão autoral OAB FÁCIL; confira as fontes vigentes."),
            (electoral, "Partidos políticos são instrumentos de:", json.dumps(["Organização da participação política e representação, conforme a lei.", "Administração de empresas privadas.", "Cobrança de impostos.", "Atuação jurisdicional."]), 0, "Partidos organizam a participação política dentro dos parâmetros constitucionais e legais.", "Questão autoral OAB FÁCIL; confira a Constituição e a legislação vigente."),
            (electoral, "Inelegibilidade representa, em linhas gerais:", json.dumps(["Impedimento jurídico à candidatura em hipóteses legais.", "Garantia de eleição automática.", "Perda de nacionalidade.", "Sanção civil para qualquer eleitor."]), 0, "Inelegibilidades restringem candidaturas nas hipóteses previstas na Constituição e na lei.", "Questão autoral OAB FÁCIL; confira a legislação vigente."),
            (electoral, "A revisão eleitoral deve conferir especialmente:", json.dumps(["Constituição, legislação atualizada e jurisprudência aplicável.", "Somente material antigo.", "Apenas notícias sem fonte.", "Nenhuma alteração normativa."]), 0, "Direito Eleitoral sofre alterações e exige conferência de fontes oficiais atualizadas.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        financial_questions = [
            (financial, "O orçamento público está relacionado ao planejamento de:", json.dumps(["Receitas, despesas e ações governamentais, conforme a lei.", "Somente contratos privados.", "Apenas eleições.", "Nenhuma atividade estatal."]), 0, "O orçamento organiza planejamento e execução financeira do Estado.", "Questão autoral OAB FÁCIL; confira a Constituição e a legislação vigente."),
            (financial, "A despesa pública deve observar:", json.dumps(["Fases e requisitos previstos na legislação orçamentária.", "Somente autorização verbal.", "Ausência de empenho.", "Nenhum controle."]), 0, "A despesa pública segue fases e controles legais, conforme o regime aplicável.", "Questão autoral OAB FÁCIL; confira a legislação vigente."),
            (financial, "A responsabilidade fiscal busca promover:", json.dumps(["Planejamento, transparência e equilíbrio na gestão fiscal.", "Gasto sem limite.", "Ausência de prestação de contas.", "Sigilo de todo orçamento."]), 0, "A responsabilidade fiscal estabelece regras de planejamento, transparência e controle.", "Questão autoral OAB FÁCIL; confira a legislação vigente."),
            (financial, "Na revisão de Direito Financeiro, é importante relacionar:", json.dumps(["Orçamento, receitas, despesas e controle.", "Somente números isolados.", "Apenas Direito Penal.", "Nenhuma fonte legal."]), 0, "A visão integrada facilita a compreensão do ciclo orçamentário e dos controles.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        social_security_questions = [
            (social_security, "A seguridade social compreende:", json.dumps(["Saúde, previdência social e assistência social.", "Somente previdência privada.", "Apenas relações trabalhistas.", "Somente seguro empresarial."]), 0, "A Constituição estrutura a seguridade social em saúde, previdência e assistência.", "Questão autoral OAB FÁCIL; confira a Constituição vigente."),
            (social_security, "A concessão de benefício previdenciário depende:", json.dumps(["Do preenchimento dos requisitos legais aplicáveis.", "Somente de pedido verbal.", "De escolha livre do servidor.", "Nunca de contribuição ou condição legal."]), 0, "Benefícios possuem requisitos próprios, que devem ser conferidos na legislação vigente.", "Questão autoral OAB FÁCIL; confira a legislação vigente."),
            (social_security, "O custeio da seguridade social envolve:", json.dumps(["Fontes e contribuições previstas na Constituição e na lei.", "Somente doações privadas.", "Apenas multas criminais.", "Nenhuma fonte pública."]), 0, "O sistema possui fontes de custeio constitucional e legalmente previstas.", "Questão autoral OAB FÁCIL; confira a Constituição e a legislação vigente."),
            (social_security, "A revisão previdenciária deve priorizar:", json.dumps(["Legislação atualizada e requisitos específicos de cada benefício.", "Resumos sem data.", "Somente notícias.", "Nenhuma fonte oficial."]), 0, "A legislação previdenciária exige conferência de alterações e dos requisitos do caso.", "Questão autoral OAB FÁCIL; material de estudo, não substitui a fonte oficial."),
        ]
        extra_source = "Questão autoral OAB FÁCIL; confira a legislação e a fonte oficial vigentes."
        civil_questions += [(civil, "Na responsabilidade pelo fato do produto, a análise deve considerar:", json.dumps(["O regime legal aplicável e os requisitos do defeito e do dano.", "Somente a vontade do consumidor.", "A inexistência de nexo causal em qualquer hipótese.", "Apenas o preço do produto."]), 0, "A responsabilidade deve ser analisada conforme o regime legal aplicável, defeito, dano e nexo.", extra_source), (civil, "A prescrição e a decadência distinguem-se porque:", json.dumps(["Possuem natureza e efeitos próprios, que devem ser examinados conforme a pretensão e a lei.", "São sempre sinônimos.", "Nunca dependem de prazo legal.", "Somente existem no Direito Penal."]), 0, "Prescrição e decadência têm regimes distintos e exigem análise do direito envolvido e da legislação.", extra_source)]
        process_civil_questions += [(process_civil, "A tutela provisória pode ser estudada a partir de:", json.dumps(["Urgência ou evidência, conforme os requisitos legais.", "Apenas sentença transitada em julgado.", "Somente acordo extrajudicial.", "Nenhuma fundamentação."]), 0, "O CPC disciplina tutelas de urgência e de evidência com requisitos próprios.", extra_source), (process_civil, "O contraditório no processo civil deve ser compreendido como:", json.dumps(["Participação e possibilidade de influência das partes, ressalvadas hipóteses legais.", "Direito exclusivo do juiz.", "Dispensa de ciência dos atos.", "Proibição de produção de prova."]), 0, "O contraditório envolve ciência, participação e possibilidade de influência nos limites legais.", extra_source)]
        constitutional_questions += [(constitutional, "O controle de constitucionalidade examina:", json.dumps(["Compatibilidade de atos normativos com a Constituição, conforme o modelo aplicável.", "Somente contratos privados.", "Apenas fatos sem norma.", "A conveniência administrativa sem parâmetros."]), 0, "O controle verifica compatibilidade constitucional segundo as vias e competências previstas.", extra_source), (constitutional, "A federação brasileira pressupõe:", json.dumps(["Repartição constitucional de competências e autonomia dos entes federados.", "Subordinação absoluta dos municípios a particulares.", "Ausência de Constituição.", "Competência única da União para todo assunto."]), 0, "A federação organiza autonomia e repartição de competências nos termos constitucionais.", extra_source)]
        penal_questions += [(penal, "A tentativa é analisada quando:", json.dumps(["A execução começa, mas o crime não se consuma por circunstâncias alheias à vontade do agente, conforme a lei.", "Há apenas pensamento sem ato executório.", "O resultado ocorre integralmente.", "Não existe início de execução."]), 0, "A tentativa exige início da execução e não consumação por circunstâncias alheias à vontade, observadas as regras legais.", extra_source), (penal, "A legítima defesa exige, em linhas gerais:", json.dumps(["Agressão injusta atual ou iminente e uso moderado dos meios necessários.", "Qualquer vingança posterior.", "Agressão já encerrada em todos os casos.", "Ausência de perigo ou agressão."]), 0, "A excludente deve ser analisada pelos requisitos legais de agressão e reação moderada.", extra_source)]
        process_penal_questions += [(process_penal, "A prisão cautelar deve ser examinada:", json.dumps(["À luz dos requisitos legais, da necessidade e da fundamentação concreta.", "Como antecipação automática da pena.", "Sem decisão fundamentada.", "Independentemente de qualquer hipótese legal."]), 0, "Medidas cautelares exigem requisitos e fundamentação, não equivalendo automaticamente à pena.", extra_source), (process_penal, "O devido processo penal envolve:", json.dumps(["Garantias como juiz competente, defesa, contraditório e limites probatórios.", "Ausência de defesa.", "Punição sem acusação.", "Dispensa de fundamentação."]), 0, "O devido processo reúne garantias constitucionais e legais de julgamento válido.", extra_source)]
        administrative_questions += [(administrative, "A anulação de ato administrativo relaciona-se, em regra, à:", json.dumps(["Ilegalidade do ato, observados competência e procedimento aplicáveis.", "Conveniência de ato sempre válido.", "Vontade particular sem fundamento.", "Ausência de controle."]), 0, "A anulação se liga à ilegalidade; a revogação, em linhas gerais, à conveniência e oportunidade dentro dos limites legais.", extra_source)]
        labour_questions += [(labour, "A alteração contratual trabalhista deve ser analisada considerando:", json.dumps(["Os limites legais e a proteção contra alteração lesiva, conforme o caso.", "A liberdade irrestrita do empregador.", "A inexistência de contrato.", "Somente a vontade de terceiros."]), 0, "Alterações contratuais estão sujeitas aos limites da legislação e à proteção do trabalhador.", extra_source)]
        labour_process_questions += [(labour_process, "O ônus da prova no processo do trabalho deve ser examinado conforme:", json.dumps(["As regras legais, a distribuição aplicável e as circunstâncias do caso.", "Uma regra fixa sem exceções.", "A vontade da testemunha.", "A ausência de alegações."]), 0, "A distribuição do ônus da prova depende da legislação e da análise do caso concreto.", extra_source)]
        tax_questions += [(tax, "A obrigação tributária principal tem por objeto:", json.dumps(["O pagamento de tributo ou penalidade pecuniária, conforme a lei.", "A prestação de serviço privado.", "Apenas uma recomendação.", "A criação de sentença."]), 0, "O CTN disciplina a obrigação principal e seu objeto nos termos legais.", extra_source)]
        question_groups = {ethics: question_rows, civil: civil_questions, constitutional: constitutional_questions, process_civil: process_civil_questions, penal: penal_questions, administrative: administrative_questions, labour: labour_questions, tax: tax_questions, business: business_questions, process_penal: process_penal_questions, labour_process: labour_process_questions, human_rights: human_rights_questions, consumer: consumer_questions, eca: eca_questions, environmental: environmental_questions, international: international_questions, philosophy: philosophy_questions, electoral: electoral_questions, financial: financial_questions, social_security: social_security_questions}
        for subject_id, rows_to_seed in question_groups.items():
            for question_row in rows_to_seed:
                exists = fetch_one(conn, "SELECT id FROM questions WHERE subject_id = %s AND prompt = %s", (question_row[0], question_row[1]))
                if exists:
                    continue
                execute(conn, "INSERT INTO questions (subject_id, prompt, options_json, answer_index, explanation, source_note) VALUES (%s, %s, %s, %s, %s, %s)", question_row)

        practical_rows = [
            (phase2_admin, "Mandado de segurança administrativo", "Ato ilegal de autoridade pública com prova pré-constituída.", "Endereçamento; partes; cabimento; fatos; direito; liminar; pedidos; fechamento.", "Autoridade coatora; prazo; prova; fundamento constitucional; pedido liminar.", "Material autoral OAB FÁCIL; confira o edital e a legislação vigente."),
            (phase2_civil, "Apelação cível", "Parte vencida pretende impugnar sentença desfavorável.", "Interposição; razões; preliminares; mérito; pedidos; fechamento.", "Tempestividade; preparo; dialeticidade; fundamentos; pedido de reforma.", "Material autoral OAB FÁCIL; confira o edital e o CPC vigente."),
            (phase2_constitutional, "Mandado de segurança constitucional", "Direito líquido e certo ameaçado por ato de autoridade.", "Competência; legitimidade; ato coator; fundamentos; liminar; pedidos.", "Autoridade; prazo; prova pré-constituída; adequação do remédio.", "Material autoral OAB FÁCIL; confira o edital e a Constituição vigente."),
            (phase2_labour, "Contestação trabalhista", "Reclamado responde aos pedidos de reclamação trabalhista.", "Endereçamento; preliminares; prejudiciais; mérito; provas; requerimentos.", "Prescrição; impugnação específica; documentos; verbas; pedidos finais.", "Material autoral OAB FÁCIL; confira o edital e a CLT vigente."),
            (phase2_business, "Petição de recuperação judicial", "Empresa viável em crise busca reorganização judicial.", "Endereçamento; crise; requisitos; documentos; pedidos.", "Legitimidade; requisitos; documentos indispensáveis; preservação.", "Material autoral OAB FÁCIL; confira o edital e a legislação vigente."),
            (phase2_penal, "Apelação criminal", "Réu impugna sentença condenatória.", "Interposição; razões; preliminares; mérito; pedidos.", "Tempestividade; nulidades; prova; tipificação; pena; reforma.", "Material autoral OAB FÁCIL; confira o edital e o CPP vigente."),
            (phase2_tax, "Ação anulatória tributária", "Contribuinte busca desconstituir cobrança indevida.", "Partes; fatos; cabimento; fundamentos; tutela; pedidos; provas.", "Ato impugnado; prazo; legitimidade; garantia; pedido tributário.", "Material autoral OAB FÁCIL; confira o edital, a Constituição e o CTN vigentes."),
        ]
        practical_rows += [
            (phase2_admin, "Ação anulatória de ato administrativo", "Servidor busca afastar penalidade administrativa aplicada sem observância do contraditório.", "Endereçamento; partes; fatos; cabimento; nulidades; mérito; tutela; pedidos.", "Processo administrativo; contraditório; motivação; prazo; prova documental; pedido de urgência.", "Material autoral OAB FÁCIL; confira o edital e a legislação vigente."),
            (phase2_civil, "Contestação cível", "Réu é citado em ação de cobrança e precisa impugnar fatos, documentos e pedidos.", "Endereçamento; preliminares; fatos; mérito; provas; pedidos.", "Tempestividade; impugnação específica; prescrição quando cabível; documentos; requerimentos.", "Material autoral OAB FÁCIL; confira o edital e o CPC vigente."),
            (phase2_constitutional, "Ação popular", "Cidadão pretende questionar ato lesivo ao patrimônio público e à moralidade administrativa.", "Competência; legitimidade; fatos; fundamentos; prova; tutela; pedidos.", "Título eleitoral; ato lesivo; legitimidade passiva; prova; pedido de anulação.", "Material autoral OAB FÁCIL; confira o edital e a Constituição vigente."),
            (phase2_labour, "Reclamação trabalhista", "Trabalhador relata parcelas contratuais não pagas e busca tutela jurisdicional.", "Endereçamento; qualificação; contrato; fatos; fundamentos; pedidos; valor; provas.", "Vínculo; jornada; verbas; prescrição; pedidos líquidos quando exigidos; fechamento.", "Material autoral OAB FÁCIL; confira o edital e a CLT vigente."),
            (phase2_business, "Habilitação ou divergência de crédito", "Credor identifica erro na relação de créditos publicada no processo de recuperação.", "Endereçamento; identificação do crédito; origem; documentos; pedidos.", "Legitimidade; classificação; valor; atualização; prova documental; prazo.", "Material autoral OAB FÁCIL; confira o edital e a legislação vigente."),
            (phase2_penal, "Resposta à acusação", "Acusado recebe denúncia e deve apresentar defesa inicial no prazo legal.", "Endereçamento; identificação; preliminares; mérito; provas; pedidos.", "Tempestividade; inépcia quando cabível; absolvição sumária; rol de testemunhas; diligências.", "Material autoral OAB FÁCIL; confira o edital e o CPP vigente."),
            (phase2_tax, "Mandado de segurança tributário", "Contribuinte pretende afastar exigência tributária ilegal demonstrada por prova pré-constituída.", "Competência; autoridade; direito líquido e certo; liminar; mérito; pedidos.", "Ato coator; prazo; prova; legitimidade; fundamento constitucional e tributário.", "Material autoral OAB FÁCIL; confira o edital, a Constituição e o CTN vigentes."),
        ]
        discursive_rows = [
            (phase2_admin, "Diferencie anulação e revogação do ato administrativo.", "Anulação decorre de ilegalidade; revogação incide sobre ato válido por conveniência e oportunidade, respeitados os limites legais.", "Material autoral OAB FÁCIL; confira as fontes vigentes."),
            (phase2_civil, "Apresente os requisitos gerais da tutela de urgência.", "Devem ser analisados probabilidade do direito e perigo de dano ou risco ao resultado útil, conforme o CPC.", "Material autoral OAB FÁCIL; confira o CPC vigente."),
            (phase2_constitutional, "Indique a finalidade do mandado de injunção.", "Busca viabilizar direito, liberdade ou prerrogativa constitucional inviabilizada pela falta de norma regulamentadora.", "Material autoral OAB FÁCIL; confira a Constituição vigente."),
            (phase2_labour, "Diferencie relação de trabalho e relação de emprego.", "Relação de emprego exige os elementos legais específicos; relação de trabalho é gênero mais amplo.", "Material autoral OAB FÁCIL; confira a CLT vigente."),
            (phase2_business, "Indique a finalidade da recuperação judicial.", "Busca superar a crise econômico-financeira e preservar empresa viável, empregos e interesses envolvidos.", "Material autoral OAB FÁCIL; confira a legislação vigente."),
            (phase2_penal, "Diferencie dolo e culpa.", "Dolo envolve vontade e consciência nos termos legais; culpa decorre de violação do dever de cuidado nas hipóteses legais.", "Material autoral OAB FÁCIL; confira o Código Penal vigente."),
            (phase2_tax, "Diferencie imunidade e isenção.", "Imunidade é limitação constitucional à competência tributária; isenção é dispensa legal do pagamento em hipótese definida pela lei.", "Material autoral OAB FÁCIL; confira a Constituição e o CTN vigentes."),
        ]
        discursive_rows += [
            (phase2_admin, "Quais elementos devem ser verificados no controle de uma sanção administrativa?", "Devem ser examinados competência, procedimento, contraditório, motivação, prova, proporcionalidade e adequação da sanção ao caso.", "Material autoral OAB FÁCIL; confira as fontes vigentes."),
            (phase2_civil, "Explique a diferença entre prescrição e decadência no caso concreto.", "A resposta deve identificar a natureza do prazo, o direito envolvido, o termo inicial e os efeitos previstos na legislação aplicável.", "Material autoral OAB FÁCIL; confira o CPC e o Código Civil vigentes."),
            (phase2_constitutional, "Indique os requisitos gerais para o cabimento da ação popular.", "A resposta deve abordar legitimidade cidadã, ato lesivo e proteção do patrimônio público, moralidade, meio ambiente ou patrimônio histórico, conforme a Constituição e a lei.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente."),
            (phase2_labour, "Como deve ser analisada a prescrição trabalhista em uma reclamação?", "É necessário identificar o vínculo, os marcos temporais, os limites constitucionais e legais e os pedidos atingidos pelo prazo.", "Material autoral OAB FÁCIL; confira a Constituição e a CLT vigentes."),
            (phase2_business, "Qual é a função da verificação de créditos na recuperação judicial?", "A verificação organiza existência, valor e classificação dos créditos, permitindo a formação adequada do quadro de credores conforme o procedimento legal.", "Material autoral OAB FÁCIL; confira a legislação vigente."),
            (phase2_penal, "O que pode ser alegado na resposta à acusação?", "Podem ser apresentadas preliminares, argumentos de mérito, pedidos de absolvição sumária quando cabíveis e especificação das provas pretendidas.", "Material autoral OAB FÁCIL; confira o CPP vigente."),
            (phase2_tax, "Quais cuidados devem orientar um mandado de segurança tributário?", "A resposta deve verificar ato coator, direito líquido e certo, prova pré-constituída, autoridade competente, prazo e pedido liminar, sem transformar a ação em dilação probatória ampla.", "Material autoral OAB FÁCIL; confira a Constituição, o CTN e a legislação vigente."),
        ]
        if is_postgres():
            with conn.cursor() as cur:
                cur.executemany("INSERT INTO practical_pieces (subject_id, title, scenario, structure, checklist, source_note) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING", practical_rows)
                cur.executemany("INSERT INTO discursive_questions (subject_id, prompt, model_answer, source_note) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING", discursive_rows)
        else:
            conn.executemany("INSERT OR IGNORE INTO practical_pieces (subject_id, title, scenario, structure, checklist, source_note) VALUES (?, ?, ?, ?, ?, ?)", practical_rows)
            conn.executemany("INSERT OR IGNORE INTO discursive_questions (subject_id, prompt, model_answer, source_note) VALUES (?, ?, ?, ?)", discursive_rows)

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


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


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
    if limited(client_key("register"), 5, 3600):
        return jsonify({"ok": False, "message": "Muitas tentativas de cadastro. Tente novamente mais tarde."}), 429
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
    if limited(client_key("login"), 8, 900):
        return jsonify({"ok": False, "message": "Muitas tentativas. Aguarde alguns minutos e tente novamente."}), 429
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


@app.post("/api/password/forgot")
def forgot_password():
    if limited(client_key("forgot"), 3, 900):
        return jsonify({"ok": True, "message": "Se o e-mail estiver cadastrado, enviaremos instruções de recuperação."})
    payload = request.get_json(silent=True) or request.form
    email = str(payload.get("email", "")).strip().lower()
    # A resposta é sempre genérica para não revelar quais e-mails têm conta.
    if EMAIL_RE.match(email):
        conn = connection()
        try:
            row = fetch_one(conn, "SELECT id FROM users WHERE email = %s", (email,))
            if row:
                raw_token = secrets.token_urlsafe(32)
                digest = token_digest(raw_token)
                expires = datetime.now(timezone.utc) + timedelta(minutes=30)
                execute(conn, "DELETE FROM password_reset_tokens WHERE user_id = %s AND used_at IS NULL", (row[0],))
                execute(conn, "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (%s, %s, %s)", (row[0], digest, expires))
                conn.commit()
                try:
                    send_reset_email(email, raw_token)
                except (OSError, smtplib.SMTPException):
                    # O token permanece protegido no banco; não é exposto em resposta ou log.
                    pass
        finally:
            conn.close()
    return jsonify({"ok": True, "message": "Se o e-mail estiver cadastrado, enviaremos instruções de recuperação."})


@app.post("/api/password/reset")
def reset_password():
    if limited(client_key("reset"), 5, 900):
        return jsonify({"ok": False, "message": "Muitas tentativas de redefinição. Aguarde alguns minutos."}), 429
    payload = request.get_json(silent=True) or request.form
    raw_token = str(payload.get("token", "")).strip()
    new_password = str(payload.get("new_password", ""))
    if len(raw_token) < 20 or len(new_password) < 8:
        return jsonify({"ok": False, "message": "Token inválido ou senha com menos de 8 caracteres."}), 400
    conn = connection()
    try:
        row = fetch_one(conn, "SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = %s", (token_digest(raw_token),))
        if not row or row[3]:
            return jsonify({"ok": False, "message": "Token inválido ou já utilizado."}), 400
        expires = row[2]
        if isinstance(expires, str):
            expires = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= datetime.now(timezone.utc):
            return jsonify({"ok": False, "message": "Este token expirou. Solicite uma nova recuperação."}), 400
        execute(conn, "UPDATE users SET password_hash = %s WHERE id = %s", (generate_password_hash(new_password), row[1]))
        execute(conn, "UPDATE password_reset_tokens SET used_at = %s WHERE id = %s", (datetime.now(timezone.utc), row[0]))
        conn.commit()
    finally:
        conn.close()
    session.clear()
    session["user_id"] = row[1]
    return jsonify({"ok": True, "message": "Senha redefinida com sucesso."})


@app.post("/api/account/password")
def change_password():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"ok": False, "message": "Faça login para continuar."}), 401
    payload = request.get_json(silent=True) or {}
    current = str(payload.get("current_password", ""))
    new_password = str(payload.get("new_password", ""))
    if len(new_password) < 8:
        return jsonify({"ok": False, "message": "A nova senha precisa ter pelo menos 8 caracteres."}), 400
    conn = connection()
    try:
        row = fetch_one(conn, "SELECT password_hash FROM users WHERE id = %s", (user_id,))
        if not row or not check_password_hash(row[0], current):
            return jsonify({"ok": False, "message": "A senha atual não confere."}), 400
        execute(conn, "UPDATE users SET password_hash = %s WHERE id = %s", (generate_password_hash(new_password), user_id))
        conn.commit()
    finally:
        conn.close()
    session.clear()
    session["user_id"] = user_id
    return jsonify({"ok": True, "message": "Senha atualizada com segurança."})


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


@app.get("/api/subjects")
def subjects():
    if not logged_user_id():
        return jsonify({"message": "Faça login para continuar."}), 401
    conn = connection()
    try:
        rows = fetch_all(conn, "SELECT s.id, s.name, s.phase, s.question_weight, COUNT(q.id) FROM subjects s LEFT JOIN questions q ON q.subject_id = s.id GROUP BY s.id, s.name, s.phase, s.question_weight, s.sort_order ORDER BY s.sort_order")
    finally:
        conn.close()
    return jsonify({"ok": True, "subjects": [{"id": r[0], "name": r[1], "phase": r[2], "question_weight": r[3], "questions": r[4]} for r in rows]})


@app.get("/api/lessons")
def lessons():
    if not logged_user_id():
        return jsonify({"message": "Faça login para continuar."}), 401
    subject_id = request.args.get("subject", type=int)
    conn = connection()
    try:
        if subject_id:
            rows = fetch_all(conn, "SELECT id, title, summary, source_note FROM lessons WHERE subject_id = %s ORDER BY sort_order", (subject_id,))
        else:
            rows = fetch_all(conn, "SELECT id, title, summary, source_note FROM lessons ORDER BY subject_id, sort_order")
    finally:
        conn.close()
    return jsonify({"ok": True, "lessons": [{"id": r[0], "title": r[1], "summary": r[2], "source_note": r[3]} for r in rows]})


@app.get("/api/phase2/mock")
def phase2_mock():
    if not logged_user_id():
        return jsonify({"message": "Faça login para continuar."}), 401
    subject_id = request.args.get("subject", type=int)
    if not subject_id:
        return jsonify({"message": "Informe a área da 2ª fase."}), 400
    conn = connection()
    try:
        piece = fetch_one(conn, "SELECT id, title, scenario, structure, checklist, source_note FROM practical_pieces WHERE subject_id = %s ORDER BY id LIMIT 1", (subject_id,))
        questions = fetch_all(conn, "SELECT id, prompt, source_note FROM discursive_questions WHERE subject_id = %s ORDER BY id LIMIT 4", (subject_id,))
    finally:
        conn.close()
    if not piece or len(questions) < 4:
        return jsonify({"message": "Esta área ainda não possui material suficiente para o simulado."}), 409
    return jsonify({"ok": True, "subject_id": subject_id, "piece": {"id": piece[0], "title": piece[1], "scenario": piece[2], "structure": piece[3], "checklist": piece[4], "source_note": piece[5]}, "questions": [{"id": row[0], "prompt": row[1], "source_note": row[2]} for row in questions]})


@app.post("/api/phase2/mock/submit")
def submit_phase2_mock():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    payload = request.get_json(silent=True) or {}
    subject_id = int(payload.get("subject_id", 0) or 0)
    piece_id = int(payload.get("piece_id", 0) or 0)
    piece = payload.get("piece", {})
    answers = payload.get("answers", [])
    duration = max(0, int(payload.get("duration_seconds", 0) or 0))
    if not subject_id or not piece_id or not isinstance(piece, dict) or not isinstance(answers, list) or len(answers) != 4:
        return jsonify({"message": "Envie a peça e as quatro respostas do simulado."}), 400
    piece_criteria = piece.get("criteria", {})
    if not isinstance(piece_criteria, dict):
        return jsonify({"message": "Critérios da peça inválidos."}), 400
    score = min(10, sum(2 for key in ("cabimento", "fundamento", "estrutura", "pedidos", "clareza") if piece_criteria.get(key)))
    normalized = [{"question_id": int(item.get("question_id", 0) or 0), "answer": str(item.get("answer", "")).strip(), "criteria": item.get("criteria", {})} for item in answers if isinstance(item, dict)]
    if len(normalized) != 4 or any(len(item["answer"]) < 20 or not isinstance(item["criteria"], dict) for item in normalized):
        return jsonify({"message": "Cada resposta precisa ter pelo menos 20 caracteres e critérios marcados."}), 400
    conn = connection()
    try:
        valid_piece = fetch_one(conn, "SELECT id FROM practical_pieces WHERE id = %s AND subject_id = %s", (piece_id, subject_id))
        question_ids = [item["question_id"] for item in normalized]
        placeholders = ",".join(["%s"] * len(question_ids))
        valid_questions = fetch_all(conn, f"SELECT id FROM discursive_questions WHERE subject_id = %s AND id IN ({placeholders})", (subject_id,) + tuple(question_ids))
    finally:
        conn.close()
    if len(set(question_ids)) != 4 or not valid_piece or {row[0] for row in valid_questions} != set(question_ids):
        return jsonify({"message": "A peça ou as questões não pertencem à área selecionada."}), 400
    for item in normalized:
        item["score"] = min(10, sum(2 for key in ("cabimento", "fundamento", "aplicacao", "conclusao", "clareza") if item["criteria"].get(key)))
        score += item["score"]
    piece_keys = ("cabimento", "fundamento", "estrutura", "pedidos", "clareza")
    answer_keys = ("cabimento", "fundamento", "aplicacao", "conclusao", "clareza")
    missing_piece = [key for key in piece_keys if not piece_criteria.get(key)]
    conn = connection()
    try:
        execute(conn, "INSERT INTO phase2_mock_attempts (user_id, subject_id, piece_id, answers_json, score, max_score, duration_seconds) VALUES (%s, %s, %s, %s, %s, %s, %s)", (user_id, subject_id, piece_id, json.dumps({"piece": piece, "answers": normalized}), score, 50, duration))
        if missing_piece:
            execute(conn, "INSERT INTO phase2_review_items (user_id, subject_id, title, detail) VALUES (%s, %s, %s, %s)", (user_id, subject_id, "Revisar critérios da peça", "Reforce: " + ", ".join(missing_piece) + "."))
        for item in normalized:
            missing = [key for key in answer_keys if not item["criteria"].get(key)]
            if missing:
                execute(conn, "INSERT INTO phase2_review_items (user_id, subject_id, title, detail) VALUES (%s, %s, %s, %s)", (user_id, subject_id, "Revisar questão discursiva", f"Questão {item['question_id']}: reforce " + ", ".join(missing) + "."))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "score": score, "max_score": 50, "feedback": "Resultado orientador salvo. Revise a peça, compare os fundamentos e confira a legislação e o edital vigentes.", "review": {"piece_missing": missing_piece, "answers": [{"question_id": item["question_id"], "score": item["score"], "missing": [key for key in answer_keys if not item["criteria"].get(key)]} for item in normalized]}})


@app.get("/api/phase2/reviews")
def phase2_reviews():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    conn = connection()
    try:
        rows = fetch_all(conn, "SELECT r.id, r.title, r.detail, r.completed, s.name FROM phase2_review_items r JOIN subjects s ON s.id = r.subject_id WHERE r.user_id = %s ORDER BY r.completed, r.id DESC", (user_id,))
    finally:
        conn.close()
    return jsonify({"ok": True, "reviews": [{"id": r[0], "title": r[1], "detail": r[2], "completed": bool(r[3]), "subject": r[4]} for r in rows]})


@app.post("/api/phase2/reviews/<int:review_id>/complete")
def complete_phase2_review(review_id):
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    completed = bool((request.get_json(silent=True) or {}).get("completed"))
    conn = connection()
    try:
        execute(conn, "UPDATE phase2_review_items SET completed = %s WHERE id = %s AND user_id = %s", (completed, review_id, user_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.get("/api/phase2/materials")
def phase2_materials():
    if not logged_user_id():
        return jsonify({"message": "Faça login para continuar."}), 401
    subject_id = request.args.get("subject", type=int)
    if not subject_id:
        return jsonify({"message": "Informe a área da 2ª fase."}), 400
    conn = connection()
    try:
        pieces = fetch_all(conn, "SELECT id, title, scenario, structure, checklist, source_note FROM practical_pieces WHERE subject_id = %s ORDER BY id", (subject_id,))
        discursives = fetch_all(conn, "SELECT id, prompt, model_answer, source_note FROM discursive_questions WHERE subject_id = %s ORDER BY id", (subject_id,))
    finally:
        conn.close()
    return jsonify({"ok": True, "pieces": [{"id": r[0], "title": r[1], "scenario": r[2], "structure": r[3], "checklist": r[4], "source_note": r[5]} for r in pieces], "discursives": [{"id": r[0], "prompt": r[1], "model_answer": r[2], "source_note": r[3]} for r in discursives]})


@app.post("/api/phase2/discursive/assess")
def assess_discursive():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    payload = request.get_json(silent=True) or {}
    subject_id = int(payload.get("subject_id", 0) or 0)
    question_id = int(payload.get("question_id", 0) or 0)
    answer = str(payload.get("answer", "")).strip()
    criteria = payload.get("criteria", {})
    if not subject_id or not question_id or len(answer) < 20 or not isinstance(criteria, dict):
        return jsonify({"message": "Escreva uma resposta com pelo menos 20 caracteres e marque os critérios."}), 400
    score = sum(2 for key in ("cabimento", "fundamento", "aplicacao", "conclusao", "clareza") if criteria.get(key))
    feedback = "Boa estrutura inicial. Revise a fonte oficial e compare sua resposta com a orientação." if score >= 6 else "Volte ao enunciado, identifique o instituto, fundamente e conclua com pedido ou consequência jurídica."
    conn = connection()
    try:
        execute(conn, "INSERT INTO discursive_attempts (user_id, subject_id, question_id, answer, score, feedback) VALUES (%s, %s, %s, %s, %s, %s)", (user_id, subject_id, question_id, answer, score, feedback))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "score": score, "max_score": 10, "feedback": feedback})


@app.get("/api/performance")
def performance():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    conn = connection()
    try:
        objective = fetch_all(conn, """SELECT s.name, COUNT(a.id), COALESCE(SUM(a.score), 0), COALESCE(SUM(a.total), 0)
            FROM quiz_attempts a JOIN subjects s ON s.id = a.subject_id WHERE a.user_id = %s
            GROUP BY s.name ORDER BY s.name""", (user_id,))
        discursive = fetch_all(conn, """SELECT s.name, COUNT(d.id), COALESCE(SUM(d.score), 0)
            FROM discursive_attempts d JOIN subjects s ON s.id = d.subject_id WHERE d.user_id = %s
            GROUP BY s.name ORDER BY s.name""", (user_id,))
        phase2 = fetch_all(conn, """SELECT s.name, COUNT(m.id), COALESCE(SUM(m.score), 0), COALESCE(MAX(m.max_score), 50)
            FROM phase2_mock_attempts m JOIN subjects s ON s.id = m.subject_id WHERE m.user_id = %s
            GROUP BY s.name ORDER BY s.name""", (user_id,))
    finally:
        conn.close()
    return jsonify({"ok": True, "objective": [{"subject": r[0], "attempts": r[1], "score": r[2], "total": r[3]} for r in objective], "discursive": [{"subject": r[0], "attempts": r[1], "score": r[2], "max_score": r[1] * 10} for r in discursive], "phase2": [{"subject": r[0], "attempts": r[1], "score": r[2], "max_score": r[3]} for r in phase2]})


@app.get("/api/calendar")
def calendar():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    user = user_row(user_id)
    conn = connection()
    try:
        count = fetch_one(conn, "SELECT COUNT(*) FROM calendar_events WHERE user_id = %s", (user_id,))[0]
        if count == 0:
            plan_days = user[3] if user else 30
            schedule = [(0, "Diagnóstico inicial", "estudo"), (2, "Revisão de Ética e Estatuto", "revisão"), (6, "Simulado semanal", "simulado"), (13, "Revisão dos erros", "revisão"), (20, "Bloco de questões", "questões"), (plan_days - 1, "Fechamento do ciclo", "revisão")]
            events = [(user_id, title, date.today() + timedelta(days=min(offset, max(plan_days - 1, 0))), category) for offset, title, category in schedule]
            if is_postgres():
                with conn.cursor() as cur:
                    cur.executemany("INSERT INTO calendar_events (user_id, title, event_date, category) VALUES (%s, %s, %s, %s)", events)
            else:
                conn.executemany("INSERT INTO calendar_events (user_id, title, event_date, category) VALUES (?, ?, ?, ?)", [(u, t, d.isoformat(), c) for u, t, d, c in events])
            conn.commit()
        rows = fetch_all(conn, "SELECT id, title, event_date, category, completed FROM calendar_events WHERE user_id = %s ORDER BY event_date, id")
    finally:
        conn.close()
    return jsonify({"ok": True, "events": [{"id": r[0], "title": r[1], "event_date": str(r[2]), "category": r[3], "completed": bool(r[4])} for r in rows]})


@app.post("/api/calendar/<int:event_id>/complete")
def complete_calendar_event(event_id):
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    completed = bool((request.get_json(silent=True) or {}).get("completed"))
    conn = connection()
    try:
        execute(conn, "UPDATE calendar_events SET completed = %s WHERE id = %s AND user_id = %s", (completed, event_id, user_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.get("/api/reviews")
def reviews():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    conn = connection()
    try:
        rows = fetch_all(conn, "SELECT id, question_id, title, detail, completed FROM review_items WHERE user_id = %s ORDER BY completed, id DESC", (user_id,))
    finally:
        conn.close()
    return jsonify({"ok": True, "reviews": [{"id": r[0], "question_id": r[1], "title": r[2], "detail": r[3], "completed": bool(r[4])} for r in rows]})


@app.post("/api/reviews/<int:review_id>/complete")
def complete_review(review_id):
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    completed = bool((request.get_json(silent=True) or {}).get("completed"))
    conn = connection()
    try:
        execute(conn, "UPDATE review_items SET completed = %s WHERE id = %s AND user_id = %s", (completed, review_id, user_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.get("/api/simulado")
def general_mock_exam():
    if not logged_user_id():
        return jsonify({"message": "Faça login para continuar."}), 401
    conn = connection()
    try:
        rows = fetch_all(conn, """SELECT q.id, q.prompt, q.options_json, q.subject_id, s.name, s.question_weight, s.sort_order
            FROM questions q JOIN subjects s ON s.id = q.subject_id
            WHERE s.phase = %s ORDER BY s.sort_order, q.id""", ("1ª fase",))
    finally:
        conn.close()
    grouped = {}
    targets = {}
    names = {}
    for row in rows:
        grouped.setdefault(row[3], []).append(row)
        targets[row[3]] = row[5]
        names[row[3]] = row[4]
    selected = []
    distribution = []
    for subject_id, subject_rows in grouped.items():
        target = targets[subject_id]
        chosen = subject_rows[:target]
        selected.extend(chosen)
        distribution.append({"subject_id": subject_id, "subject": names[subject_id], "target": target, "selected": len(chosen), "available": len(subject_rows)})
    selected.sort(key=lambda row: (row[6], row[0]))
    return jsonify({"ok": True, "total": len(selected), "target_total": sum(item["target"] for item in distribution), "distribution": distribution, "questions": [{"id": r[0], "prompt": r[1], "options": json.loads(r[2]), "subject_id": r[3], "subject_name": r[4]} for r in selected]})


@app.post("/api/simulado/submit")
def submit_general_mock_exam():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    payload = request.get_json(silent=True) or {}
    raw_answers = payload.get("answers", {})
    question_ids = payload.get("question_ids", [])
    if not isinstance(raw_answers, dict) or not isinstance(question_ids, list) or not question_ids:
        return jsonify({"message": "Envie as respostas do simulado."}), 400
    try:
        ids = [int(item) for item in question_ids]
    except (TypeError, ValueError):
        return jsonify({"message": "Questões inválidas."}), 400
    placeholders = ",".join(["%s"] * len(ids))
    conn = connection()
    try:
        rows = fetch_all(conn, f"SELECT q.id, q.prompt, q.answer_index, q.explanation, q.subject_id, s.name FROM questions q JOIN subjects s ON s.id = q.subject_id WHERE q.id IN ({placeholders}) AND s.phase = %s", tuple(ids) + ("1ª fase",))
        by_id = {row[0]: row for row in rows}
        corrections = []
        score = 0
        for question_id in ids:
            row = by_id.get(question_id)
            if not row:
                continue
            selected = raw_answers.get(str(question_id))
            try:
                selected_int = int(selected) if selected is not None else None
            except (TypeError, ValueError):
                selected_int = None
            correct = selected_int == row[2]
            if correct:
                score += 1
            corrections.append({"id": row[0], "prompt": row[1], "selected": selected_int, "correct_answer": row[2], "correct": correct, "explanation": row[3], "subject_name": row[5]})
            if not correct:
                if is_postgres():
                    execute(conn, "INSERT INTO review_items (user_id, question_id, title, detail) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING", (user_id, row[0], f"Revisar questão de {row[5]}", row[3]))
                else:
                    execute(conn, "INSERT OR IGNORE INTO review_items (user_id, question_id, title, detail) VALUES (%s, %s, %s, %s)", (user_id, row[0], f"Revisar questão de {row[5]}", row[3]))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "score": score, "total": len(corrections), "corrections": corrections})


@app.get("/api/quiz")
def quiz():
    if not logged_user_id():
        return jsonify({"message": "Faça login para continuar."}), 401
    subject_id = request.args.get("subject", type=int)
    if not subject_id:
        lookup = connection()
        try:
            subject_id = fetch_one(lookup, "SELECT id FROM subjects WHERE name = %s", ("Ética e Estatuto da OAB",))[0]
        finally:
            lookup.close()
    conn = connection()
    try:
        rows = fetch_all(conn, "SELECT id, prompt, options_json FROM questions WHERE subject_id = %s ORDER BY id", (subject_id,))
    finally:
        conn.close()
    return jsonify({"ok": True, "subject_id": subject_id, "questions": [{"id": r[0], "prompt": r[1], "options": json.loads(r[2])} for r in rows]})


@app.post("/api/quiz/submit")
def submit_quiz():
    user_id = logged_user_id()
    if not user_id:
        return jsonify({"message": "Faça login para continuar."}), 401
    payload = request.get_json(silent=True) or {}
    subject_id = int(payload.get("subject_id", 0))
    raw_answers = payload.get("answers", {})
    if not subject_id or not isinstance(raw_answers, dict):
        return jsonify({"message": "Envie as respostas do bloco."}), 400
    conn = connection()
    try:
        rows = fetch_all(conn, "SELECT id, prompt, options_json, answer_index, explanation FROM questions WHERE subject_id = %s ORDER BY id", (subject_id,))
        if not rows:
            return jsonify({"message": "Este bloco ainda não possui questões."}), 404
        corrections = []
        score = 0
        for row in rows:
            selected = raw_answers.get(str(row[0]))
            try:
                selected_int = int(selected) if selected is not None else None
            except (TypeError, ValueError):
                selected_int = None
            correct = selected_int == row[3]
            if correct:
                score += 1
            corrections.append({"id": row[0], "prompt": row[1], "selected": selected_int, "correct_answer": row[3], "correct": correct, "explanation": row[4]})
            if not correct:
                if is_postgres():
                    execute(conn, "INSERT INTO review_items (user_id, question_id, title, detail) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING", (user_id, row[0], "Revisar questão de Ética", row[4]))
                else:
                    execute(conn, "INSERT OR IGNORE INTO review_items (user_id, question_id, title, detail) VALUES (%s, %s, %s, %s)", (user_id, row[0], "Revisar questão de Ética", row[4]))
        if is_postgres():
            with conn.cursor() as cur:
                cur.execute("INSERT INTO quiz_attempts (user_id, subject_id, score, total, answers_json) VALUES (%s, %s, %s, %s, %s)", (user_id, subject_id, score, len(rows), json.dumps(raw_answers)))
        else:
            conn.execute("INSERT INTO quiz_attempts (user_id, subject_id, score, total, answers_json) VALUES (?, ?, ?, ?, ?)", (user_id, subject_id, score, len(rows), json.dumps(raw_answers)))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "score": score, "total": len(rows), "corrections": corrections})


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


@app.get("/api/admin/conteudos")
@admin_required
def admin_contents():
    conn = connection()
    try:
        subjects_rows = fetch_all(conn, "SELECT id, name, phase, question_weight FROM subjects ORDER BY sort_order")
        lessons_rows = fetch_all(conn, "SELECT id, subject_id, title, summary, source_note FROM lessons ORDER BY subject_id, sort_order")
        questions_rows = fetch_all(conn, "SELECT id, subject_id, prompt, options_json, answer_index, explanation, source_note FROM questions ORDER BY subject_id, id")
    finally:
        conn.close()
    counts = {}
    for row in questions_rows:
        counts[row[1]] = counts.get(row[1], 0) + 1
    return jsonify({"ok": True, "subjects": [{"id": r[0], "name": r[1], "phase": r[2], "question_weight": r[3], "questions": counts.get(r[0], 0)} for r in subjects_rows], "lessons": [{"id": r[0], "subject_id": r[1], "title": r[2], "summary": r[3], "source_note": r[4]} for r in lessons_rows], "questions": [{"id": r[0], "subject_id": r[1], "prompt": r[2], "options": json.loads(r[3]), "answer_index": r[4], "explanation": r[5], "source_note": r[6]} for r in questions_rows]})


@app.post("/api/admin/lessons")
@admin_required
def admin_add_lesson():
    payload = request.get_json(silent=True) or {}
    subject_id = int(payload.get("subject_id", 0) or 0)
    title = str(payload.get("title", "")).strip()
    summary = str(payload.get("summary", "")).strip()
    source_note = str(payload.get("source_note", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.")).strip()
    if not subject_id or not title or not summary or len(title) > 180:
        return jsonify({"message": "Preencha disciplina, título e resumo."}), 400
    conn = connection()
    try:
        if is_postgres():
            execute(conn, "INSERT INTO lessons (subject_id, title, summary, source_note, sort_order) VALUES (%s, %s, %s, %s, 99) ON CONFLICT DO NOTHING", (subject_id, title, summary, source_note))
        else:
            execute(conn, "INSERT OR IGNORE INTO lessons (subject_id, title, summary, source_note, sort_order) VALUES (%s, %s, %s, %s, 99)", (subject_id, title, summary, source_note))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "message": "Aula adicionada."}), 201


@app.patch("/api/admin/lessons/<int:lesson_id>")
@admin_required
def admin_edit_lesson(lesson_id):
    payload = request.get_json(silent=True) or {}
    title = str(payload.get("title", "")).strip()
    summary = str(payload.get("summary", "")).strip()
    source_note = str(payload.get("source_note", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.")).strip()
    if not title or not summary:
        return jsonify({"message": "Informe título e resumo."}), 400
    conn = connection()
    try:
        execute(conn, "UPDATE lessons SET title = %s, summary = %s, source_note = %s WHERE id = %s", (title, summary, source_note, lesson_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "message": "Aula atualizada."})


@app.delete("/api/admin/lessons/<int:lesson_id>")
@admin_required
def admin_delete_lesson(lesson_id):
    conn = connection()
    try:
        execute(conn, "DELETE FROM lessons WHERE id = %s", (lesson_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "message": "Aula excluída."})


@app.patch("/api/admin/questions/<int:question_id>")
@admin_required
def admin_edit_question(question_id):
    payload = request.get_json(silent=True) or {}
    prompt = str(payload.get("prompt", "")).strip()
    options = payload.get("options", [])
    explanation = str(payload.get("explanation", "")).strip()
    try:
        answer_index = int(payload.get("answer_index"))
    except (TypeError, ValueError):
        return jsonify({"message": "Índice da alternativa inválido."}), 400
    if not prompt or not isinstance(options, list) or len(options) != 4 or answer_index not in range(4) or not explanation:
        return jsonify({"message": "Confira enunciado, quatro alternativas, resposta e explicação."}), 400
    conn = connection()
    try:
        execute(conn, "UPDATE questions SET prompt = %s, options_json = %s, answer_index = %s, explanation = %s WHERE id = %s", (prompt, json.dumps([str(item).strip() for item in options]), answer_index, explanation, question_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "message": "Questão atualizada."})


@app.delete("/api/admin/questions/<int:question_id>")
@admin_required
def admin_delete_question(question_id):
    conn = connection()
    try:
        execute(conn, "DELETE FROM questions WHERE id = %s", (question_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "message": "Questão excluída."})


@app.get("/api/admin/desempenho")
@admin_required
def admin_performance():
    conn = connection()
    try:
        rows = fetch_all(conn, """SELECT u.name, u.email, s.name, COUNT(a.id), COALESCE(SUM(a.score), 0), COALESCE(SUM(a.total), 0)
            FROM quiz_attempts a JOIN users u ON u.id = a.user_id JOIN subjects s ON s.id = a.subject_id
            GROUP BY u.name, u.email, s.name ORDER BY u.name, s.name""")
        discursive = fetch_all(conn, """SELECT u.name, u.email, s.name, COUNT(d.id), COALESCE(SUM(d.score), 0)
            FROM discursive_attempts d JOIN users u ON u.id = d.user_id JOIN subjects s ON s.id = d.subject_id
            GROUP BY u.name, u.email, s.name ORDER BY u.name, s.name""")
        phase2 = fetch_all(conn, """SELECT u.name, u.email, s.name, COUNT(m.id), COALESCE(SUM(m.score), 0), COALESCE(MAX(m.max_score), 50)
            FROM phase2_mock_attempts m JOIN users u ON u.id = m.user_id JOIN subjects s ON s.id = m.subject_id
            GROUP BY u.name, u.email, s.name ORDER BY u.name, s.name""")
    finally:
        conn.close()
    return jsonify({"ok": True, "objective": [{"name": r[0], "email": r[1], "subject": r[2], "attempts": r[3], "score": r[4], "total": r[5]} for r in rows], "discursive": [{"name": r[0], "email": r[1], "subject": r[2], "attempts": r[3], "score": r[4]} for r in discursive], "phase2": [{"name": r[0], "email": r[1], "subject": r[2], "attempts": r[3], "score": r[4], "max_score": r[5]} for r in phase2]})


@app.post("/api/admin/questions")
@admin_required
def admin_add_question():
    payload = request.get_json(silent=True) or {}
    subject_id = int(payload.get("subject_id", 0) or 0)
    prompt = str(payload.get("prompt", "")).strip()
    options = payload.get("options", [])
    answer_index = payload.get("answer_index")
    explanation = str(payload.get("explanation", "")).strip()
    source_note = str(payload.get("source_note", "Questão autoral OAB FÁCIL; confira a fonte oficial vigente.")).strip()
    if not subject_id or not prompt or not isinstance(options, list) or len(options) < 2 or not all(str(item).strip() for item in options):
        return jsonify({"message": "Informe a disciplina, enunciado e pelo menos duas alternativas."}), 400
    try:
        answer_index = int(answer_index)
    except (TypeError, ValueError):
        return jsonify({"message": "Informe o índice da alternativa correta."}), 400
    if answer_index < 0 or answer_index >= len(options) or not explanation:
        return jsonify({"message": "Confira a alternativa correta e a explicação."}), 400
    conn = connection()
    try:
        execute(conn, "INSERT INTO questions (subject_id, prompt, options_json, answer_index, explanation, source_note) VALUES (%s, %s, %s, %s, %s, %s)", (subject_id, prompt, json.dumps([str(item).strip() for item in options]), answer_index, explanation, source_note))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "message": "Questão adicionada."}), 201


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
