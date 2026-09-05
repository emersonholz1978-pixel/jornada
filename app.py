import csv
import io
import json
import os
import re
import sqlite3
import secrets
from datetime import date, datetime, timedelta, timezone
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
        lesson_rows += [
            (civil, "Pessoas e personalidade", "Revise capacidade, direitos da personalidade e proteção jurídica da pessoa.", "Material autoral OAB FÁCIL; confira o Código Civil vigente.", 1),
            (civil, "Obrigações e responsabilidade civil", "Organize obrigação, dano, nexo causal e as hipóteses gerais de responsabilização.", "Material autoral OAB FÁCIL; confira o Código Civil vigente.", 2),
            (civil, "Contratos e boa-fé", "Estude formação, interpretação e função da boa-fé objetiva nos contratos.", "Material autoral OAB FÁCIL; confira o Código Civil vigente.", 3),
            (civil, "Revisão por questões de Civil", "Faça questões e registre os conceitos que precisam de nova revisão.", "Material autoral OAB FÁCIL; confira a fonte oficial vigente.", 4),
            (constitutional, "Princípios fundamentais", "Revise fundamentos da República, objetivos fundamentais e princípios estruturantes.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 1),
            (constitutional, "Direitos e garantias fundamentais", "Organize direitos individuais, coletivos e instrumentos de proteção constitucional.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 2),
            (constitutional, "Organização dos Poderes", "Estude a separação funcional, controles e competências previstas na Constituição.", "Material autoral OAB FÁCIL; confira a Constituição vigente.", 3),
            (constitutional, "Controle de constitucionalidade", "Monte um quadro com noções de controle difuso, concentrado e efeitos das decisões.", "Material autoral OAB FÁCIL; confira a Constituição e a legislação vigente.", 4),
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
        question_groups = {ethics: question_rows, civil: civil_questions, constitutional: constitutional_questions}
        for subject_id, rows_to_seed in question_groups.items():
            existing_questions = fetch_one(conn, "SELECT COUNT(*) FROM questions WHERE subject_id = %s", (subject_id,))[0]
            if existing_questions == 0:
                if is_postgres():
                    with conn.cursor() as cur:
                        cur.executemany("INSERT INTO questions (subject_id, prompt, options_json, answer_index, explanation, source_note) VALUES (%s, %s, %s, %s, %s, %s)", rows_to_seed)
                else:
                    conn.executemany("INSERT INTO questions (subject_id, prompt, options_json, answer_index, explanation, source_note) VALUES (?, ?, ?, ?, ?, ?)", rows_to_seed)

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


@app.get("/api/subjects")
def subjects():
    if not logged_user_id():
        return jsonify({"message": "Faça login para continuar."}), 401
    conn = connection()
    try:
        rows = fetch_all(conn, "SELECT id, name, phase, question_weight FROM subjects ORDER BY sort_order")
    finally:
        conn.close()
    return jsonify({"ok": True, "subjects": [{"id": r[0], "name": r[1], "phase": r[2], "question_weight": r[3]} for r in rows]})


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
        questions_count = fetch_all(conn, "SELECT subject_id, COUNT(*) FROM questions GROUP BY subject_id")
    finally:
        conn.close()
    counts = {row[0]: row[1] for row in questions_count}
    return jsonify({"ok": True, "subjects": [{"id": r[0], "name": r[1], "phase": r[2], "question_weight": r[3], "questions": counts.get(r[0], 0)} for r in subjects_rows], "lessons": [{"id": r[0], "subject_id": r[1], "title": r[2], "summary": r[3], "source_note": r[4]} for r in lessons_rows]})


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
