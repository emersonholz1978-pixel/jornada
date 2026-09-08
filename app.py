        # Expansao complementar: trilhas de aprofundamento, aplicacao e revisao para cada disciplina.
        comprehensive_lesson_rows = []
        for subject_id, subject_name, phase in subject_catalog:
            if phase == "1ª fase":
                extra = [
                    ("Fundamentos e conceitos-chave", f"Leia os conceitos estruturantes de {subject_name}, diferencie termos parecidos e escreva uma definicao propria para cada um.", "Material autoral OAB FACIL; confira a fonte oficial vigente.", 8),
                    ("Legislacao aplicada ao caso", f"Conecte os temas de {subject_name} aos dispositivos legais correspondentes, destacando requisitos, excecoes e consequencias.", "Material autoral OAB FACIL; confira a redacao oficial vigente.", 9),
                    ("Casos praticos e tomada de decisao", f"Resolva situacoes-problema de {subject_name}: identifique a questao juridica, a regra, a excecao e a conclusao fundamentada.", "Material autoral OAB FACIL; estudo orientado por casos.", 10),
                    ("Revisao espacada e caderno de erros", f"Revise {subject_name} em 24 horas, 7 dias e 30 dias, registrando causa, fundamento e correcao de cada erro.", "Material autoral OAB FACIL; confira edital e fontes oficiais.", 11),
                ]
            elif phase == "2ª fase":
                extra = [
                    ("Leitura estrategica do enunciado", f"Treine a leitura de enunciados de {subject_name}: destaque fatos, pedido, prazo, competencia, tese e dispositivo aplicavel.", "Material autoral OAB FACIL; confira o edital vigente.", 7),
                    ("Modelo de resposta fundamentada", f"Escreva respostas de {subject_name} com tese, fundamento legal, aplicacao aos fatos e conclusao.", "Material autoral OAB FACIL; confira a legislacao vigente.", 8),
                    ("Simulado orientado e espelho", f"Faca um treino completo de {subject_name} em cinco horas e compare sua peca e respostas com um checklist de pontuacao.", "Material autoral OAB FACIL; confira os padroes oficiais.", 9),
                ]
            else:
                extra = []
            comprehensive_lesson_rows.extend((subject_id, title, summary, source_note, sort_order) for title, summary, source_note, sort_order in extra)
        if is_postgres():
            with conn.cursor() as cur:
                cur.executemany("INSERT INTO lessons (subject_id, title, summary, source_note, sort_order) VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING", comprehensive_lesson_rows)
        else:
            conn.executemany("INSERT OR IGNORE INTO lessons (subject_id, title, summary, source_note, sort_order) VALUES (?, ?, ?, ?, ?)", comprehensive_lesson_rows)

        question_rows = [
