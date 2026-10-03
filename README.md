# 🕊️ Pacifista — Auditor de Segurança para Código Python

Ferramenta de análise estática que varre projetos Python, aponta falhas de segurança classificadas por gravidade, atribui uma **nota de saúde (0–100)** ao código e exporta um relatório em Markdown. Roda pela **linha de comando** (sem dependências) ou por um **painel web** local em FastAPI.

Criei o Pacifista para revisar os sistemas internos que desenvolvo antes de cada publicação em produção.

## O que ele detecta

| Regra | Gravidade | Como detecta |
|---|---|---|
| Credenciais hardcoded (`password = "..."`, `api_key = "..."`) | 🔴 Crítica | Regex linha a linha (funciona até em arquivo com erro de sintaxe) |
| SQL Injection (`execute(f"... {x}")`, `+`, `%`, `.format`) | 🟠 Alta | AST, inclusive resolvendo variáveis locais da função |
| Injeção de comando (`os.system`, `subprocess(..., shell=True)`) | 🟠 Alta | AST |
| `eval()` / `exec()` | 🟠 Alta | AST |
| Deserialização insegura (`pickle.load`, `yaml.load` sem `SafeLoader`) | 🟠 Alta | AST |
| `random` usado para gerar token/senha | 🟡 Média | AST + contexto do nome da função |
| Hash fraco (`hashlib.md5`, `sha1`, `hashlib.new("md5")`) | 🟡 Média | AST |
| `except: pass` silencioso | 🟢 Baixa | AST |
| Complexidade ciclomática > 6 | 🟢 Baixa | AST |

Cada achado vem com **descrição, recomendação de correção com exemplo de código e roteiro de como testar** a vulnerabilidade.

## Como usar

```bash
# Modo CLI — só biblioteca padrão, nada para instalar
python -m pacifista --scan caminho/do/projeto
python -m pacifista --scan caminho/do/projeto --export-md   # gera pacifista_report.md

# Painel web
pip install -r requirements.txt
python -m pacifista --web --port 8000   # http://127.0.0.1:8000
```

## Testes

```bash
python -m unittest discover -s tests -v
```

`tests/mock_vulnerable.py` é um arquivo propositalmente vulnerável que exercita todas as regras. Os testes também cobrem um arquivo limpo (zero falsos positivos) e um arquivo com erro de sintaxe.

## Arquitetura

```
pacifista/
├── analyzer.py   # NodeVisitor do AST + regex de segredos
├── vuln_db.py    # base de regras: título, gravidade, correção e como testar
├── reporter.py   # agrega achados, calcula a nota e gera o Markdown
├── cli.py        # argparse; carrega o painel web só quando pedido
├── web.py        # FastAPI + Jinja2 (painel interativo)
├── templates/
└── static/
```

**Decisões de projeto**
- **AST em vez de regex** para as regras de código: evita falsos positivos em comentários e strings, e permite olhar o contexto (nome da função, variáveis locais).
- **Modo CLI sem dependências**, para rodar em qualquer máquina, inclusive em pipeline de CI.
- O painel escuta apenas em `127.0.0.1`: ele lê caminhos do disco local e não deve ser exposto na rede.

## Stack

Python 3.10+ · `ast` · FastAPI · Jinja2 · unittest
