# -*- coding: utf-8 -*-
"""
Pacifista - Core Analyzer (analyzer.py)
Analisa arquivos Python utilizando Abstract Syntax Trees (AST) e expressões regulares.
"""

import ast
import re
import os

# Padrão Regex para buscar chaves hardcoded no código: atribuições de strings
# suspeitas de serem tokens, senhas ou chaves. Fica no módulo para que a
# análise por regex funcione mesmo quando o AST falha (erro de sintaxe).
SECRET_KEY_PATTERN = re.compile(
    r'(api[-_]?key|secret|password|passwd|token|jwt_secret|private[-_]?key|aws[-_]?secret)\s*=\s*[\'"][a-zA-Z0-9_\-\.\:\/\=\+\@]{8,128}[\'"]',
    re.IGNORECASE
)


class PacifistaASTAnalyzer(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []
        self.current_function = None
        self.local_assignments = {}

    def add_finding(self, check_id, line, column, extra_info=None, code_snippet=None):
        self.findings.append({
            "file": self.filename,
            "check_id": check_id,
            "line": line,
            "column": column,
            "extra_info": extra_info or "",
            "code_snippet": code_snippet or ""
        })

    def visit_FunctionDef(self, node):
        # Medição de complexidade ciclomática básica (número de caminhos independentes)
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.And, ast.Or, ast.ExceptHandler)):
                complexity += 1
        
        if complexity > 6:
            # Pega a linha inicial da função
            code_line = f"def {node.name}(...)"
            self.add_finding(
                "high_complexity",
                node.lineno,
                node.col_offset,
                f"A função '{node.name}' é muito complexa (Complexidade Ciclomática: {complexity}). Considere dividi-la.",
                code_line
            )
        
        # Mapear variáveis locais dentro da função para detectar fluxos inseguros (ex: SQLi)
        self.local_assignments = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        self.local_assignments[target.id] = child.value

        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = None
        self.local_assignments = {}

    def visit_Call(self, node):
        # 1. Detecção de eval/exec
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                self.add_finding("dangerous_eval", node.lineno, node.col_offset, f"Chamada direta da função perigosa '{node.func.id}()'.")

        # 2. Detecção de subprocess e os.system (Injeção de Comando)
        # Ex: os.system("...")
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "os" and node.func.attr == "system":
                    self.add_finding("command_injection", node.lineno, node.col_offset, "Uso de 'os.system'. Considere subprocess.run sem shell=True.")
                
                # Ex: subprocess.Popen(..., shell=True) ou subprocess.run(..., shell=True)
                if node.func.value.id == "subprocess" and node.func.attr in ("Popen", "run", "call", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self.add_finding(
                                "command_injection",
                                node.lineno,
                                node.col_offset,
                                f"Uso de 'subprocess.{node.func.attr}' com shell=True ativo. Altamente vulnerável."
                            )

            # 3. Detecção de serialização insegura pickle.loads/yaml.load
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "pickle" and node.func.attr in ("loads", "load"):
                    self.add_finding(
                        "insecure_deserialization",
                        node.lineno,
                        node.col_offset,
                        "Deserialização com o módulo 'pickle' detectada. Prefira JSON."
                    )
                if node.func.value.id == "yaml" and node.func.attr == "load":
                    # Checar se usa safeLoader
                    has_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader":
                            if isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader":
                                has_safe_loader = True
                    if not has_safe_loader:
                        self.add_finding(
                            "insecure_deserialization",
                            node.lineno,
                            node.col_offset,
                            "Chamada do YAML.load sem SafeLoader ativo."
                        )

        # 3b. Detecção de hash fraco: hashlib.md5(...), hashlib.sha1(...), hashlib.new("md5")
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
            weak = None
            if node.func.attr in ("md5", "sha1"):
                weak = node.func.attr
            elif node.func.attr == "new" and node.args and isinstance(node.args[0], ast.Constant) \
                    and str(node.args[0].value).lower() in ("md5", "sha1"):
                weak = str(node.args[0].value).lower()
            if weak:
                self.add_finding(
                    "weak_hashing",
                    node.lineno,
                    node.col_offset,
                    f"Uso de hash fraco '{weak}'. Para senhas, prefira bcrypt/argon2; para integridade, SHA-256."
                )

        # 4. Detecção de SQL Injection nos executores de bancos comuns
        # Ex: cursor.execute(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            # Checar se o primeiro argumento posicional tem concatenação ou formatação
            if node.args:
                arg = node.args[0]
                
                # Resolver a variável de forma simples se ela foi definida no escopo local da função
                if isinstance(arg, ast.Name) and hasattr(self, 'local_assignments') and arg.id in self.local_assignments:
                    arg = self.local_assignments[arg.id]
                
                is_unsafe = False
                
                # Concatenação: sql = "select * from table where id = " + user_id
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    is_unsafe = True
                # Formatação f-string: f"select * from table where id = {user_id}"
                elif isinstance(arg, ast.JoinedStr):
                    is_unsafe = True
                # Formatação antiga: "select * from table where id = %s" % user_id
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                    is_unsafe = True
                # Formatação por método: "select * ...".format(user_id)
                elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                    is_unsafe = True
                
                if is_unsafe:
                    self.add_finding(
                        "sql_injection",
                        node.lineno,
                        node.col_offset,
                        "Execução de consulta SQL contendo concatenação direta ou formatação dinâmica de strings."
                    )

        # 5. Detecção de geradores inseguros de números/strings
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "random":
                if node.func.attr in ("randint", "choice", "random", "randrange", "uniform"):
                    # Alerta para o uso em senhas/tokens se estiver em contextos suspeitos de chaves
                    if self.current_function and any(kw in self.current_function.lower() for kw in ("token", "senha", "password", "key", "auth", "secret")):
                        self.add_finding(
                            "insecure_random",
                            node.lineno,
                            node.col_offset,
                            f"Uso do módulo 'random' para geração na função '{self.current_function}'. Prefira o módulo 'secrets'."
                        )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        # Detecção de except: pass
        if len(node.body) == 1:
            item = node.body[0]
            if isinstance(item, ast.Pass):
                self.add_finding(
                    "except_pass",
                    node.lineno,
                    node.col_offset,
                    "Tratamento de exceção silencioso (except: pass) detectado."
                )
        self.generic_visit(node)


def analyze_file(filepath):
    """
    Analisa um arquivo Python específico buscando falhas usando AST e análises regex de linha.
    """
    findings = []
    
    # 1. Ler conteúdo do arquivo
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.splitlines()
    except Exception as e:
        return [{"file": filepath, "check_id": "read_error", "line": 0, "column": 0, "extra_info": str(e), "code_snippet": ""}]

    # 2. Executar análise via AST
    try:
        tree = ast.parse(content, filename=filepath)
        analyzer = PacifistaASTAnalyzer(filepath)
        analyzer.visit(tree)
        findings.extend(analyzer.findings)
    except SyntaxError as se:
        findings.append({
            "file": filepath,
            "check_id": "syntax_error",
            "line": se.lineno or 0,
            "column": se.offset or 0,
            "extra_info": f"Erro de sintaxe Python: {se.msg}",
            "code_snippet": lines[se.lineno - 1] if se.lineno and se.lineno <= len(lines) else ""
        })

    # 3. Análise baseada em Regex linha a linha (Complemento)
    for idx, line in enumerate(lines, 1):
        # Ignorar comentários da análise de secrets
        clean_line = line.split('#')[0].strip()
        
        # Testar Regex de Secrets
        secret_match = SECRET_KEY_PATTERN.search(clean_line)
        if secret_match:
            # Evitar adicionar duplicados se o AST já pegou algo parecido na mesma linha
            if not any(f["line"] == idx and f["check_id"] == "hardcoded_secret" for f in findings):
                # Oculta parte do segredo por segurança no relatório
                parts = clean_line.split('=')
                var_name = parts[0].strip()
                hidden_snippet = f"{var_name} = '********'"
                
                findings.append({
                    "file": filepath,
                    "check_id": "hardcoded_secret",
                    "line": idx,
                    "column": len(parts[0]) + 1,
                    "extra_info": f"Segredo exposto na atribuição da variável '{var_name}'.",
                    "code_snippet": hidden_snippet
                })

    # Adicionar trecho de código nos achados se estiver faltando
    for f in findings:
        if not f["code_snippet"] and 0 < f["line"] <= len(lines):
            f["code_snippet"] = lines[f["line"] - 1].strip()

    return findings


def scan_directory(directory_path):
    """
    Varre recursivamente o diretório atrás de arquivos .py e analisa cada um.
    """
    all_findings = []
    total_files = 0
    
    for root, _, files in os.walk(directory_path):
        # Pular diretórios virtuais e caches comuns
        if any(part in root for part in ('.git', '.venv', 'venv', '__pycache__', 'node_modules', '.gemini', '.claude')):
            continue
            
        for file in files:
            if file.endswith('.py'):
                total_files += 1
                full_path = os.path.join(root, file)
                file_findings = analyze_file(full_path)
                all_findings.extend(file_findings)
                
    return all_findings, total_files
