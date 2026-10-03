# -*- coding: utf-8 -*-
"""
Pacifista - Vulnerability Database (vuln_db.py)
Contém definições de vulnerabilidades comuns, recomendações de correção e métodos de teste (sonda).
"""

VULNERABILITY_DATABASE = {
    "hardcoded_secret": {
        "title": "Chave de API ou Credencial Exposta (Hardcoded Secrets)",
        "severity": "CRITICAL",
        "description": (
            "Detectamos o que parece ser uma chave de API, senha, token ou credencial "
            "definida diretamente no código-fonte. Credenciais hardcoded podem ser vazadas "
            "facilmente se o código for compartilhado ou enviado para sistemas de controle de versão (Git)."
        ),
        "recommendation": (
            "Utilize variáveis de ambiente ou gerenciadores de segredos (como Vault ou arquivos .env salvos fora do Git). "
            "Exemplo com python-dotenv:\n"
            "```python\n"
            "import os\n"
            "from dotenv import load_dotenv\n"
            "load_dotenv()\n"
            "api_key = os.getenv('API_KEY')\n"
            "```"
        ),
        "how_to_test": (
            "1. Verifique se o valor da credencial foi modificado para ler de variáveis de ambiente.\n"
            "2. Crie um caso de teste onde a variável de ambiente não esteja definida e verifique se a aplicação "
            "trata o erro de forma segura sem quebrar.\n"
            "3. Execute um scan de commits históricos com ferramentas como `gitleaks` para garantir que o segredo "
            "não permaneça no histórico do Git."
        )
    },
    "sql_injection": {
        "title": "Injeção de SQL Potencial (SQL Injection)",
        "severity": "HIGH",
        "description": (
            "Detecção de concatenação direta de strings ou formatação de strings em instruções SQL. "
            "Isso permite que um invasor manipule a estrutura da consulta SQL, podendo extrair, modificar "
            "ou apagar dados do banco de dados."
        ),
        "recommendation": (
            "Utilize sempre consultas parametrizadas (placeholders como `?`, `%s`, ou `:param` dependendo do driver). "
            "Nunca concatene variáveis diretamente na query SQL. Exemplo correto:\n"
            "```python\n"
            "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))\n"
            "```"
        ),
        "how_to_test": (
            "1. Insira caracteres especiais como `'` (aspa simples), `\"` (aspa dupla), `--` ou `OR '1'='1` nos inputs analisados.\n"
            "2. Se o sistema retornar um erro de sintaxe SQL exposto ou ignorar as restrições normais "
            "retornando todos os registros, a vulnerabilidade está ativa.\n"
            "3. Escreva testes de integração enviando payloads comuns do SQLmap (`' OR 1=1 --`) e verifique se "
            "são tratados como strings puras."
        )
    },
    "dangerous_eval": {
        "title": "Uso de Funções Inseguras (eval / exec)",
        "severity": "HIGH",
        "description": (
            "O uso de `eval()` ou `exec()` com dados que venham direta ou indiretamente do usuário é "
            "extremamente perigoso. Permite a execução arbitrária de código Python, levando ao "
            "comprometimento total do servidor (RCE - Remote Code Execution)."
        ),
        "recommendation": (
            "Substitua `eval()` por alternativas seguras como `ast.literal_eval()` para converter strings "
            "em tipos nativos do Python (dicionários, listas, tuplas), ou utilize parses estruturados de JSON."
        ),
        "how_to_test": (
            "1. Tente enviar payloads de teste para executar comandos simples como `__import__('os').system('whoami')` "
            "ou expressões matemáticas como `2 + 2` no input avaliado.\n"
            "2. Se o comando no payload for executado ou a expressão for avaliada, o sistema está vulnerável.\n"
            "3. Valide o comportamento criando testes de unidade passando inputs inválidos e strings de ataque, "
            "garantindo que uma exceção apropriada seja lançada."
        )
    },
    "command_injection": {
        "title": "Injeção de Comando de Sistema (OS Command Injection)",
        "severity": "HIGH",
        "description": (
            "Chamadas ao sistema operacional utilizando `os.system` ou `subprocess.Popen` com `shell=True` "
            "passando entradas dinâmicas sem higienização. Um invasor pode concatenar comandos de terminal "
            "(como `; rm -rf /` ou `& dir`) para executar ações no sistema hospedeiro."
        ),
        "recommendation": (
            "1. Sempre evite usar `shell=True` em chamadas de subprocessos.\n"
            "2. Passe os argumentos como uma lista ordenada. Exemplo correto:\n"
            "```python\n"
            "import subprocess\n"
            "subprocess.run(['ls', '-la', diretorio_usuario])\n"
            "```"
        ),
        "how_to_test": (
            "1. Injete terminadores de comando ou encadeadores nos parâmetros passados à função (ex: `; id`, `& whoami`, `| ping`).\n"
            "2. Verifique se o output do comando injetado é retornado ou se há atraso na resposta (Time-based command injection).\n"
            "3. Escreva testes automatizados garantindo que qualquer caractere especial de shell (`|`, `;`, `&`, `$`, `` ` ``) "
            "seja rejeitado na validação de entrada antes de chegar à execução."
        )
    },
    "insecure_deserialization": {
        "title": "Deserialização Insegura (pickle / yaml.load)",
        "severity": "HIGH",
        "description": (
            "A deserialização de arquivos/dados não confiáveis usando a biblioteca `pickle` ou `yaml.load` "
            "sem o SafeLoader pode levar à execução de código arbitrário durante o processo de reconstrução do objeto."
        ),
        "recommendation": (
            "1. Evite o uso de `pickle` para comunicação de dados de origem externa. Use formatos de serialização seguros e neutros "
            "como JSON.\n"
            "2. Se estiver utilizando PyYAML, use `yaml.safe_load()` em vez de `yaml.load()`."
        ),
        "how_to_test": (
            "1. Construa um payload serializado contendo a instrução para executar um comando simples (como tocar um ping) "
            "e envie ao endpoint de deserialização.\n"
            "2. Se a ação descrita no payload ocorrer, o sistema está vulnerável.\n"
            "3. Verifique se a aplicação aceita JSON comum e rejeita assinaturas binárias de pickle."
        )
    },
    "insecure_random": {
        "title": "Uso de Gerador de Números Pseudo-Aleatórios Inseguro",
        "severity": "MEDIUM",
        "description": (
            "O módulo padrão `random` do Python usa o algoritmo Mersenne Twister, que é previsível. "
            "Não deve ser usado para gerar tokens de segurança, senhas, chaves criptográficas ou hashes de redefinição de senha."
        ),
        "recommendation": (
            "Utilize o módulo `secrets` para qualquer geração de valores relacionados a criptografia ou segurança. Exemplo:\n"
            "```python\n"
            "import secrets\n"
            "token = secrets.token_hex(16)\n"
            "```"
        ),
        "how_to_test": (
            "1. Verifique se os tokens de sessão gerados pelo sistema são previsíveis coletando uma amostra sequencial de tokens.\n"
            "2. Use ferramentas de análise estatística de entropia para checar a aleatoriedade dos identificadores gerados."
        )
    },
    "weak_hashing": {
        "title": "Uso de Algoritmo de Hash Fraco (MD5 / SHA1)",
        "severity": "MEDIUM",
        "description": (
            "O uso de algoritmos de hash ultrapassados como MD5 ou SHA-1 para hashes de senhas ou assinaturas de integridade "
            "é desaconselhado devido a vulnerabilidades de colisão conhecidas e alta velocidade de quebra por força bruta."
        ),
        "recommendation": (
            "Use algoritmos modernos como SHA-256/SHA-512 do módulo `hashlib`, ou preferencialmente algoritmos de derivação "
            "de chaves lentos como `bcrypt` ou `argon2` para armazenar senhas."
        ),
        "how_to_test": (
            "1. Tente extrair ou interceptar o hash gerado pelo sistema e tente revertê-lo usando bancos de dados de "
            "rainbow tables públicos (como md5decrypt).\n"
            "2. Se o hash for decifrado instantaneamente, ele é fraco e inseguro."
        )
    },
    "except_pass": {
        "title": "Tratamento de Exceção Silencioso (except: pass)",
        "severity": "LOW",
        "description": (
            "Capturar exceções genéricas (`except Exception:` ou `except:`) seguido apenas por `pass` silencia "
            "erros e dificulta o rastreamento de falhas. Isso pode mascarar falhas lógicas críticas ou até bugs de segurança "
            "sem deixar vestígios em logs."
        ),
        "recommendation": (
            "Sempre capture exceções específicas e adicione logs apropriados para depuração. Se precisar mesmo ignorar, "
            "registre a ocorrência em um log de nível correspondente (ex: logger.warning)."
        ),
        "how_to_test": (
            "1. Force as condições de erro no trecho suspeito (ex: enviando tipos de dados errados, derrubando a rede ou banco).\n"
            "2. Monitore os logs da aplicação. Se o sistema falhar silenciosamente sem disparar alertas ou mensagens de erro, "
            "a captura silenciosa está ativa e prejudicando a resiliência do sistema."
        )
    }
}
