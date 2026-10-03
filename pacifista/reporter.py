# -*- coding: utf-8 -*-
"""
Pacifista - Report Generator (reporter.py)
Processa achados de segurança e gera relatórios interativos e planos de testes.
"""

import os
import json
from .vuln_db import VULNERABILITY_DATABASE

def generate_report_data(findings, total_files, scan_path):
    """
    Consolida os dados brutos da varredura, calcula métricas, scores de segurança
    e retorna um relatório em formato estruturado (dicionário).
    """
    # Contadores de severidade
    stats = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "total_issues": len(findings)
    }

    processed_findings = []
    
    for f in findings:
        check_id = f["check_id"]
        
        # Mapeamento com o banco de dados de vulnerabilidades
        db_info = VULNERABILITY_DATABASE.get(check_id)
        
        if db_info:
            severity = db_info["severity"]
            title = db_info["title"]
            description = db_info["description"]
            recommendation = db_info["recommendation"]
            how_to_test = db_info["how_to_test"]
        else:
            # Casos dinâmicos/customizados que não estão diretamente no banco principal
            if check_id == "high_complexity":
                severity = "LOW"
                title = "Complexidade Ciclomática Alta"
                description = f["extra_info"]
                recommendation = "Divida a função em subfunções menores e mais focadas (Single Responsibility Principle)."
                how_to_test = "1. Faça testes unitários cobrindo as diversas ramificações condicionais (if/else).\n2. Monitore a cobertura de código."
            elif check_id == "syntax_error":
                severity = "HIGH"
                title = "Erro de Sintaxe Python"
                description = f["extra_info"]
                recommendation = "Corrija a sintaxe de acordo com as especificações do interpretador Python."
                how_to_test = "1. Execute o arquivo diretamente com `python <nome_arquivo.py>` para checar erros de compilação."
            else:
                severity = "INFO"
                title = f"Alerta Geral ({check_id})"
                description = f["extra_info"]
                recommendation = "Revise o código para garantir a segurança."
                how_to_test = "1. Revise manualmente o comportamento esperado desta linha."

        stats[severity] += 1
        
        # Normalização do caminho do arquivo para facilitar exibição
        display_file = os.path.relpath(f["file"], scan_path) if os.path.isabs(f["file"]) else f["file"]
        display_file = display_file.replace("\\", "/")

        processed_findings.append({
            "file": display_file,
            "absolute_path": f["file"].replace("\\", "/"),
            "line": f["line"],
            "column": f["column"],
            "check_id": check_id,
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "how_to_test": how_to_test,
            "code_snippet": f["code_snippet"]
        })

    # Cálculo do Score de Segurança (Inicia em 100 e decresce proporcionalmente)
    # Pesos de desconto por criticidade
    deductions = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 7,
        "LOW": 3,
        "INFO": 0
    }
    
    score = 100
    for severity, count in stats.items():
        if severity in deductions:
            score -= (deductions[severity] * count)
            
    score = max(0, score) # O menor score possível é 0
    
    # Criar lista única de testes sugeridos (checklist consolidado)
    test_checklist = []
    seen_checks = set()
    for pf in processed_findings:
        cid = pf["check_id"]
        if cid not in seen_checks:
            seen_checks.add(cid)
            test_checklist.append({
                "category": pf["title"],
                "severity": pf["severity"],
                "steps": pf["how_to_test"]
            })

    return {
        "scan_path": scan_path.replace("\\", "/"),
        "total_files": total_files,
        "score": score,
        "stats": stats,
        "findings": processed_findings,
        "test_checklist": test_checklist
    }

def save_markdown_report(report_data, output_path):
    """
    Gera um belo arquivo Markdown contendo o relatório de segurança e testes.
    """
    md = []
    md.append(f"# Relatório de Auditoria Pacifista")
    md.append(f"**Diretório Analisado:** `{report_data['scan_path']}`")
    md.append(f"**Total de arquivos Python escaneados:** {report_data['total_files']}")
    md.append(f"")
    
    # Renderizar Score
    score = report_data['score']
    if score >= 85:
        badge = "🟢 SEGURO"
    elif score >= 60:
        badge = "🟡 ALERTA"
    else:
        badge = "🔴 VULNERÁVEL"
        
    md.append(f"## Status Geral: {badge} ({score}/100)")
    md.append(f"")
    md.append(f"| Criticidade | Quantidade |")
    md.append(f"| --- | --- |")
    md.append(f"| 🔥 Crítica | {report_data['stats']['CRITICAL']} |")
    md.append(f"| 🔴 Alta | {report_data['stats']['HIGH']} |")
    md.append(f"| 🟡 Média | {report_data['stats']['MEDIUM']} |")
    md.append(f"| 🔵 Baixa | {report_data['stats']['LOW']} |")
    md.append(f"")
    md.append(f"---")
    
    md.append(f"## 🚨 Vulnerabilidades Encontradas")
    if not report_data["findings"]:
        md.append("✅ Nenhum problema de segurança ou limpeza foi detectado. Parabéns!")
    else:
        for idx, f in enumerate(report_data["findings"], 1):
            severity_emoji = {"CRITICAL": "🔥 CRÍTICO", "HIGH": "🔴 ALTO", "MEDIUM": "🟡 MÉDIO", "LOW": "🔵 BAIXO", "INFO": "ℹ️ INFO"}
            emoji = severity_emoji.get(f["severity"], "ℹ️")
            
            md.append(f"### {idx}. {f['title']} [{emoji}]")
            md.append(f"- **Arquivo:** `{f['file']}` (Linha {f['line']}, Coluna {f['column']})")
            md.append(f"- **Descrição:** {f['description']}")
            md.append(f"- **Trecho Afetado:**")
            md.append(f"  ```python")
            md.append(f"  {f['code_snippet']}")
            md.append(f"  ```")
            md.append(f"- **Recomendação de Correção:**")
            md.append(f"  {f['recommendation']}")
            md.append(f"")
            
    md.append(f"---")
    md.append(f"## 🧪 Roteiro de Testes e Sondagem (Checklist)")
    md.append("Execute os testes abaixo no seu ambiente de desenvolvimento para comprovar e sanar potenciais riscos:")
    md.append("")
    
    if not report_data["test_checklist"]:
        md.append("Não há testes pendentes, pois o código não apresentou vulnerabilidades estruturais óbvias.")
    else:
        for t in report_data["test_checklist"]:
            md.append(f"### Teste para: {t['category']}")
            steps = t["steps"].split('\n')
            for step in steps:
                if step.strip():
                    md.append(f"- [ ] {step.strip().lstrip('1234567890. ')}")
            md.append("")

    # Escrever no arquivo
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write("\n".join(md))
        
    return output_path
