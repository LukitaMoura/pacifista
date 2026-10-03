# -*- coding: utf-8 -*-
"""
Pacifista - CLI (cli.py)
Executa a varredura pela linha de comando ou sobe o painel web local (--web).
"""

import sys
import os
import argparse

from .analyzer import scan_directory
from .reporter import generate_report_data, save_markdown_report


def run_cli_mode(scan_path, export_md):
    """
    Executa a auditoria em modo CLI direto no terminal.
    """
    if not os.path.exists(scan_path):
        print(f"Erro: O caminho '{scan_path}' não existe.")
        sys.exit(1)
        
    print(f"[*] Pacifista: Iniciando varredura em '{scan_path}'...")
    findings, total_files = scan_directory(scan_path)
    report_data = generate_report_data(findings, total_files, scan_path)
    
    print(f"\n=================== RESULTADOS DA VARREDURA ===================")
    print(f"Arquivos analisados: {total_files}")
    print(f"Pontuação Geral de Saúde: {report_data['score']}/100")
    print(f"Falhas Detectadas: {len(findings)}")
    print(f"---------------------------------------------------------------")
    print(f"  - Crítica: {report_data['stats']['CRITICAL']}")
    print(f"  - Alta:    {report_data['stats']['HIGH']}")
    print(f"  - Média:   {report_data['stats']['MEDIUM']}")
    print(f"  - Baixa:   {report_data['stats']['LOW']}")
    print(f"===============================================================")
    
    if findings:
        print("\nDetalhamento das falhas encontradas:")
        for idx, f in enumerate(report_data["findings"], 1):
            print(f"\n{idx}. [{f['severity']}] {f['title']}")
            print(f"   Arquivo: {f['file']} (Linha {f['line']})")
            print(f"   Trecho:  {f['code_snippet']}")
            print(f"   Solução: {f['recommendation'].split('```')[0].strip()}")
            
    if export_md:
        output_file = os.path.join(scan_path, "pacifista_report.md")
        save_markdown_report(report_data, output_file)
        print(f"\n[+] Relatório Markdown gerado e salvo em: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Pacifista - Auditor de Código e Segurança Python")
    parser.add_argument("--scan", type=str, help="Caminho do diretório que deseja analisar")
    parser.add_argument("--export-md", action="store_true", help="Gera um arquivo Markdown pacifista_report.md na pasta analisada")
    parser.add_argument("--web", action="store_true", help="Inicia o painel Web Interativo no localhost")
    parser.add_argument("--port", type=int, default=8000, help="Porta para rodar o painel Web (Padrão: 8000)")
    
    args = parser.parse_args()
    
    # Se o argumento --scan for passado, roda o modo de linha de comando direto
    if args.scan:
        run_cli_mode(args.scan, args.export_md)
    # Caso contrário, ou se pedir --web explicitamente, roda o FastAPI
    else:
        print(f"[*] Pacifista: Iniciando painel de auditoria Web em http://127.0.0.1:{args.port}...")
        import uvicorn
        from .web import app
        uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
