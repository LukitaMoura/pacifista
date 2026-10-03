# -*- coding: utf-8 -*-
"""
Pacifista - Painel Web (web.py)
Servidor FastAPI local com o painel interativo de auditoria.
Carregado apenas quando o usuário pede --web, para que o modo CLI
funcione só com a biblioteca padrão.
"""

import os

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .analyzer import scan_directory
from .reporter import generate_report_data, save_markdown_report

app = FastAPI(title="Pacifista Code Auditor")

# Configurar diretórios locais para templates e arquivos estáticos
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
templates_dir = os.path.join(BASE_DIR, "templates")

# Criar pastas caso não existam
os.makedirs(static_dir, exist_ok=True)
os.makedirs(templates_dir, exist_ok=True)

# Montar arquivos estáticos e carregar templates
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)


@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """
    Entrega o painel web principal.
    """
    # Envia o caminho do workspace atual padrão
    default_scan_path = os.path.dirname(BASE_DIR).replace("\\", "/")
    return templates.TemplateResponse(
        "index.html", 
        {"request": request, "default_path": default_scan_path}
    )


@app.post("/api/scan")
async def api_scan(payload: dict):
    """
    API para iniciar a varredura em um diretório e retornar os dados estruturados do relatório.
    """
    path = payload.get("path")
    if not path:
        raise HTTPException(status_code=400, detail="Caminho do diretório é obrigatório.")
        
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="O diretório fornecido não existe no sistema.")
        
    try:
        findings, total_files = scan_directory(path)
        report_data = generate_report_data(findings, total_files, path)
        return JSONResponse(content=report_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro interno durante varredura: {str(e)}")


@app.post("/api/export-markdown")
async def api_export_markdown(payload: dict):
    """
    Gera e salva o relatório Markdown no diretório analisado.
    """
    report_data = payload.get("report_data")
    if not report_data:
        raise HTTPException(status_code=400, detail="Dados do relatório são obrigatórios para exportação.")
        
    scan_path = report_data.get("scan_path")
    output_filename = "pacifista_report.md"
    output_path = os.path.join(scan_path, output_filename)
    
    try:
        save_markdown_report(report_data, output_path)
        return JSONResponse(content={"status": "success", "file_path": output_path.replace("\\", "/")})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao salvar arquivo Markdown: {str(e)}")
