# -*- coding: utf-8 -*-
"""
Pacifista - Unit Tests (test_analyzer.py)
"""

import os
import tempfile
import unittest

from pacifista.analyzer import analyze_file

class TestPacifistaAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.mock_file = os.path.join(self.test_dir, "mock_vulnerable.py")

    def test_vulnerabilities_detection(self):
        findings = analyze_file(self.mock_file)
        
        # Mapeamento dos check_ids que devem ser encontrados
        found_ids = [f["check_id"] for f in findings]
        
        # Testar se os principais problemas foram identificados
        self.assertIn("hardcoded_secret", found_ids, "Deveria detectar chaves hardcoded.")
        self.assertIn("sql_injection", found_ids, "Deveria detectar injeção de SQL.")
        self.assertIn("command_injection", found_ids, "Deveria detectar injeção de comando de terminal.")
        self.assertIn("dangerous_eval", found_ids, "Deveria detectar uso de eval().")
        self.assertIn("insecure_deserialization", found_ids, "Deveria detectar deserialização insegura.")
        self.assertIn("insecure_random", found_ids, "Deveria detectar uso de random em escopo de token/senha.")
        self.assertIn("except_pass", found_ids, "Deveria detectar except: pass vazio.")
        self.assertIn("high_complexity", found_ids, "Deveria detectar funções com alta complexidade ciclomática.")
        self.assertIn("weak_hashing", found_ids, "Deveria detectar hash fraco (md5/sha1).")

    def test_syntax_error_still_scans_secrets(self):
        code = 'def f(:\n    pass\npassword = "supersecret123"\n'
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
            tmp.write(code)
        try:
            found_ids = [f["check_id"] for f in analyze_file(tmp.name)]
        finally:
            os.remove(tmp.name)
        self.assertIn("syntax_error", found_ids)
        self.assertIn("hardcoded_secret", found_ids)

    def test_clean_file_has_no_findings(self):
        code = (
            "import os\n"
            "import secrets\n\n"
            "def gerar_token():\n"
            "    return secrets.token_hex(16)\n\n"
            "API_KEY = os.getenv('API_KEY')\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
            tmp.write(code)
        try:
            self.assertEqual(analyze_file(tmp.name), [])
        finally:
            os.remove(tmp.name)

if __name__ == "__main__":
    unittest.main()
