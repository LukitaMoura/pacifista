# -*- coding: utf-8 -*-
"""
Mock target file containing intentional vulnerabilities to test Pacifista's scanner.
"""
import os
import subprocess
import pickle
import yaml
import random
import hashlib

# 1. Hardcoded Secret
API_KEY = "AIzaSyD-9x_SampleSecretKeyForTesting123"

def query_user(user_id):
    # 2. SQL Injection
    query = "SELECT * FROM users WHERE id = " + user_id
    # Simula chamada execute
    db_cursor = None
    db_cursor.execute(query)

def execute_command(user_input):
    # 3. Command Injection
    os.system("echo " + user_input)
    
    # 4. Command Injection via subprocess with shell=True
    subprocess.Popen("ping -c 1 " + user_input, shell=True)

def process_unsafe_eval(user_code):
    # 5. Dangerous eval
    return eval(user_code)

def load_payload(data):
    # 6. Insecure Deserialization via pickle
    return pickle.loads(data)

def load_config(yaml_string):
    # 7. Insecure YAML loading
    return yaml.load(yaml_string)

def generate_user_token():
    # 8. Insecure Randomness in security context
    return str(random.randint(100000, 999999))

def hash_user_password(password):
    # 9. Weak hashing algorithm (MD5)
    return hashlib.md5(password.encode()).hexdigest()

def do_risky_operation():
    try:
        # Alguma operação que falha
        x = 1 / 0
    except Exception:
        # 10. Except-pass silencioso
        pass

def very_complex_function(a, b, c, d, e, f):
    # 11. Complexidade ciclomática alta (muitos ifs/condições)
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        if f > 0:
                            return 1
                        else:
                            return 2
                    else:
                        return 3
                else:
                    return 4
            else:
                return 5
        else:
            return 6
    else:
        return 7
