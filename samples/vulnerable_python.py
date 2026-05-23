"""Sample vulnerable Python code for testing"""
import os
import subprocess
import hashlib
import sqlite3

# CWE-798: Hardcoded credentials
DB_PASSWORD = "admin123"
SECRET_KEY = "my-secret-key-2024"

def authenticate(username):
    """Insecure authentication function"""
    # CWE-20: User input without validation
    password = input("Enter password: ")
    
    # CWE-89: SQL Injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    
    # CWE-327: Weak cryptographic algorithm
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    return cursor.fetchone()

def run_system_command(user_cmd):
    """Dangerous command execution"""
    # CWE-78: OS Command Injection
    cmd = input("Enter command: ")
    result = os.system(cmd)          # taint: input -> system
    subprocess.run(cmd, shell=True)  # another sink
    return result

def read_file(filename):
    """Path traversal vulnerability"""
    # CWE-22: Path Traversal
    user_path = input("File path: ")
    f = open(user_path)              # taint: input -> open (no context manager)
    return f.read()

def process_data():
    # CWE-95: Code injection via eval
    expr = input("Enter expression: ")
    result = eval(expr)             # extremely dangerous
    
    # Dead code after return... but let's add dead assignment
    unused_var = 42 * 100           # CWE-563: never used
    
    return result

class WeakSecurity:
    def __init__(self, data=[], config={}):   # CWE-1188: mutable default args
        self.data = data
        self.config = config
    
    def process(self):
        try:
            risky_operation = eval(self.data[0])
        except:                               # CWE-390: bare except
            pass                              # silently swallows all errors
    
    def infinite_check(self):
        while True:                           # CWE-835: potential infinite loop
            status = input("Continue? ")
            if status == "no":
                break
