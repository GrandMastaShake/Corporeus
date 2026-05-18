"""Comprehensive tests for the Corporeus AST Scanner.

Covers all 8 CWE classes:
  CWE-79 XSS, CWE-89 SQLi, CWE-22 Path Traversal, CWE-78 OS Command,
  CWE-94 Code Injection, CWE-200 Info Exposure, CWE-269 Improper Auth,
  CWE-352 CSRF.

Edge cases: empty files, syntax errors, safe code, multiple CWEs.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from corporeus.scanner import scan_file, scan_source, scan_directory, Finding


# ═══════════════════════════════════════════════════════════════════════════
# CWE-79 XSS
# ═══════════════════════════════════════════════════════════════════════════


class TestCWE79_XSS:
    def test_mark_safe_with_user_input(self):
        code = """\
from django.utils.safestring import mark_safe

def render_comment(comment):
    return mark_safe(comment)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-79"]
        assert len(f) >= 1
        assert any("XSS" in x.title for x in f)

    def test_render_template_string_with_user_input(self):
        code = """\
from flask import render_template_string

def show(name):
    return render_template_string("<div>{{ name }}</div>", name=name)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-79"]
        assert len(f) >= 1

    def test_safe_code_no_xss(self):
        code = """\
from html import escape

def render_safe(text):
    return escape(text)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-79"]
        assert len(f) == 0

    def test_xss_line_numbers(self):
        code = "from django.utils.safestring import mark_safe\n\ndef render(c):\n    return mark_safe(c)\n"
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-79"]
        assert f
        assert f[0].line == 4


# ═══════════════════════════════════════════════════════════════════════════
# CWE-89 SQL Injection
# ═══════════════════════════════════════════════════════════════════════════


class TestCWE89_SQLInjection:
    def test_fstring_in_execute(self):
        code = """\
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchone()
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-89"]
        assert len(f) >= 1
        assert any("String Interpolation" in x.title for x in f)

    def test_string_concatenation_sql(self):
        code = """\
import sqlite3

def search_users(query):
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    sql = "SELECT * FROM users WHERE name = '" + query + "'"
    cur.execute(sql)
    return cur.fetchall()
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-89"]
        assert len(f) >= 1
        assert any("Concatenation" in x.title for x in f)

    def test_safe_parameterized_query(self):
        code = """\
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-89"]
        assert len(f) == 0

    def test_format_string_sql(self):
        code = """\
def find(name):
    sql = "SELECT * FROM users WHERE name = {}".format(name)
    db.execute(sql)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-89"]
        assert len(f) >= 1

    def test_tainted_variable_sql(self):
        code = """\
def query(user_id):
    q = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(q)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-89"]
        assert len(f) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# CWE-22 Path Traversal
# ═══════════════════════════════════════════════════════════════════════════


class TestCWE22_PathTraversal:
    def test_open_user_input(self):
        code = """\
def read_file(filename):
    with open(filename) as f:
        return f.read()
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-22"]
        assert len(f) >= 1
        assert any("File Path" in x.title for x in f)

    def test_os_path_join_user_input(self):
        code = """\
import os

def get_path(base, user_file):
    return os.path.join(base, user_file)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-22"]
        assert len(f) >= 1
        assert any("Path Construction" in x.title for x in f)

    def test_safe_open_literal(self):
        code = """\
def read_config():
    with open("config.json") as f:
        return f.read()
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-22"]
        assert len(f) == 0

    def test_safe_os_path_join_literals(self):
        code = """\
import os

def get_path():
    return os.path.join("/safe", "path", "file.txt")
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-22"]
        assert len(f) == 0


# ═══════════════════════════════════════════════════════════════════════════
# CWE-78 OS Command Injection
# ═══════════════════════════════════════════════════════════════════════════


class TestCWE78_OSCommand:
    def test_os_system_user_input(self):
        code = """\
import os

def ping(host):
    os.system("ping -c 1 " + host)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-78"]
        assert len(f) >= 1
        assert any("os.system" in x.title for x in f)

    def test_os_popen_user_input(self):
        code = """\
import os

def list_dir(path):
    return os.popen("ls " + path).read()
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-78"]
        assert len(f) >= 1
        assert any("os.popen" in x.title for x in f)

    def test_subprocess_shell_true(self):
        code = """\
import subprocess

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-78"]
        assert len(f) >= 1
        assert any("shell=True" in x.title for x in f)

    def test_safe_subprocess_list(self):
        code = """\
import subprocess

def safe_ls():
    return subprocess.run(["ls", "/home"], shell=False)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-78"]
        # Should not find because shell=False and constant list
        assert len(f) == 0

    def test_os_system_literal(self):
        code = """\
import os

def hello():
    os.system("echo hello")
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-78"]
        # Literal string is safe
        assert len(f) == 0


# ═══════════════════════════════════════════════════════════════════════════
# CWE-94 Code Injection
# ═══════════════════════════════════════════════════════════════════════════


class TestCWE94_CodeInjection:
    def test_eval_user_input(self):
        code = """\
def calculate(expr):
    return eval(expr)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-94"]
        assert len(f) >= 1
        assert any("eval" in x.title for x in f)

    def test_exec_user_input(self):
        code = """\
def run_code(code):
    exec(code)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-94"]
        assert len(f) >= 1
        assert any("exec" in x.title for x in f)

    def test_pickle_loads(self):
        code = """\
import pickle

def load_data(data):
    return pickle.loads(data)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-94"]
        assert len(f) >= 1
        assert any("pickle" in x.title for x in f)

    def test_unsafe_yaml_load(self):
        code = """\
import yaml

def load_config(stream):
    return yaml.load(stream)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-94"]
        assert len(f) >= 1
        assert any("yaml" in x.title for x in f)

    def test_safe_yaml_safe_load(self):
        code = """\
import yaml

def load_config(stream):
    return yaml.safe_load(stream)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-94"]
        # safe_load is safe
        assert len(f) == 0

    def test_safe_yaml_load_with_safe_loader(self):
        code = """\
import yaml
from yaml import SafeLoader

def load_config(stream):
    return yaml.load(stream, Loader=SafeLoader)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-94"]
        assert len(f) == 0

    def test_marshal_loads(self):
        code = """\
import marshal

def load_data(data):
    return marshal.loads(data)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-94"]
        assert len(f) >= 1
        assert any("marshal" in x.title for x in f)

    def test_safe_literal_eval(self):
        code = """\
from ast import literal_eval

def parse(data):
    return literal_eval(data)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-94"]
        assert len(f) == 0


# ═══════════════════════════════════════════════════════════════════════════
# CWE-200 Info Exposure (Secrets + Debug)
# ═══════════════════════════════════════════════════════════════════════════


class TestCWE200_InfoExposure:
    def test_hardcoded_password(self):
        code = """\
DB_PASSWORD = "super_secret_password_123"
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-200" and "password" in x.title.lower()]
        assert len(f) >= 1

    def test_hardcoded_api_key(self):
        code = """\
API_KEY = "sk-1234567890abcdef"
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-200" and "api" in x.title.lower()]
        assert len(f) >= 1

    def test_hardcoded_secret(self):
        code = """\
CLIENT_SECRET = "my_secret_value_here"
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-200"]
        assert len(f) >= 1

    def test_debug_mode_enabled(self):
        code = """\
DEBUG = True
FLASK_DEBUG = True
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-200" and "debug" in x.title.lower()]
        assert len(f) >= 1

    def test_no_false_positive_on_test_secret(self):
        code = """\
TEST_PASSWORD = "test"
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-200" and "password" in x.title.lower()]
        # "test" triggers false-positive filter
        assert len(f) == 0

    def test_safe_env_var(self):
        code = """\
import os

DB_PASSWORD = os.environ.get("DB_PASSWORD")
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-200" and "password" in x.title.lower()]
        assert len(f) == 0

    def test_hardcoded_token(self):
        code = """\
ACCESS_TOKEN = "ghp_1234567890abcdef1234567890abcdef123456"
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-200" and "token" in x.title.lower()]
        assert len(f) >= 1

    def test_secret_line_numbers(self):
        code = "\n\nAPI_KEY = 'secret_value_here'\n"
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-200"]
        assert f
        assert f[0].line == 3


# ═══════════════════════════════════════════════════════════════════════════
# CWE-269 Improper Auth
# ═══════════════════════════════════════════════════════════════════════════


class TestCWE269_ImproperAuth:
    def test_auth_bypass_variable(self):
        code = """\
SKIP_AUTH = True
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-269"]
        assert len(f) >= 1
        assert any("Auth" in x.title for x in f)

    def test_disable_auth(self):
        code = """\
disable_auth = True
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-269"]
        assert len(f) >= 1

    def test_no_auth_flag(self):
        code = """\
no_auth = True
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-269"]
        assert len(f) >= 1

    def test_safe_normal_variable(self):
        code = """\
authenticated = True
user_logged_in = True
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-269"]
        assert len(f) == 0


# ═══════════════════════════════════════════════════════════════════════════
# CWE-352 CSRF
# ═══════════════════════════════════════════════════════════════════════════


class TestCWE352_CSRF:
    def test_csrf_exempt_decorator(self):
        code = """\
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def my_view(request):
    return "hello"
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-352"]
        assert len(f) >= 1

    def test_csrf_exempt_call(self):
        code = """\
from django.views.decorators.csrf import csrf_exempt

csrf_exempt(my_view)
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-352"]
        assert len(f) >= 1

    def test_safe_view_without_exempt(self):
        code = """\
def safe_view(request):
    return "hello"
"""
        findings = scan_source(code)
        f = [x for x in findings if x.cwe_id == "CWE-352"]
        assert len(f) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_empty_source(self):
        assert scan_source("") == []

    def test_whitespace_only(self):
        assert scan_source("   \n   \n") == []

    def test_syntax_error(self):
        code = "def broken(\n"
        assert scan_source(code) == []

    def test_multiple_cwes_in_one_file(self):
        code = """\
import os
import sqlite3

DB_PASSWORD = "secret123"

def handler(user_id, filename, cmd):
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    os.system(cmd)
    with open(filename) as f:
        return f.read()
"""
        findings = scan_source(code)
        cwes = set(f.cwe_id for f in findings)
        assert "CWE-89" in cwes
        assert "CWE-78" in cwes
        assert "CWE-22" in cwes
        assert "CWE-200" in cwes

    def test_scan_file_not_found(self):
        assert scan_file("/nonexistent/file.py") == []

    def test_scan_file_wrong_extension(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("import os\nos.system('ls')\n")
            path = f.name
        try:
            assert scan_file(path) == []
        finally:
            os.unlink(path)

    def test_scan_file_valid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import os\nos.system(user_cmd)\n")
            path = f.name
        try:
            findings = scan_file(path)
            assert len(findings) >= 1
            assert findings[0].cwe_id == "CWE-78"
            assert findings[0].file_path == path
        finally:
            os.unlink(path)

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "vuln.py"), "w") as f:
                f.write("import os\nos.system(cmd)\n")
            with open(os.path.join(tmpdir, "safe.py"), "w") as f:
                f.write("print('hello')\n")
            findings = scan_directory(tmpdir)
            assert len(findings) >= 1
            assert all(f.file_path for f in findings)

    def test_finding_dataclass(self):
        f = Finding(
            cwe_id="CWE-78",
            title="Test",
            description="desc",
            severity="high",
            line=1,
            line_end=1,
            source="src",
            confidence=0.9,
            remediation="fix",
        )
        assert f.cwe_id == "CWE-78"
        assert f.line == 1

    def test_severity_sorting_critical_first(self):
        code = """\
import os

def handler(user_input):
    os.system(user_input)
    eval(user_input)
"""
        findings = scan_source(code)
        severities = [f.severity for f in findings]
        assert severities[0] == "critical"

    def test_source_field_populated(self):
        code = "import os\nos.system(cmd)\n"
        findings = scan_source(code)
        assert findings
        assert "os.system" in findings[0].source

    def test_metadata_field(self):
        f = Finding(cwe_id="CWE-78", title="T", description="D",
                    severity="high", line=1, line_end=1,
                    source="s", confidence=0.9, remediation="r",
                    metadata={"extra": "data"})
        assert f.metadata == {"extra": "data"}

    def test_no_duplicates(self):
        code = """\
import os

def f1(): os.system(a)
def f2(): os.system(b)
"""
        findings = scan_source(code)
        os_findings = [f for f in findings if f.cwe_id == "CWE-78" and "os.system" in f.title]
        # Two different lines should produce two different findings
        assert len(os_findings) == 2
        assert os_findings[0].line != os_findings[1].line
