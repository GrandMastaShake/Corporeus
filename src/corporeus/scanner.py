"""Corporeus AST Scanner — focused CWE detection via static analysis.

A single-file scanner that parses Python source and detects 8 CWE classes:
  CWE-79  XSS, CWE-89  SQLi, CWE-22  Path Traversal, CWE-78  OS Command,
  CWE-94  Code Injection, CWE-200 Info Exposure, CWE-269 Improper Auth,
  CWE-352 CSRF.

Usage:
    from corporeus.scanner import scan_file, scan_source
    findings = scan_file("app.py")
    for f in findings:
        print(f"Line {f.line}: CWE-{f.cwe_id} {f.title}")
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set


# ── Data model ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single vulnerability finding."""

    cwe_id: str
    title: str
    description: str
    severity: str
    line: int
    line_end: int
    source: str
    confidence: float
    remediation: str
    file_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ── Severity ordering ───────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Utility helpers ─────────────────────────────────────────────────────


def _line_range(node: ast.AST) -> tuple[int, int]:
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", start)
    return start, end or start


def _node_source(node: ast.AST, lines: list[str]) -> str:
    start, end = _line_range(node)
    return "".join(lines[start - 1 : end]).strip()


def _full_name(func: ast.expr) -> str:
    parts: list[str] = []
    cur: ast.expr = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value  # type: ignore[assignment]
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _is_user_controlled(node: ast.AST) -> bool:
    """Heuristic — is this value user-controlled?"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return False
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.JoinedStr)):
        return True
    if isinstance(node, ast.BinOp):
        return True
    if isinstance(node, ast.Tuple):
        return any(_is_user_controlled(e) for e in node.elts)
    return False


# ── Analyzer: CWE-89 SQL Injection ──────────────────────────────────────

_SQL_KEYWORDS: Set[str] = {
    "select", "insert", "update", "delete", "drop", "create",
    "alter", "where", "from", "join", "union", "exec",
}
_SQL_METHODS = {"execute", "executemany", "executescript", "raw"}


class _TaintTracker:
    """1-level taint tracking for indirect flow detection."""

    def __init__(self) -> None:
        self.tainted: Set[str] = set()

    def scan(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    if _is_tainted_expr(node.value):
                        self.tainted.add(tgt.id)

    def is_tainted(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in self.tainted


def _is_tainted_expr(node: ast.expr | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _has_variables(node)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    return False


def _has_variables(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, (ast.Name, ast.Attribute, ast.Subscript, ast.FormattedValue)):
            return True
    return False


def _contains_sql(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            lowered = child.value.lower()
            if any(kw in lowered for kw in _SQL_KEYWORDS):
                return True
    return False


# ── Analyzer: CWE-79 XSS ────────────────────────────────────────────────

_XSS_FUNCS = {"mark_safe", "render_template_string", "render_string"}


# ── Analyzer: CWE-22 Path Traversal ─────────────────────────────────────

_FILE_FUNCS = {"open", "file"}


# ── Analyzer: CWE-78 OS Command ─────────────────────────────────────────

_OS_DANGEROUS = {"system", "popen", "popen2", "popen3", "popen4"}
_SUBPROC_METHODS = {"call", "run", "Popen", "check_output", "check_call"}


# ── Analyzer: CWE-94 Code Injection ─────────────────────────────────────

_EVAL_EXEC = {"eval", "exec", "compile"}
_PICKLE_DANGEROUS = {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"}
_MARSHAL_DANGEROUS = {"marshal.loads", "marshal.load"}
_YAML_DANGEROUS = {"yaml.load", "yaml.unsafe_load"}


# ── Analyzer: CWE-200 Info Exposure (Secrets) ───────────────────────────

_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r"password\s*=\s*[\"'][^\"']{4,}[\"']", "Hardcoded Password", "high"),
    (r"passwd\s*=\s*[\"'][^\"']{4,}[\"']", "Hardcoded Password", "high"),
    (r"api_key\s*=\s*[\"'][^\"']{8,}[\"']", "Hardcoded API Key", "medium"),
    (r"apikey\s*=\s*[\"'][^\"']{8,}[\"']", "Hardcoded API Key", "medium"),
    (r"secret\s*=\s*[\"'][^\"']{8,}[\"']", "Hardcoded Secret", "high"),
    (r"token\s*=\s*[\"'][^\"']{8,}[\"']", "Hardcoded Token", "medium"),
    (r"auth_token\s*=\s*[\"'][^\"']{8,}[\"']", "Hardcoded Auth Token", "high"),
    (r"access_token\s*=\s*[\"'][^\"']{8,}[\"']", "Hardcoded Access Token", "high"),
    (r"client_secret\s*=\s*[\"'][^\"']{8,}[\"']", "Hardcoded Client Secret", "critical"),
    (r"private_key\s*=\s*[\"'][^\"']{8,}[\"']", "Hardcoded Private Key", "critical"),
]

_FP_PATTERNS = [
    r"^.*(example|sample|dummy|test|placeholder|your_|changeme|TODO|FIXME).*$",
    r"^\*{3,}$",
]


# ── Analyzer: CWE-269 Improper Auth ─────────────────────────────────────

_AUTH_BYPASS_FUNCS = {"login", "authenticate", "verify"}
_AUTH_WEAKNESS_SIGNS = {
    "allow_any", "skip_auth", "no_auth", "disable_auth",
    "trust_all", "permit_all", "open_access",
}


# ── Analyzer: CWE-352 CSRF ─────────────────────────────────────────────_

_CSRF_EXEMPT_DECORATORS = {"csrf_exempt", "exempt"}


def _is_false_positive(value: str) -> bool:
    for pat in _FP_PATTERNS:
        if re.search(pat, value, re.IGNORECASE):
            return True
    return False


def _has_user_input(node: ast.AST) -> bool:
    """Check if node references user input."""
    user_vars = {"user", "username", "comment", "message", "content",
                 "input", "data", "text", "query", "name", "email",
                 "url", "path", "host", "cmd", "code", "expr", "value",
                 "payload", "request", "response"}
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            if child.id.lower() in user_vars:
                return True
            if child.id not in {"True", "False", "None", "self", "cls"}:
                if not child.id.startswith("_"):
                    return True
        if isinstance(child, (ast.Attribute, ast.Subscript)):
            return True
    return False


# ── Core scanning ───────────────────────────────────────────────────────


def _scan_ast(file_path: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    tt = _TaintTracker()
    tt.scan(tree)

    for node in ast.walk(tree):
        # ═══════════════════════════════════════════════════════════════
        # CWE-89 SQL Injection
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            func_name = _full_name(node.func)
            if node.func and (
                (isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_METHODS)
                or (isinstance(node.func, ast.Name) and node.func.id in _SQL_METHODS)
            ):
                for arg in node.args:
                    if _is_tainted_sql(arg) or tt.is_tainted(arg):
                        start, end = _line_range(node)
                        findings.append(
                            Finding(
                                cwe_id="CWE-89",
                                title="SQL Injection via String Interpolation",
                                description="User input interpolated into an SQL query.",
                                severity="high",
                                line=start,
                                line_end=end,
                                source=_node_source(node, lines),
                                confidence=0.9,
                                remediation="Use parameterized queries.",
                                file_path=file_path,
                            )
                        )

        # ═══════════════════════════════════════════════════════════════
        # CWE-89 SQL Injection — string concatenation with SQL keywords
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                if _contains_sql(node) and _has_variables(node):
                    start, end = _line_range(node)
                    findings.append(
                        Finding(
                            cwe_id="CWE-89",
                            title="SQL Injection via String Concatenation",
                            description="SQL query built via string concatenation.",
                            severity="high",
                            line=start,
                            line_end=end,
                            source=_node_source(node, lines),
                            confidence=0.85,
                            remediation="Use parameterized queries instead.",
                            file_path=file_path,
                        )
                    )

        # ═══════════════════════════════════════════════════════════════
        # CWE-79 XSS
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            func_name = _full_name(node.func)
            if func_name in _XSS_FUNCS or (
                isinstance(node.func, ast.Name) and node.func.id in _XSS_FUNCS
            ):
                has_ui = any(_has_user_input(a) for a in node.args)
                has_ui = has_ui or any(_has_user_input(k.value) for k in node.keywords)
                if has_ui:
                    start, end = _line_range(node)
                    findings.append(
                        Finding(
                            cwe_id="CWE-79",
                            title="Cross-Site Scripting (XSS) via Unescaped Output",
                            description="User input rendered without HTML escaping.",
                            severity="high",
                            line=start,
                            line_end=end,
                            source=_node_source(node, lines),
                            confidence=0.85,
                            remediation="Use html.escape() or Jinja2 auto-escaping.",
                            file_path=file_path,
                        )
                    )

        # ═══════════════════════════════════════════════════════════════
        # CWE-79 XSS — HTML Response with user input
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"Response", "make_response"}:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if "<" in arg.value and "html" in arg.value.lower():
                            start, end = _line_range(node)
                            findings.append(
                                Finding(
                                    cwe_id="CWE-79",
                                    title="Potential XSS in HTML Response",
                                    description="HTML response may contain unescaped user input.",
                                    severity="medium",
                                    line=start,
                                    line_end=end,
                                    source=_node_source(node, lines),
                                    confidence=0.7,
                                    remediation="Escape user input with html.escape().",
                                    file_path=file_path,
                                )
                            )

        # ═══════════════════════════════════════════════════════════════
        # CWE-22 Path Traversal
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            func_name = _full_name(node.func)
            # open(user_input)
            if isinstance(node.func, ast.Name) and node.func.id in _FILE_FUNCS:
                if node.args and _is_user_controlled(node.args[0]):
                    start, end = _line_range(node)
                    findings.append(
                        Finding(
                            cwe_id="CWE-22",
                            title="Path Traversal via Unsanitized File Path",
                            description="User input used as a file path without validation.",
                            severity="high",
                            line=start,
                            line_end=end,
                            source=_node_source(node, lines),
                            confidence=0.85,
                            remediation="Validate paths with os.path.commonpath().",
                            file_path=file_path,
                        )
                    )
            # os.path.join with user input
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                for arg in node.args:
                    if _is_user_controlled(arg):
                        start, end = _line_range(node)
                        findings.append(
                            Finding(
                                cwe_id="CWE-22",
                                title="Potential Path Traversal in Path Construction",
                                description="User input used in path construction without sanitization.",
                                severity="medium",
                                line=start,
                                line_end=end,
                                source=_node_source(node, lines),
                                confidence=0.75,
                                remediation="Sanitize the resulting path before use.",
                                file_path=file_path,
                            )
                        )
                        break

        # ═══════════════════════════════════════════════════════════════
        # CWE-78 OS Command Injection
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            func_name = _full_name(node.func)
            # os.system, os.popen etc
            if isinstance(node.func, ast.Attribute) and node.func.attr in _OS_DANGEROUS:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    if any(_is_user_controlled(a) for a in node.args):
                        start, end = _line_range(node)
                        findings.append(
                            Finding(
                                cwe_id="CWE-78",
                                title="Command Injection via os.system()/os.popen()",
                                description="User input passed to os.system()/os.popen().",
                                severity="critical",
                                line=start,
                                line_end=end,
                                source=_node_source(node, lines),
                                confidence=0.9,
                                remediation="Use subprocess.run() with a list of arguments.",
                                file_path=file_path,
                            )
                        )
            # subprocess.* with shell=True
            if isinstance(node.func, ast.Attribute) and node.func.attr in _SUBPROC_METHODS:
                for kw in node.keywords:
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            start, end = _line_range(node)
                            findings.append(
                                Finding(
                                    cwe_id="CWE-78",
                                    title="Command Injection via subprocess with shell=True",
                                    description="subprocess called with shell=True.",
                                    severity="high",
                                    line=start,
                                    line_end=end,
                                    source=_node_source(node, lines),
                                    confidence=0.85,
                                    remediation="Set shell=False, pass command as list.",
                                    file_path=file_path,
                                )
                            )
            # subprocess with user input
            if isinstance(node.func, ast.Attribute) and node.func.attr in _SUBPROC_METHODS:
                if any(_is_user_controlled(a) for a in node.args):
                    start, end = _line_range(node)
                    findings.append(
                        Finding(
                            cwe_id="CWE-78",
                            title="Potential Command Injection in subprocess",
                            description="User input may be passed to subprocess.",
                            severity="high",
                            line=start,
                            line_end=end,
                            source=_node_source(node, lines),
                            confidence=0.8,
                            remediation="Use subprocess with a list of arguments.",
                            file_path=file_path,
                        )
                    )

        # ═══════════════════════════════════════════════════════════════
        # CWE-94 Code Injection — eval/exec/compile
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _EVAL_EXEC:
                if node.args and not isinstance(node.args[0], ast.Constant):
                    start, end = _line_range(node)
                    findings.append(
                        Finding(
                            cwe_id="CWE-94",
                            title="Code Injection via eval()/exec()",
                            description="eval()/exec() with user-controlled input.",
                            severity="critical",
                            line=start,
                            line_end=end,
                            source=_node_source(node, lines),
                            confidence=0.95,
                            remediation="Use ast.literal_eval() for safe evaluation.",
                            file_path=file_path,
                        )
                    )

        # ═══════════════════════════════════════════════════════════════
        # CWE-94 Code Injection — pickle
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            func_name = _full_name(node.func)
            if func_name in _PICKLE_DANGEROUS:
                start, end = _line_range(node)
                findings.append(
                    Finding(
                        cwe_id="CWE-94",
                        title="Code Injection via pickle deserialization",
                        description="pickle.loads() can execute arbitrary code.",
                        severity="critical",
                        line=start,
                        line_end=end,
                        source=_node_source(node, lines),
                        confidence=0.95,
                        remediation="Use json.loads() for safe deserialization.",
                        file_path=file_path,
                    )
                )

        # ═══════════════════════════════════════════════════════════════
        # CWE-94 Code Injection — yaml.load without SafeLoader
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            func_name = _full_name(node.func)
            if func_name in _YAML_DANGEROUS:
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        if isinstance(kw.value, ast.Attribute) and kw.value.attr in {"SafeLoader", "FullLoader"}:
                            has_safe_loader = True
                        elif isinstance(kw.value, ast.Name) and kw.value.id == "SafeLoader":
                            has_safe_loader = True
                if not has_safe_loader:
                    start, end = _line_range(node)
                    findings.append(
                        Finding(
                            cwe_id="CWE-94",
                            title="Code Injection via yaml.load()",
                            description="yaml.load() without SafeLoader can execute arbitrary code.",
                            severity="critical",
                            line=start,
                            line_end=end,
                            source=_node_source(node, lines),
                            confidence=0.9,
                            remediation="Use yaml.safe_load() instead.",
                            file_path=file_path,
                        )
                    )

        # ═══════════════════════════════════════════════════════════════
        # CWE-94 Code Injection — marshal
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            func_name = _full_name(node.func)
            if func_name in _MARSHAL_DANGEROUS:
                start, end = _line_range(node)
                findings.append(
                    Finding(
                        cwe_id="CWE-94",
                        title="Code Injection via marshal.loads()",
                        description="marshal.loads() is not safe for untrusted data.",
                        severity="high",
                        line=start,
                        line_end=end,
                        source=_node_source(node, lines),
                        confidence=0.8,
                        remediation="Use json for safe serialization.",
                        file_path=file_path,
                    )
                )

        # ═══════════════════════════════════════════════════════════════
        # CWE-200 Info Exposure — debug mode / sensitive data
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    name_lower = tgt.id.lower()
                    # Debug mode enabled
                    if name_lower in {"debug", "flask_debug", "django_debug"}:
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            start, end = _line_range(node)
                            findings.append(
                                Finding(
                                    cwe_id="CWE-200",
                                    title="Debug Mode Enabled",
                                    description="Debug mode enabled — leaks stack traces and sensitive info.",
                                    severity="medium",
                                    line=start,
                                    line_end=end,
                                    source=_node_source(node, lines),
                                    confidence=0.8,
                                    remediation="Set DEBUG = False in production.",
                                    file_path=file_path,
                                )
                            )

        # ═══════════════════════════════════════════════════════════════
        # CWE-200 Info Exposure — hardcoded secrets
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    name_lower = tgt.id.lower()
                    secret_keywords = {"password", "secret", "token", "api_key", "apikey",
                                       "private_key", "client_secret", "auth"}
                    if any(kw in name_lower for kw in secret_keywords):
                        if isinstance(node.value, ast.Constant) and node.value.value:
                            val = str(node.value.value)
                            if len(val) >= 4 and not _is_false_positive(val):
                                start, end = _line_range(node)
                                findings.append(
                                    Finding(
                                        cwe_id="CWE-200",
                                        title=f"Hardcoded Secret: {tgt.id}",
                                        description=f"Variable '{tgt.id}' contains a hardcoded secret.",
                                        severity="high",
                                        line=start,
                                        line_end=end,
                                        source=_node_source(node, lines),
                                        confidence=0.85,
                                        remediation=f"Use os.environ.get('{tgt.id.upper()}').",
                                        file_path=file_path,
                                    )
                                )

        # ═══════════════════════════════════════════════════════════════
        # CWE-269 Improper Auth — weak authentication
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    name_lower = tgt.id.lower()
                    if name_lower in _AUTH_WEAKNESS_SIGNS or "skip_auth" in name_lower:
                        start, end = _line_range(node)
                        findings.append(
                            Finding(
                                cwe_id="CWE-269",
                                title="Improper Authentication: Auth Bypass Configured",
                                description="Authentication check appears to be disabled or bypassed.",
                                severity="critical",
                                line=start,
                                line_end=end,
                                source=_node_source(node, lines),
                                confidence=0.85,
                                remediation="Remove authentication bypass in production.",
                                file_path=file_path,
                            )
                        )

        # ═══════════════════════════════════════════════════════════════
        # CWE-352 CSRF — @csrf_exempt or missing CSRF protection
        # ═══════════════════════════════════════════════════════════════
        if isinstance(node, ast.Call):
            func_name = _full_name(node.func)
            if func_name in {"csrf_exempt", "exempt_csrf"} or (
                isinstance(node.func, ast.Name) and node.func.id == "csrf_exempt"
            ):
                start, end = _line_range(node)
                findings.append(
                    Finding(
                        cwe_id="CWE-352",
                        title="CSRF Protection Disabled via csrf_exempt",
                        description="CSRF protection explicitly disabled for a route/handler.",
                        severity="medium",
                        line=start,
                        line_end=end,
                        source=_node_source(node, lines),
                        confidence=0.75,
                        remediation="Only exempt CSRF for verified safe endpoints (e.g., API with token auth).",
                        file_path=file_path,
                    )
                )

        # Function definitions with CSRF exempt decorators
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            dec_names = set()
            for dec in node.decorator_list:
                if isinstance(dec, (ast.Name, ast.Attribute)):
                    dec_names.add(_full_name(dec))
            if _CSRF_EXEMPT_DECORATORS & dec_names or "csrf_exempt" in dec_names:
                start, end = _line_range(node)
                findings.append(
                    Finding(
                        cwe_id="CWE-352",
                        title="CSRF Protection Disabled via Decorator",
                        description=f"Function '{node.name}' exempted from CSRF protection.",
                        severity="medium",
                        line=start,
                        line_end=end,
                        source=_node_source(node, lines),
                        confidence=0.75,
                        remediation="Only exempt CSRF for verified safe endpoints.",
                        file_path=file_path,
                    )
                )

    # ═══════════════════════════════════════════════════════════════
    # CWE-200 Info Exposure — regex-based secret detection on raw lines
    # ═══════════════════════════════════════════════════════════════
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith('"""'):
            continue
        for pat, title, sev in _SECRET_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                match = re.search(r"=\s*[\"']([^\"']+)[\"']", line)
                val = match.group(1) if match else ""
                if val and not _is_false_positive(val):
                    findings.append(
                        Finding(
                            cwe_id="CWE-200",
                            title=f"{title} in Source Code",
                            description=f"A {title.lower()} was found hardcoded.",
                            severity=sev,
                            line=lineno,
                            line_end=lineno,
                            source=line.strip(),
                            confidence=0.9,
                            remediation="Load secrets from environment variables.",
                            file_path=file_path,
                        )
                    )

    # Deduplicate by (cwe_id, line, source)
    seen: set[tuple[str, int, str]] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f.cwe_id, f.line, f.source[:80])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity descending then confidence descending
    deduped.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 99), -f.confidence))
    return deduped


def _is_tainted_sql(node: ast.AST) -> bool:
    """Check if node contains tainted SQL."""
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                return True
        return False
    if isinstance(node, ast.BinOp):
        return _contains_sql(node) and _has_variables(node)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return _contains_sql(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _contains_sql(node.left)
    return False


# ═════════════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════════════


def scan_source(source: str, file_path: str = "<string>") -> list[Finding]:
    """Scan Python source code for vulnerabilities.

    Args:
        source: Python source code as a string.
        file_path: Logical path for reporting.

    Returns:
        List of Findings sorted by severity (critical first).
    """
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []
    lines = source.splitlines(keepends=True)
    return _scan_ast(file_path, tree, lines)


def scan_file(file_path: str) -> list[Finding]:
    """Scan a single Python file for vulnerabilities.

    Args:
        file_path: Path to the ``.py`` file.

    Returns:
        List of Findings sorted by severity (critical first).
    """
    path = Path(file_path)
    if not path.is_file():
        return []
    if path.suffix != ".py":
        return []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError:
        return []

    return scan_source(source, file_path)


def scan_directory(directory: str) -> list[Finding]:
    """Recursively scan a directory for Python files.

    Args:
        directory: Path to the directory.

    Returns:
        List of Findings from all ``.py`` files.
    """
    findings: list[Finding] = []
    for py_file in Path(directory).rglob("*.py"):
        findings.extend(scan_file(str(py_file)))
    return findings


# ── Convenience alias ───────────────────────────────────────────────────

scan = scan_source
