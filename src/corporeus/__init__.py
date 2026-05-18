"""Corporeus — AST Security Scanner.

A focused static analysis scanner that detects 8 common vulnerability classes
in Python source code via AST parsing:

  CWE-79  XSS, CWE-89  SQLi, CWE-22  Path Traversal, CWE-78  OS Command,
  CWE-94  Code Injection, CWE-200 Info Exposure, CWE-269 Improper Auth,
  CWE-352 CSRF.

Usage:
    from corporeus import scan, scan_file, scan_source
    findings = scan_source("import os\n os.system(user_input)")
    for f in findings:
        print(f"Line {f.line}: {f.cwe_id} — {f.title}")
"""

from corporeus.scanner import (
    Finding,
    scan,
    scan_directory,
    scan_file,
    scan_source,
)

__all__ = ["Finding", "scan", "scan_source", "scan_file", "scan_directory"]
