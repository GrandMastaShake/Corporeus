# Corporeus

AST-based security scanner for Python. Detects 8 CWE vulnerability classes via static analysis — no runtime execution, zero dependencies.

## CWE Coverage

| CWE | Class | Severity |
|-----|-------|----------|
| CWE-89 | SQL Injection | Critical |
| CWE-79 | Cross-Site Scripting | High |
| CWE-22 | Path Traversal | High |
| CWE-78 | OS Command Injection | Critical |
| CWE-94 | Code Injection | Critical |
| CWE-200 | Information Exposure | Medium |
| CWE-269 | Improper Privilege Management | High |
| CWE-352 | Cross-Site Request Forgery | Medium |

## Install

```bash
pip install corporeus
```

## Usage

```bash
# CLI
ember-scan path/to/code/

# Python API
from corporeus.scanner import scan_file, scan_source

findings = scan_file("app.py")
for f in findings:
    print(f"Line {f.line}: CWE-{f.cwe_id} {f.title} [{f.severity}]")
```

## Features

- Pure Python stdlib — zero runtime dependencies
- 1-level taint tracking
- False-positive filtering and deduplication
- Confidence scores per finding
- Remediation guidance per CWE class

## Tests

```bash
pip install pytest
pytest tests/ -v
```

54 tests, 0 failing.

## License

MIT
