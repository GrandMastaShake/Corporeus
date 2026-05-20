# Corporeus

**AST-based static security scanner for Python.** Detects 8 CWE vulnerability classes before deployment — no runtime execution, zero external dependencies, CI/CD ready.

[![Tests](https://img.shields.io/badge/tests-54%20passing-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

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

## Ecosystem

| Repo | Role |
|------|------|
| [EmberArmor](https://github.com/GrandMastaShake/EmberArmor) | Runtime enforcement layer |
| [EmberHoneypot](https://github.com/GrandMastaShake/EmberHoneypot) | AI deception + threat intelligence |
| [Corporeus](https://github.com/GrandMastaShake/Corporeus) | Static AST vulnerability scanner (this repo) |
| [EmberBench](https://github.com/GrandMastaShake/EmberBench) | Adversarial evaluation harness |

---

## License

MIT — see [LICENSE](LICENSE)
