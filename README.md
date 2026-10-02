# Corporeus

A small Python library that parses Python source with `ast` and reports lines that match a fixed list of risky-looking patterns.

## Status

Learning prototype. Not ready for use as a security control. Last updated 2026-10-02.

For real projects use [Bandit](https://github.com/PyCQA/bandit), [Ruff's `S` rules](https://docs.astral.sh/ruff/rules/) or [Semgrep](https://semgrep.dev/). They resolve import aliases and ship a command line, machine-readable output and suppression comments. Corporeus has none of those.

## What works today

The commands and examples on this page were run on Python 3.12 on Windows. `pyproject.toml` declares Python 3.9 or newer; older versions were not run.

- The scanner is one file, `src/corporeus/scanner.py`, and uses only the standard library.
- It is a library with three functions: `scan_source(source)`, `scan_file(path)` and `scan_directory(path)`. Each returns a list of `Finding` dataclasses with the fields `cwe_id`, `title`, `description`, `severity`, `line`, `line_end`, `source`, `confidence`, `remediation`, `file_path` and `metadata`. `scan` is an alias for `scan_source`.
- Scanned code is parsed, never imported or executed.
- Within one file, findings are de-duplicated and sorted by severity.
- The 54 tests in `tests/` pass.

### Rules

Each rule carries a CWE id as a label. The label says what the rule is looking for. It does not mean that class of bug is covered.

| Label | What the rule flags |
|-------|---------------------|
| CWE-89 | `.execute()`, `.executemany()`, `.executescript()` or `.raw()` given an f-string, `+`, `%` or `.format()` string that contains an SQL keyword, or a variable that was assigned an interpolated string elsewhere in the file. Also any `+` or `%` string expression containing a word such as `select` or `from`. |
| CWE-79 | `mark_safe(html)`, `render_template_string(t)`, `render_string(t)`. `Response()` or `make_response()` given a literal HTML string. |
| CWE-22 | `open(p)`, `Path(p)` and any `.join(x)` call where the argument is a variable. |
| CWE-78 | `os.system(cmd)`, `os.popen(cmd)`. Any method named `call`, `run`, `Popen`, `check_output` or `check_call` with `shell=True` or a variable as an argument. `getattr(os, "system")`. `__import__("os")`. |
| CWE-94 | `eval(x)`, `exec(x)`, `compile(x, ...)`. `pickle.load`, `pickle.loads`, `marshal.load`, `marshal.loads`. `yaml.unsafe_load`, and `yaml.load` without a `Loader=` keyword naming `SafeLoader` or `FullLoader`. |
| CWE-200 | `DEBUG = True`. A string or number of four or more characters assigned to a variable whose name contains `password`, `secret`, `token`, `api_key`, `apikey`, `private_key` or `auth`. |
| CWE-269 | Any assignment to a variable named `allow_any`, `skip_auth`, `no_auth`, `disable_auth`, `trust_all`, `permit_all` or `open_access`. |
| CWE-352 | `csrf_exempt` used as a decorator or called. |

## What is not implemented

- No command-line tool. There is no console script, and `python -m corporeus` fails.
- Not published on PyPI. Install from a clone (see below).
- No JSON, SARIF or text report. Results are Python objects only.
- No exit codes, config file, exclude list or suppression comments. `# nosec` and `# noqa` have no effect, and `scan_directory` walks into `.venv`, `node_modules` and `.git`.
- No import resolution. Matching is on literal names, so `from os import system`, `import os as o` and `from pickle import loads` are all missed.
- No data-flow analysis. What the code calls taint tracking is one file-wide set of variable names that were assigned an interpolated string. It has no sources, no scopes, and loses track after `q2 = q`.
- Secret detection goes by variable name, not by the shape of the value.
- No rules for weak hashes, TLS verification, weak randomness, archive extraction or server-side request forgery.
- No rules that know about LLM applications, agent tools or MCP servers.
- No CI workflow in this repository.

## Install and run the tests

From a clone of this repository, inside a virtual environment:

```bash
pip install -e .
pip install pytest
pytest
```

The run ends with `54 passed`.

## Usage

Save this as `example.py`:

```python
from corporeus import scan_source

source = '''
import os
import subprocess

def run(cmd):
    os.system(cmd)
    subprocess.run(cmd, shell=True)

def label(names):
    return ", ".join(names)
'''

for f in scan_source(source):
    print(f"line {f.line}: {f.cwe_id} [{f.severity}] {f.title}")
```

`python example.py` prints:

```text
line 6: CWE-78 [critical] Command Injection via os.system()/os.popen()
line 7: CWE-78 [high] Command Injection via subprocess with shell=True
line 10: CWE-22 [medium] Potential Path Traversal in Path Construction
```

The third line is a false positive: joining a list of names is not a path operation.

## Known issues

- It fails open. A file that does not parse returns an empty list, the same as a clean file, with no error. That covers any syntax error and any file that starts with a UTF-8 byte-order mark.
- It is noisy. `", ".join(names)` is reported as path traversal and `runner.run(task)` as command injection. On the three other public Ember repositories ([EmberArmor](https://github.com/GrandMastaShake/EmberArmor), [EmberHoneypot](https://github.com/GrandMastaShake/EmberHoneypot), [EmberBench](https://github.com/GrandMastaShake/EmberBench)) it reported 73 findings on 2026-10-02. 56 of them came from those two rules, and on reading all 73, 1 was a real issue.
- `MAX_TOKENS = 4096` and `AUTHOR = "Jane Doe"` are reported as hardcoded secrets. The same secret string under a neutral variable name, in a dict value or in an annotated assignment is not reported, and any value containing `test`, `example`, `sample` or `dummy` is skipped.
- `SKIP_AUTH = False` is reported as a critical auth bypass. The value is never read.
- `Response("<html>static</html>")` is reported as XSS. `Response(f"<html>{user}</html>")` is not.
- `yaml.load(s, yaml.SafeLoader)`, with the loader passed positionally, is reported as critical.
- Two findings with the same label on one line collapse into one.
- `Finding.source` holds the full source line, so a flagged secret is repeated by anything that prints findings.
- `confidence` is a fixed number per rule, not something computed.
- The usage examples in the docstrings of `src/corporeus/__init__.py` and `src/corporeus/scanner.py` are wrong. The first contains a syntax error and so returns no findings; the second prints `CWE-CWE-78`.

## Direction

Corporeus is not under active development as a general scanner. If it continues, it will be narrowed to things the general tools do not cover, such as MCP server code and agent tool definitions.

## License

MIT. See [LICENSE](LICENSE).
