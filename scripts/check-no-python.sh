#!/bin/sh
# No-Python guard (Drake's rule, 2026-10-15: no Python anywhere in AIEN).
# Fails when git tracks any Python source, notebook, Python packaging file,
# or any file whose first line is a python shebang. POSIX sh, git and grep only.
# Usage: sh scripts/check-no-python.sh   (from anywhere inside the repository)
set -eu
cd "$(git rev-parse --show-toplevel)"

names='(^|/)(setup\.py|setup\.cfg|pyproject\.toml|Pipfile|Pipfile\.lock|requirements[^/]*\.txt|requirements[^/]*\.in)$|\.(py|pyi|pyw|pyx|ipynb)$'
# Tracked paths that match the name rule but are not Python, one ERE per line.
exempt=''

found=$(git ls-files | grep -E "$names" || true)
if [ -n "$exempt" ] && [ -n "$found" ]; then
  found=$(printf '%s\n' "$found" | grep -v -E "$exempt" || true)
fi
shebang=$(git grep -I -n -E '^#!.*python' -- . 2>/dev/null | grep -E '^[^:]+:1:' | cut -d: -f1 || true)

if [ -n "$found" ] || [ -n "$shebang" ]; then
  echo "no-python guard: FAIL. Python is not allowed in this repository. Offending tracked files:" >&2
  [ -n "$found" ] && printf '%s\n' "$found" | sed 's/^/  /' >&2
  [ -n "$shebang" ] && printf '%s\n' "$shebang" | sed 's/$/ (python shebang)/; s/^/  /' >&2
  exit 1
fi
echo "no-python guard: PASS ($(git ls-files | wc -l | tr -d ' ') tracked files, none is Python)"
