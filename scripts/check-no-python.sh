#!/bin/sh
# No-Python guard (Drake's rule, 2026-10-15: no Python anywhere in AIEN).
# Fails when git tracks any Python source, notebook, Python packaging or
# environment file, or any file whose first line is a python shebang.
# POSIX sh, git, grep and head only.
# Usage: sh scripts/check-no-python.sh   (from anywhere inside the repository)
set -eu
cd "$(git rev-parse --show-toplevel)"

# File names are matched case-insensitively (Foo.PY counts).
names='(^|/)(setup\.py|setup\.cfg|pyproject\.toml|pipfile|pipfile\.lock|poetry\.lock|uv\.lock|\.python-version|requirements[^/]*\.txt|requirements[^/]*\.in)$|\.(py|pyi|pyw|pyx|pyc|ipynb)$'
# Tracked paths that match the name rule but are not Python (one ERE, empty for none).
exempt=''

# -z keeps non-ASCII names unquoted so the patterns see the real name.
found=$(git ls-files -z | tr '\0' '\n' | grep -i -E "$names" || true)
if [ -n "$exempt" ] && [ -n "$found" ]; then
  found=$(printf '%s\n' "$found" | grep -v -E "$exempt" || true)
fi
# Candidates contain a python shebang line anywhere; keep those where it is line 1.
shebang=$(git grep -I -l -z -i -E '^#!.*python' -- . 2>/dev/null | tr '\0' '\n' |
  while IFS= read -r f; do
    if head -n 1 -- "$f" | grep -q -i -E '^#!.*python'; then printf '%s\n' "$f"; fi
  done || true)

if [ -n "$found" ] || [ -n "$shebang" ]; then
  echo "no-python guard: FAIL. Python is not allowed in this repository. Offending tracked files:" >&2
  [ -n "$found" ] && printf '%s\n' "$found" | sed 's/^/  /' >&2
  [ -n "$shebang" ] && printf '%s\n' "$shebang" | sed 's/$/ (python shebang)/; s/^/  /' >&2
  exit 1
fi
echo "no-python guard: PASS ($(git ls-files | wc -l | tr -d ' ') tracked files, none is Python)"
