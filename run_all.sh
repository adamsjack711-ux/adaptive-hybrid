#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -z "${PYTHON:-}" ]; then
    PYTHON=python3
    if [ -x .venv/bin/python ]; then
        PYTHON=.venv/bin/python
    fi
fi
exec "$PYTHON" -u -m verification.run_all
