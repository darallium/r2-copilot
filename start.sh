#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON_EXEC="$VENV_DIR/bin/python"

if [ ! -f "$PYTHON_EXEC" ]; then
  echo "Error: Python executable not found in the virtual environment at $VENV_DIR."
  exit 1
fi

"$PYTHON_EXEC" -m radare2_mcp.server "$@"

