#!/bin/bash
# macOS: double-click to run. Keeps the window open to show the result.
cd "$(dirname "$0")" || exit 1
PY="$(command -v /opt/homebrew/bin/python3 /usr/local/bin/python3 python3 2>/dev/null | head -1)"
if [ -z "$PY" ]; then echo "Python 3 is needed: install it from https://www.python.org/downloads/"; else "$PY" gpcert.py renew; fi
echo; read -rsn1 -p "Press any key to close this window."
