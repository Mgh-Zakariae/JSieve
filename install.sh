#!/usr/bin/env bash
set -e

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

cat <<'MSG'
[+] JSieve installed successfully.
[+] Activate the environment with:
    source .venv/bin/activate

[+] Then use:
    jsieve -h

[!] External tools are still required for real scans: subfinder, httpx/httpx-toolkit, katana.
MSG
