"""
pod_matcher/plugins/python_entry.py

Entry-point plugin for Python containers.

Resolves the actual source file from Python module paths found in CMD/ENTRYPOINT:
  - `python -m myapp.server`   → myapp/server.py
  - `python myapp/server.py`   → myapp/server.py
  - `gunicorn myapp.wsgi:app`  → myapp/wsgi.py
  - `uvicorn myapp.main:app`   → myapp/main.py
  - `celery -A tasks.app ...`  → tasks/app.py
  - `flask run`                → looks for app.py / wsgi.py / __init__.py
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

import structlog

log = structlog.get_logger(__name__)

# WSGI/ASGI module:callable pattern  e.g. "myapp.wsgi:application"
_MODULE_CALLABLE_RE = re.compile(r"^([\w.]+):\w+$")
# Celery app pattern: -A module.path
_CELERY_APP_RE = re.compile(r"-A\s+([\w.]+)")
# Gunicorn/uvicorn module pattern
_SERVER_MODULE_RE = re.compile(r"(gunicorn|uvicorn|daphne|hypercorn)\s+([\w.:]+)")


def resolve_entry_point(cmd: list[str], source_dir: str) -> Optional[str]:
    """
    Given a container CMD/entrypoint list, return the relative path to the
    Python source file that is the entry point.
    """
    full_cmd = " ".join(cmd)

    # --- Celery: celery -A tasks.app worker ... ---
    m = _CELERY_APP_RE.search(full_cmd)
    if m:
        return _module_to_path(m.group(1), source_dir)

    # --- WSGI/ASGI servers: gunicorn myapp.wsgi:app ---
    m = _SERVER_MODULE_RE.search(full_cmd)
    if m:
        module_ref = m.group(2)
        # Strip the :callable part
        module_path = module_ref.split(":")[0]
        return _module_to_path(module_path, source_dir)

    # --- python -m myapp.server ---
    if "-m" in cmd:
        idx = cmd.index("-m")
        if idx + 1 < len(cmd):
            return _module_to_path(cmd[idx + 1], source_dir)

    # --- python script.py ---
    for token in cmd:
        if token.endswith(".py") and not token.startswith("-"):
            candidate = os.path.join(source_dir, token)
            if os.path.exists(candidate):
                return token

    # --- Flask run: look for conventional entry points ---
    if "flask" in full_cmd or "run" in full_cmd:
        for name in ["app.py", "wsgi.py", "application.py", "main.py"]:
            if os.path.exists(os.path.join(source_dir, name)):
                return name

    log.warning("python_entry_point_not_found", cmd=full_cmd)
    return None


def _module_to_path(module_dotted: str, source_dir: str) -> Optional[str]:
    """
    Converts a dotted module path to a file path:
      "myapp.server" → "myapp/server.py"
      "myapp"        → "myapp/__init__.py"  or  "myapp.py"
    """
    relative = module_dotted.replace(".", os.sep)

    # Try as a module file first
    candidate_file = relative + ".py"
    if os.path.exists(os.path.join(source_dir, candidate_file)):
        return candidate_file

    # Try as a package __init__.py
    candidate_init = os.path.join(relative, "__init__.py")
    if os.path.exists(os.path.join(source_dir, candidate_init)):
        return candidate_init

    log.warning("python_module_not_found", module=module_dotted, source_dir=source_dir)
    return candidate_file  # Return best guess even if not found
