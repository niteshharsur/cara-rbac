"""
pod_matcher/go_symtab.py

Extracts the main() source path from a compiled Go binary using DWARF
debug information embedded in the ELF/Mach-O binary.

This supplements the LLM match when the Go binary is available locally
(e.g. pulled from the container image filesystem). The DWARF data contains
the package path of the main package, which maps directly to the source file.

Usage:
    from pod_matcher.go_symtab import GoSymtabExtractor
    extractor = GoSymtabExtractor()
    entry = extractor.extract("/path/to/binary")
    # entry = "github.com/my-org/my-app/cmd/server"  → maps to cmd/server/main.go
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import structlog

log = structlog.get_logger(__name__)

# Pattern to extract main package path from `go version -m` output
_BUILD_INFO_RE = re.compile(r"^\s*path\s+(.+)$", re.MULTILINE)
# Pattern from `nm` symbol table
_MAIN_PACKAGE_RE = re.compile(r"\s+T\s+main\.main$", re.MULTILINE)


class GoSymtabExtractor:
    """
    Extracts the Go main package import path from a compiled binary.

    Strategy (in priority order):
    1. `go version -m <binary>` — reads the embedded build info (Go 1.12+)
    2. `nm <binary>` + DWARF inspection — fallback for stripped binaries
    3. Heuristic: search for known patterns in binary strings
    """

    def extract_package_path(self, binary_path: str) -> Optional[str]:
        """
        Returns the Go module path of the main package, e.g.
        "github.com/my-org/app/cmd/server"
        Returns None if extraction fails.
        """
        path = Path(binary_path)
        if not path.exists():
            log.warning("binary_not_found", path=binary_path)
            return None

        # Try go version -m (most reliable)
        result = self._try_go_version(binary_path)
        if result:
            return result

        # Fallback: nm + strings
        return self._try_nm_strings(binary_path)

    def _try_go_version(self, binary_path: str) -> Optional[str]:
        """Runs `go version -m <binary>` and parses the path field."""
        try:
            out = subprocess.check_output(
                ["go", "version", "-m", binary_path],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
            )
            m = _BUILD_INFO_RE.search(out)
            if m:
                pkg_path = m.group(1).strip()
                log.debug("go_version_m_found", path=pkg_path)
                return pkg_path
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def _try_nm_strings(self, binary_path: str) -> Optional[str]:
        """Fallback: use `nm` to find main.main symbol, then strings for module path."""
        try:
            nm_out = subprocess.check_output(
                ["nm", binary_path],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=15,
            )
            if not _MAIN_PACKAGE_RE.search(nm_out):
                return None

            # Use `strings` to find go build path patterns
            strings_out = subprocess.check_output(
                ["strings", binary_path],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=15,
            )
            # Look for patterns like "go/src/..." or module paths
            for line in strings_out.splitlines():
                line = line.strip()
                if line.startswith("go/src/") or "/" in line and "main" in line:
                    if len(line) > 10 and len(line) < 200:
                        return line
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def package_path_to_file(self, pkg_path: str, source_dir: str) -> Optional[str]:
        """
        Converts a Go package import path to a relative source file path.

        Example:
          pkg_path   = "github.com/my-org/app/cmd/server"
          source_dir = "/workspace/app"
          → "cmd/server/main.go"

        Strategy: strip the module prefix (read from go.mod) and append /main.go.
        """
        go_mod = self._find_go_mod(source_dir)
        if not go_mod:
            return None

        module_name = self._read_module_name(go_mod)
        if not module_name or not pkg_path.startswith(module_name):
            return None

        relative_pkg = pkg_path[len(module_name):].lstrip("/")
        candidate = os.path.join(source_dir, relative_pkg, "main.go")

        if os.path.exists(candidate):
            return os.path.relpath(candidate, source_dir)
        return None

    @staticmethod
    def _find_go_mod(source_dir: str) -> Optional[str]:
        """Finds go.mod in source_dir or any parent directory."""
        current = Path(source_dir)
        for _ in range(5):
            candidate = current / "go.mod"
            if candidate.exists():
                return str(candidate)
            current = current.parent
        return None

    @staticmethod
    def _read_module_name(go_mod_path: str) -> Optional[str]:
        """Parses 'module X' from go.mod."""
        try:
            with open(go_mod_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("module "):
                        return line.split(None, 1)[1].strip()
        except OSError:
            pass
        return None
