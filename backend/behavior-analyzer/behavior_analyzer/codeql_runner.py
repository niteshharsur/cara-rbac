"""
behavior_analyzer/codeql_runner.py

Wraps the CodeQL CLI to create databases, execute queries, and parse BQRS results.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
import structlog

log = structlog.get_logger(__name__)

class CodeQLRunner:
    def __init__(self, cli_path: str = "codeql"):
        self.cli_path = cli_path

    def _run_cmd(self, args: list[str]) -> subprocess.CompletedProcess:
        """
        Helper to execute a command with logging.
        """
        cmd = [self.cli_path] + args
        log.info("executing_codeql_cmd", command=" ".join(cmd))
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res
        except subprocess.CalledProcessError as e:
            log.error(
                "codeql_cmd_failed",
                command=" ".join(cmd),
                exit_code=e.returncode,
                stdout=e.stdout,
                stderr=e.stderr
            )
            raise e

    def create_database(self, repo_dir: Path, db_dir: Path, language: str) -> bool:
        """
        Creates a CodeQL database of the repository for the specified language.
        """
        if db_dir.exists():
            log.info("removing_existing_db_dir", path=str(db_dir))
            shutil.rmtree(db_dir)

        args = [
            "database", "create",
            str(db_dir),
            f"--language={language}",
            f"--source-root={repo_dir}",
        ]
        
        # Go build requires setting build commands if go version is old, but default auto-builder works fine
        # We can pass --overwrite flag as well, but manual deletion is safer.
        try:
            self._run_cmd(args)
            return True
        except Exception:
            return False

    def run_query(self, db_dir: Path, query_file: Path, bqrs_file: Path) -> bool:
        """
        Runs a CodeQL query against the database, outputting results in BQRS format.
        """
        bqrs_file.parent.mkdir(parents=True, exist_ok=True)
        if bqrs_file.exists():
            bqrs_file.unlink()

        args = [
            "query", "run",
            str(query_file),
            f"--database={db_dir}",
            f"--output={bqrs_file}"
        ]
        try:
            self._run_cmd(args)
            return True
        except Exception:
            return False

    def decode_bqrs(self, bqrs_file: Path, output_json: Path) -> list[dict]:
        """
        Decodes BQRS binary result into standard JSON, then parses it into list of dicts.
        """
        if output_json.exists():
            output_json.unlink()

        args = [
            "bqrs", "decode",
            str(bqrs_file),
            "--format=json",
            f"--output={output_json}"
        ]
        try:
            self._run_cmd(args)
            
            with open(output_json, "r", encoding="utf-8") as f:
                data = json.load(f)

            # CodeQL BQRS JSON structure:
            # {
            #   "#select": {
            #     "columns": [{"name": "col1", "type": "string"}, ...],
            #     "tuples": [[val1, val2], ...]
            #   }
            # }
            select_data = data.get("#select", {})
            columns = [col["name"] for col in select_data.get("columns", [])]
            tuples = select_data.get("tuples", [])

            results = []
            for t in tuples:
                # Map each tuple back to key-value dict matching column names
                row = {}
                for idx, col_name in enumerate(columns):
                    # Sometimes values in CodeQL BQRS JSON are dicts representing entity details:
                    # {"label": "myFunc", "url": {...}}
                    val = t[idx]
                    if isinstance(val, dict) and "label" in val:
                        row[col_name] = val["label"]
                    else:
                        row[col_name] = val
                results.append(row)

            return results
        except Exception as e:
            log.error("decode_bqrs_failed", error=str(e), bqrs_file=str(bqrs_file))
            return []
