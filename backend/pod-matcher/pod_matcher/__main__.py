"""
pod_matcher/__main__.py

CLI entrypoint for M2 Pod Matcher.
Reads pod metadata from Postgres (written by M1), inspects images,
runs LLM matching, and writes entry-point results back to the pods table.

Usage:
    python -m pod_matcher \\
        --scan-id <uuid> \\
        --source-dir /path/to/source \\
        [--db postgresql://cara:secret@localhost/cara_rbac] \\
        [--model gpt-4o] \\
        [--output results.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import psycopg2
import structlog

from pod_matcher.cache import build_cache, make_cache_key
from pod_matcher.image_inspector import ImageInspector
from pod_matcher.llm_client import LLMClient

log = structlog.get_logger(__name__)


def collect_source_files(source_dir: str) -> list[str]:
    """
    Recursively list all source files in the repo directory.
    Filters to known source extensions; excludes vendor/node_modules/build dirs.
    """
    EXCLUDE_DIRS = {"vendor", "node_modules", ".git", "dist", "build", "__pycache__", ".venv"}
    SOURCE_EXTS = {".go", ".py", ".java", ".js", ".ts", ".rs", ".c", ".cpp", ".cs"}

    files = []
    for path in Path(source_dir).rglob("*"):
        if path.is_file() and path.suffix in SOURCE_EXTS:
            # Skip excluded directories anywhere in the path
            if not any(part in EXCLUDE_DIRS for part in path.parts):
                files.append(str(path.relative_to(source_dir)))
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description="M2 Pod Matcher — LLM pod-to-program matcher")
    parser.add_argument("--scan-id", required=True, help="Scan UUID from Postgres")
    parser.add_argument("--source-dir", required=True, help="Path to application source repository")
    parser.add_argument("--db", default=os.getenv("POSTGRES_URL"), help="Postgres connection URL")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model to use")
    parser.add_argument("--output", default="", help="Write results to JSON file instead of DB")
    args = parser.parse_args()

    if not args.db and not args.output:
        parser.error("--db or --output is required")

    log.info("m2_start", scan_id=args.scan_id, source_dir=args.source_dir, model=args.model)

    # Collect source file list once (shared across all pods in the scan)
    source_files = collect_source_files(args.source_dir)
    log.info("source_files_collected", count=len(source_files))

    # Load pods from Postgres (written by M1)
    pods = load_pods(args.db, args.scan_id)
    if not pods:
        log.warning("no_pods_found", scan_id=args.scan_id)
        sys.exit(0)

    inspector = ImageInspector()
    llm = LLMClient(model=args.model)
    cache = build_cache(args.db)

    results = []
    for pod in pods:
        pod_name = pod["pod_name"]
        namespace = pod["namespace"]
        image_ref = pod.get("image_ref", "")

        if not image_ref:
            log.warning("pod_no_image", pod=pod_name)
            continue

        # Check cache first
        digest = inspector.content_hash(image_ref)
        cache_key = make_cache_key(image_ref, digest)
        cached = cache.get(cache_key)

        if cached:
            log.info("cache_hit", pod=pod_name, image=image_ref)
            result = cached
        else:
            # Inspect image
            try:
                info = inspector.inspect(image_ref)
                info.language = inspector.detect_language(info)
            except Exception as exc:
                log.error("image_inspect_failed", pod=pod_name, image=image_ref, error=str(exc))
                continue

            # LLM match
            try:
                match = llm.match(
                    pod_name=pod_name,
                    namespace=namespace,
                    image_ref=image_ref,
                    entrypoint=info.entrypoint,
                    cmd=info.cmd,
                    source_files=source_files,
                )
                result = match.model_dump()
                cache.set(cache_key, result)
            except Exception as exc:
                log.error("llm_match_failed", pod=pod_name, error=str(exc))
                continue

        results.append({"pod_id": pod["id"], **result})

        # Update pods table with entry point info
        if args.db:
            update_pod_entry_point(args.db, pod["id"], result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        log.info("results_written", path=args.output, count=len(results))
    else:
        log.info("m2_complete", scan_id=args.scan_id, matched=len(results))


def load_pods(db_url: str, scan_id: str) -> list[dict]:
    """Load all pods for a scan from Postgres."""
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, pod_name, namespace, service_account
                FROM pods
                WHERE scan_id = %s
                """,
                (scan_id,),
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    finally:
        conn.close()


def update_pod_entry_point(db_url: str, pod_id: str, result: dict) -> None:
    """Write the matched entry point back to the pods table."""
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE pods
                SET main_executable  = %s,
                    entry_point_file = %s
                WHERE id = %s
                """,
                (result.get("main_executable"), result.get("entry_point_file"), pod_id),
            )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
