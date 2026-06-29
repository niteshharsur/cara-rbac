"""
behavior_analyzer/__main__.py

CLI entrypoint for M3 Behavior Analyzer.
Orchestrates CodeQL database creation, query execution, call graph reachability,
and saves the static permission observations (P_static) to the DB.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
import psycopg2
import psycopg2.extras
import structlog

from behavior_analyzer.codeql_runner import CodeQLRunner
from behavior_analyzer.reachability import ReachabilityAnalyzer

log = structlog.get_logger(__name__)

def load_pods(db_url: str, scan_id: str) -> list[dict]:
    """
    Loads pods associated with the scan ID from the database.
    """
    log.info("loading_pods", scan_id=scan_id)
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, pod_name, namespace, entry_point_file FROM pods WHERE scan_id = %s",
                (scan_id,)
            )
            return list(cur.fetchall())
    finally:
        conn.close()

def save_static_observations(db_url: str, scan_id: str, observations: list[dict]):
    """
    Saves static permission observations to the permission_observations table.
    """
    log.info("saving_static_observations", count=len(observations))
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            # Delete any existing static observations for this scan first
            cur.execute(
                "DELETE FROM permission_observations WHERE scan_id = %s AND source = 'static'",
                (scan_id,)
            )

            # Insert new observations
            insert_query = """
                INSERT INTO permission_observations
                  (scan_id, pod_id, source, verb, resource, api_group, scope, call_site_file, call_site_line)
                VALUES
                  (%s, %s, 'static', %s, %s, %s, %s, %s, %s)
            """
            for obs in observations:
                cur.execute(
                    insert_query,
                    (
                        scan_id,
                        obs["pod_id"],
                        obs["verb"],
                        obs["resource"],
                        obs["api_group"],
                        obs["scope"],
                        obs["call_site_file"],
                        obs["call_site_line"]
                    )
                )
        conn.commit()
        log.info("static_observations_saved_successfully")
    except Exception as e:
        conn.rollback()
        log.error("failed_to_save_static_observations", error=str(e))
        raise e
    finally:
        conn.close()

def detect_language_from_ext(entry_point: str) -> str | None:
    """
    Heuristically detects programming language from file extension.
    """
    if not entry_point:
        return None
    suffix = Path(entry_point).suffix.lower()
    if suffix == ".go":
        return "go"
    elif suffix == ".py":
        return "python"
    elif suffix in (".java", ".jar"):
        return "java"
    elif suffix in (".js", ".ts"):
        return "javascript"
    return None

def main():
    parser = argparse.ArgumentParser(description="M3 Behavior Analyzer — CodeQL Reachability Analysis")
    parser.add_argument("--scan-id", required=True, help="Scan UUID from Postgres")
    parser.add_argument("--source-dir", required=True, help="Path to application source repository")
    parser.add_argument("--db", default=os.getenv("POSTGRES_URL"), help="Postgres connection URL")
    parser.add_argument("--codeql-path", default="codeql", help="Path to CodeQL CLI binary")
    args = parser.parse_args()

    if not args.db:
        parser.error("--db or POSTGRES_URL env var is required")

    log.info("m3_start", scan_id=args.scan_id, source_dir=args.source_dir)

    # 1. Load pods
    pods = load_pods(args.db, args.scan_id)
    if not pods:
        log.warning("no_pods_found_in_db", scan_id=args.scan_id)
        sys.exit(0)

    # 2. Group pods by language
    pods_by_lang = {}
    for pod in pods:
        ep = pod.get("entry_point_file")
        if not ep:
            log.warning("pod_missing_entry_point", pod=pod["pod_name"])
            continue
        lang = detect_language_from_ext(ep)
        if not lang:
            log.warning("unsupported_language_for_pod", pod=pod["pod_name"], file=ep)
            continue
        if lang not in pods_by_lang:
            pods_by_lang[lang] = []
        pods_by_lang[lang].append(pod)

    runner = CodeQLRunner(cli_path=args.codeql_path)
    
    # Establish a scratch workspace for CodeQL DBs
    scratch_dir = Path("C:/Users/nites/OneDrive/Desktop/cara-rbac/backend/behavior-analyzer/scratch")
    scratch_dir.mkdir(parents=True, exist_ok=True)

    all_static_observations = []

    # 3. For each language, run CodeQL and analyze reachability
    for lang, lang_pods in pods_by_lang.items():
        log.info("processing_language", language=lang, pod_count=len(lang_pods))

        db_dir = scratch_dir / f"codeql_db_{lang}"
        bqrs_file = scratch_dir / f"call_graph_{lang}.bqrs"
        json_file = scratch_dir / f"call_graph_{lang}.json"

        # Step 3a: Create database
        log.info("creating_codeql_database", lang=lang, db_dir=str(db_dir))
        success = runner.create_database(Path(args.source_dir), db_dir, lang)
        if not success:
            log.error("codeql_database_creation_failed", lang=lang)
            continue

        # Step 3b: Locate and run query
        # Resolve query file path relative to this script
        query_filename = f"go_call_graph.ql" if lang == "go" else "python_call_graph.ql"
        query_file = Path(__file__).parent.parent / "codeql-queries" / lang / query_filename
        
        # If folder structure differs, search under codeql-queries
        if not query_file.exists():
            query_file = Path(__file__).parent.parent / "codeql-queries" / query_filename

        log.info("running_codeql_query", query=str(query_file))
        success = runner.run_query(db_dir, query_file, bqrs_file)
        if not success:
            log.error("codeql_query_execution_failed", query=str(query_file))
            continue

        # Step 3c: Decode BQRS
        log.info("decoding_bqrs_results")
        rows = runner.decode_bqrs(bqrs_file, json_file)
        log.info("decoded_tuples", count=len(rows))

        # Step 3d: Build graph and run reachability
        analyzer = ReachabilityAnalyzer()
        if lang == "go":
            analyzer.load_go_calls(rows)
        elif lang == "python":
            analyzer.load_python_calls(rows)
        else:
            log.warning("unsupported_language_loaders", lang=lang)
            continue

        # Step 3e: Analyze each pod in this language group
        for pod in lang_pods:
            ep_file = pod["entry_point_file"]
            # Typically start function is "main"
            entry_func = "main"
            
            # Retrieve reachable K8s API calls
            reachable_calls = analyzer.analyze_reachability(ep_file, entry_func)
            
            for call in reachable_calls:
                mapped = call["mapped"]
                all_static_observations.append({
                    "pod_id": pod["id"],
                    "verb": mapped["verb"],
                    "resource": mapped["resource"],
                    "api_group": mapped["api_group"],
                    "scope": mapped["scope"],
                    "call_site_file": call["call_site_file"],
                    "call_site_line": call["call_site_line"]
                })

    # 4. Save results to Database
    if all_static_observations:
        save_static_observations(args.db, args.scan_id, all_static_observations)
    else:
        log.warning("no_static_observations_extracted_to_save")

    log.info("m3_completed", total_observations=len(all_static_observations))

if __name__ == "__main__":
    main()
