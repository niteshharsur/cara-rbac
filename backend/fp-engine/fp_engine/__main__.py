"""
fp_engine/__main__.py

CLI entrypoint for M6 False Positive Engine.
Processes requested, static, and runtime permissions to classify them into the 6 CARA-RBAC classes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import math
from decimal import Decimal
import psycopg2
import psycopg2.extras
import structlog

log = structlog.get_logger(__name__)

# Sensitive verbs in Kubernetes RBAC
SENSITIVE_VERBS = {"*", "create", "update", "patch", "delete", "deletecollection", "bind", "escalate", "impersonate"}

# Sensitive resources in Kubernetes RBAC
SENSITIVE_RESOURCES = {"*", "secrets", "pods", "deployments", "roles", "rolebindings", "clusterroles", "clusterrolebindings", "namespaces"}

def load_observations(db_url: str, scan_id: str) -> list[dict]:
    """
    Loads all permission observations for the given scan ID.
    """
    log.info("loading_observations", scan_id=scan_id)
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, pod_id, source, verb, resource, api_group, scope, is_startup_only, observed_count, call_site_file, call_site_line
                FROM permission_observations
                WHERE scan_id = %s
                """,
                (scan_id,)
            )
            return list(cur.fetchall())
    finally:
        conn.close()

def save_classifications(db_url: str, scan_id: str, classifications: list[dict]):
    """
    Saves classifications back to the classifications table.
    """
    log.info("saving_classifications", count=len(classifications))
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            # Delete existing classifications for this scan first
            cur.execute("DELETE FROM classifications WHERE scan_id = %s", (scan_id,))

            insert_query = """
                INSERT INTO classifications
                  (scan_id, pod_id, verb, resource, scope, class, confidence, confidence_band, threat_score, rationale, evidence_ref, confidence_score)
                VALUES
                  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            for cl in classifications:
                cur.execute(
                    insert_query,
                    (
                        scan_id,
                        cl["pod_id"],
                        cl["verb"],
                        cl["resource"],
                        cl["scope"],
                        cl["class"],
                        cl["confidence"],
                        cl["confidence_band"],
                        cl["threat_score"],
                        cl["rationale"],
                        psycopg2.extras.Json(cl["evidence_ref"]),
                        cl["confidence_score"]
                    )
                )
        conn.commit()
        log.info("classifications_saved_successfully")
    except Exception as e:
        conn.rollback()
        log.error("failed_to_save_classifications", error=str(e))
        raise e
    finally:
        conn.close()

def update_risk_scores(db_url: str, scan_id: str, classifications: list[dict]):
    """
    Computes and saves overall AppRiskScore and per-pod risk scores to scans and pods tables.
    """
    log.info("updating_risk_scores", scan_id=scan_id)
    if not classifications:
        return
    
    # Calculate pod-level risk averages
    pod_scores = {}
    for cl in classifications:
        pod_id = cl["pod_id"]
        ts = float(cl["threat_score"])
        if pod_id not in pod_scores:
            pod_scores[pod_id] = []
        pod_scores[pod_id].append(ts)
        
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            # Update each pod
            for pod_id, scores in pod_scores.items():
                avg_score = sum(scores) / len(scores) if scores else 0.0
                cur.execute(
                    "UPDATE pods SET pod_risk_score = %s WHERE id = %s",
                    (avg_score, pod_id)
                )
                
            # Update scan app risk
            all_scores = [float(cl["threat_score"]) for cl in classifications]
            app_risk = sum(all_scores) / len(all_scores) if all_scores else 0.0
            
            # Map explanation
            explanation = f"Scan risk score calculated dynamically as {app_risk:.2f} based on {len(all_scores)} analyzed permission classifications."
            if app_risk > 0.7:
                explanation += " CRITICAL: Multiple confirmed excess privileges (CEP) detected on sensitive resources."
            elif app_risk > 0.4:
                explanation += " WARNING: Medium-level threat scores detected across workloads."
            else:
                explanation += " Secure: Workload privileges match runtime behaviors closely."
                
            cur.execute(
                "UPDATE scans SET app_risk_score = %s, risk_explanation = %s WHERE id = %s",
                (app_risk, explanation, scan_id)
            )
        conn.commit()
        log.info("risk_scores_updated_successfully", app_risk=app_risk)
    except Exception as e:
        conn.rollback()
        log.error("failed_to_update_risk_scores", error=str(e))
        raise e
    finally:
        conn.close()

def make_key(verb: str, resource: str, api_group: str, scope: str) -> str:
    """
    Creates a unique string key for set matching.
    """
    return f"{verb}:{resource}:{api_group or ''}:{scope}"

def calculate_threat_score(klass: str, verb: str, resource: str) -> float:
    """
    Computes threat score based on classification class and risk of verb/resource.
    CEP (excess) gets high threat, SFP/SOP/RP get lower threat.
    """
    is_sensitive_verb = verb.lower() in SENSITIVE_VERBS
    is_sensitive_res = resource.lower() in SENSITIVE_RESOURCES
    severity = 1.0 if (is_sensitive_verb and is_sensitive_res) else (0.6 if (is_sensitive_verb or is_sensitive_res) else 0.2)

    if klass == "CEP":
        return round(0.7 + (severity * 0.3), 2)
    elif klass in ("DP", "DRP"):
        return round(0.5 + (severity * 0.3), 2)
    elif klass == "SFP":
        return round(0.2 + (severity * 0.2), 2)
    elif klass == "SOP":
        return round(0.1 + (severity * 0.1), 2)
    else: # RP (Required)
        return 0.0

def classify_permission(has_static: bool, has_runtime: bool, is_startup: bool, has_cluster: bool = False) -> tuple[str, float, str, str]:
    """
    Classifies a permission mapping based on static, runtime, and cluster signals.
    Returns: (class, confidence, confidence_band, rationale)
    """
    if has_cluster:
        return (
            "DRP",
            1.0,
            "HIGH",
            "Default Role Presence (DRP): Permission is already granted by pre-existing default cluster roles or inherited bindings."
        )
    elif not has_static and not has_runtime:
        return (
            "CEP",
            1.0,
            "HIGH",
            "Permission was explicitly requested in RBAC manifests, but is neither statically reachable in the code graph nor observed at runtime."
        )
    elif has_static and not has_runtime:
        return (
            "SFP",
            0.70,
            "MEDIUM",
            "Permission is statically reachable in code, but was never exercised during the runtime monitoring window. Keep with caution."
        )
    elif has_static and has_runtime:
        if is_startup:
            return (
                "SOP",
                0.90,
                "HIGH",
                "Permission is statically reachable and was exercised at runtime, but ONLY during the container startup window. Candidate for InitContainer isolation."
            )
        else:
            return (
                "RP",
                1.0,
                "HIGH",
                "Permission is fully validated — statically reachable in code and active during steady-state runtime operations."
            )
    else: # not has_static and has_runtime
        if is_startup:
            return (
                "DRP",
                0.50,
                "LOW",
                "Dynamic runtime permission observed only during container startup. Not statically visible in source code call graph."
            )
        else:
            return (
                "DP",
                0.50,
                "LOW",
                "Dynamic permission observed during steady-state runtime, but not statically visible in code graph. May indicate reflection or anomaly."
            )

def main():
    parser = argparse.ArgumentParser(description="M6 False Positive Engine")
    parser.add_argument("--scan-id", required=True, help="Scan UUID from Postgres")
    parser.add_argument("--db", default=os.getenv("POSTGRES_URL"), help="Postgres connection URL")
    parser.add_argument("--alpha", type=float, default=0.4, help="Static evidence weight coefficient")
    parser.add_argument("--beta", type=float, default=0.4, help="Runtime evidence weight coefficient")
    parser.add_argument("--gamma", type=float, default=0.2, help="Threat weight coefficient")
    args = parser.parse_args()

    if not args.db:
        parser.error("--db or POSTGRES_URL env var is required")

    log.info("fp_engine_start", scan_id=args.scan_id)

    # 1. Load observations
    obs_list = load_observations(args.db, args.scan_id)
    if not obs_list:
        log.warning("no_observations_found", scan_id=args.scan_id)
        sys.exit(0)

    # 2. Group observations by pod
    obs_by_pod = {}
    for obs in obs_list:
        pod_id = obs["pod_id"]
        if not pod_id:
            continue
        if pod_id not in obs_by_pod:
            obs_by_pod[pod_id] = []
        obs_by_pod[pod_id].append(obs)

    all_classifications = []

    # 3. Process each pod's observations
    for pod_id, pod_obs in obs_by_pod.items():
        requested = {}
        static = {}
        runtime = {}
        cluster = {}

        for obs in pod_obs:
            src = obs["source"]
            key = make_key(obs["verb"], obs["resource"], obs["api_group"], obs["scope"])
            if src == "requested":
                requested[key] = obs
            elif src == "static":
                static[key] = obs
            elif src == "runtime":
                runtime[key] = obs
            elif src == "cluster":
                cluster[key] = obs

        log.info("pod_observations", pod_id=pod_id, requested=len(requested), static=len(static), runtime=len(runtime), cluster=len(cluster))

        # Classify each requested permission
        for key, req_obs in requested.items():
            verb = req_obs["verb"]
            resource = req_obs["resource"]
            api_group = req_obs["api_group"]
            scope = req_obs["scope"]

            has_static = key in static
            has_runtime = key in runtime
            has_cluster = key in cluster

            is_startup = False
            obs_count = 0
            if has_runtime:
                is_startup = runtime[key].get("is_startup_only", False)
                obs_count = runtime[key].get("observed_count") or 0

            klass, _, _, rationale = classify_permission(has_static, has_runtime, is_startup, has_cluster)
            threat_score = calculate_threat_score(klass, verb, resource)

            # Confidence scoring C(p) = alpha*S(p) + beta*R(p) + gamma*T(p)
            S_p = 1.0 if has_static else 0.0
            # Runtime frequency weight using log(obs_count + 1) normalized roughly to cap at log(100)
            R_p = min(1.0, math.log(obs_count + 1) / math.log(100)) if has_runtime else 0.0
            T_p = threat_score

            confidence_score = (args.alpha * S_p) + (args.beta * R_p) + (args.gamma * T_p)
            confidence_score = max(0.0, min(1.0, confidence_score)) # clamp to [0,1]

            if confidence_score >= 0.7:
                confidence_band = "HIGH"
            elif confidence_score >= 0.4:
                confidence_band = "MEDIUM"
            else:
                confidence_band = "LOW"

            evidence = {}
            if klass == "SFP":
                evidence = {"call_site": static[key].get("call_site_file"), "line": static[key].get("call_site_line")}
            elif klass in ("SOP", "RP"):
                evidence = {
                    "call_site": static[key].get("call_site_file"),
                    "line": static[key].get("call_site_line"),
                    "runtime_count": obs_count
                }
            elif klass in ("DRP", "DP"):
                evidence = {
                    "runtime_count": obs_count
                }

            all_classifications.append({
                "pod_id": pod_id,
                "verb": verb,
                "resource": resource,
                "scope": scope,
                "class": klass,
                "confidence": confidence_score,
                "confidence_band": confidence_band,
                "threat_score": threat_score,
                "rationale": rationale,
                "evidence_ref": evidence,
                "confidence_score": confidence_score
            })

    # 4. Save results to DB
    if all_classifications:
        save_classifications(args.db, args.scan_id, all_classifications)
        update_risk_scores(args.db, args.scan_id, all_classifications)
    else:
        log.warning("no_classifications_created")

    log.info("fp_engine_completed", total_classifications=len(all_classifications))

if __name__ == "__main__":
    main()
