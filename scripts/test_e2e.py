#!/usr/bin/env python3
# scripts/test_e2e.py
# Automated End-to-End Integration Testing Suite for CARA-RBAC

import subprocess
import time
import json
import sys

# Test configurations
SCAN_ID = "22222222-2222-2222-2222-222222222222"
APP_ID = "22222222-2222-2222-2222-222222222222"
DB_URL = "postgresql://cara:cara_dev_secret@localhost:5432/cara_rbac?sslmode=disable"

def log_stage(msg):
    print(f"\n=======================================================")
    print(f"STAGE: {msg}")
    print(f"=======================================================")

def run_cmd(args, cwd=None):
    res = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Command failed: {' '.join(args)}")
        print(f"Stdout:\n{res.stdout}")
        print(f"Stderr:\n{res.stderr}")
        sys.exit(res.returncode)
    return res.stdout.strip()

def run_sql(sql):
    cmd = ["wsl.exe", "-u", "root", "docker", "exec", "-i", "cara-rbac_postgres_1", "psql", "-U", "cara", "-d", "cara_rbac", "-t", "-c", sql]
    return run_cmd(cmd)

def main():
    # ── STAGE 0: Service Lifecycle Management ────────────────────────────────
    log_stage("Restarting Runtime Monitor to clear cache")
    print("Killing existing monitor processes in WSL...")
    subprocess.run(["wsl.exe", "-u", "root", "sh", "-c", "fuser -k 8081/tcp || true"])
    subprocess.run(["wsl.exe", "-u", "root", "sh", "-c", "fuser -k 5060/tcp || true"])
    subprocess.run(["wsl.exe", "pkill", "-f", "cmd/monitor/main.go"])
    subprocess.run(["wsl.exe", "pkill", "-f", "monitor"])
    
    print("Starting runtime-monitor in background...")
    global log_file
    log_file = open("monitor.log", "w")
    monitor_proc = subprocess.Popen(
        ["wsl.exe", "sh", "-c", f"cd /mnt/c/Users/nites/OneDrive/Desktop/cara-rbac/backend/runtime-monitor && go run cmd/monitor/main.go --port 8081 --db '{DB_URL}'"],
        stdout=log_file,
        stderr=log_file
    )
    
    # Wait for monitor to boot
    time.sleep(3)
    
    try:
        # ── STAGE 1: Database Initialization ─────────────────────────────────────
        log_stage("Initializing Test Database State")
        
        # Clean previous records for this test scan ID
        print("Clearing database entries...")
        run_sql(f"DELETE FROM scans WHERE id = '{SCAN_ID}';")
        run_sql(f"DELETE FROM applications WHERE id = '{APP_ID}';")
        
        # Insert fresh records
        print("Seeding test application and scan entries...")
        run_sql(f"INSERT INTO applications (id, name, source_repo_url) VALUES ('{APP_ID}', 'E2E Test App', 'https://github.com/org/e2e-test');")
        run_sql(f"INSERT INTO scans (id, application_id, mode, status) VALUES ('{SCAN_ID}', '{APP_ID}', 'hybrid', 'running');")
        
        # Verify seeding
        scan_count = run_sql(f"SELECT COUNT(*) FROM scans WHERE id = '{SCAN_ID}';")
        assert scan_count.strip() == "1", "Scan entry was not successfully seeded!"
        print("Database successfully prepared.")
    
        # ── STAGE 2: Run M1 rbac-analyzer ───────────────────────────────────────
        log_stage("Running M1 rbac-analyzer Static Manifest Parser")
        
        cmd = [
            "wsl.exe", "sh", "-c",
            f"cd /mnt/c/Users/nites/OneDrive/Desktop/cara-rbac/backend/rbac-analyzer && go run cmd/analyzer/main.go --scan-id {SCAN_ID} --input testdata/sample-app.yaml --db '{DB_URL}'"
        ]
        print("Executing rbac-analyzer...")
        output = run_cmd(cmd)
        print(output)
        
        # Assert requested observations were parsed
        req_count = run_sql(f"SELECT COUNT(*) FROM permission_observations WHERE scan_id = '{SCAN_ID}' AND source = 'requested';")
        print(f"Observations written: {req_count.strip()}")
        assert int(req_count.strip()) > 0, "No requested observations were parsed by rbac-analyzer!"
        print("Phase A requested observations created.")
    
        # ── STAGE 3: Seed M2/M3/M4 Mock Observations ────────────────────────────
        log_stage("Seeding Mock Behavior (M2/M3) & Cluster Context (M4)")
        
        # Update pod entrypoint configs (M2 Pod Matcher result)
        print("Updating pod entrypoint configurations...")
        run_sql(f"UPDATE pods SET entry_point_file = 'main.go', main_executable = '/bin/api-server' WHERE scan_id = '{SCAN_ID}' AND pod_name = 'api-server';")
        run_sql(f"UPDATE pods SET entry_point_file = 'worker.py', main_executable = '/usr/bin/python' WHERE scan_id = '{SCAN_ID}' AND pod_name = 'worker';")
        
        # Find generated pod IDs
        api_pod_id = run_sql(f"SELECT id FROM pods WHERE scan_id = '{SCAN_ID}' AND pod_name = 'api-server';").strip()
        worker_pod_id = run_sql(f"SELECT id FROM pods WHERE scan_id = '{SCAN_ID}' AND pod_name = 'worker';").strip()
        
        print(f"Resolved Pod IDs: api-server={api_pod_id}, worker={worker_pod_id}")
        
        # Seed static CodeQL reachability (M3 Behavior Analyzer output)
        # We assert that the api-server can call "get" and "list" on "pods" and "get" on "secrets"
        print("Inserting static reachability observations...")
        run_sql(f"INSERT INTO permission_observations (scan_id, pod_id, source, verb, resource, scope) VALUES ('{SCAN_ID}', '{api_pod_id}', 'static', 'get', 'secrets', 'namespace');")
        run_sql(f"INSERT INTO permission_observations (scan_id, pod_id, source, verb, resource, scope) VALUES ('{SCAN_ID}', '{api_pod_id}', 'static', 'get', 'pods', 'namespace');")
        run_sql(f"INSERT INTO permission_observations (scan_id, pod_id, source, verb, resource, scope) VALUES ('{SCAN_ID}', '{api_pod_id}', 'static', 'list', 'pods', 'namespace');")
        run_sql(f"INSERT INTO permission_observations (scan_id, pod_id, source, verb, resource, scope) VALUES ('{SCAN_ID}', '{worker_pod_id}', 'static', 'get', 'pods', 'namespace');")
        
        # Seed cluster context observations (M4 Cluster Collector output)
        print("Inserting live cluster context observations...")
        run_sql(f"INSERT INTO permission_observations (scan_id, pod_id, source, verb, resource, scope) VALUES ('{SCAN_ID}', '{api_pod_id}', 'cluster', 'get', 'secrets', 'namespace');")
        run_sql(f"INSERT INTO permission_observations (scan_id, pod_id, source, verb, resource, scope) VALUES ('{SCAN_ID}', '{api_pod_id}', 'cluster', 'get', 'pods', 'namespace');")
        run_sql(f"INSERT INTO permission_observations (scan_id, pod_id, source, verb, resource, scope) VALUES ('{SCAN_ID}', '{worker_pod_id}', 'cluster', 'get', 'pods', 'namespace');")
        print("Mock reachability and bindings seeded.")
    
        # ── STAGE 4: Stream Runtime Events to M5 Monitor ────────────────────────
        log_stage("Streaming Dynamic Runtime Events via M5 Runtime Monitor")
        
        # Events payload mapping
        events = [
            {"scan_id": SCAN_ID, "pod_name": "api-server-79b8979fc-2tflm", "namespace": "sample-app", "verb": "get", "resource": "secrets", "is_startup": True},
            {"scan_id": SCAN_ID, "pod_name": "api-server-79b8979fc-2tflm", "namespace": "sample-app", "verb": "get", "resource": "pods", "is_startup": False},
            {"scan_id": SCAN_ID, "pod_name": "worker-f38b29f-x82kd", "namespace": "sample-app", "verb": "get", "resource": "pods", "is_startup": False}
        ]
        
        for i, ev in enumerate(events):
            payload = json.dumps(ev)
            print(f"Posting event {i+1}: {ev['pod_name']} -> {ev['verb']} {ev['resource']}...")
            
            import urllib.request
            req = urllib.request.Request(
                "http://localhost:8081/api/v1/event",
                data=payload.encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            try:
                with urllib.request.urlopen(req) as response:
                    res = response.read().decode('utf-8')
                    print(f"Monitor Response: {res}")
            except Exception as ex:
                print(f"Post failed: {ex}")
                raise ex
            
        time.sleep(1) # Wait briefly for transactions to commit
        
        # Assert runtime observations were inserted
        run_count = run_sql(f"SELECT COUNT(*) FROM permission_observations WHERE scan_id = '{SCAN_ID}' AND source = 'runtime';")
        print(f"Runtime logs verified in Postgres: {run_count.strip()}")
        assert int(run_count.strip()) == 3, f"Expected 3 runtime observations, got {run_count.strip()}"
        print("Runtime event logging verified.")
    
        # ── STAGE 5: Run M6 False Positive Engine ────────────────────────────────
        log_stage("Executing M6 False Positive engine Classifications")
        
        cmd = [
            "wsl.exe", "sh", "-c",
            f"cd /mnt/c/Users/nites/OneDrive/Desktop/cara-rbac/backend/fp-engine && python3 -m fp_engine --scan-id {SCAN_ID} --db '{DB_URL}'"
        ]
        print("Running classification engine...")
        output = run_cmd(cmd)
        print(output)
        
        # Check classifications in database
        classes_summary = run_sql(f"SELECT class, COUNT(*) FROM classifications WHERE scan_id = '{SCAN_ID}' GROUP BY class;")
        print("Classification Summary Results:")
        print(classes_summary)
        
        # Verify classifications table is populated
        class_total = run_sql(f"SELECT COUNT(*) FROM classifications WHERE scan_id = '{SCAN_ID}';")
        assert int(class_total.strip()) > 0, "No permissions were classified by the FP engine!"
        print("Classification phase verified.")
    
        # ── STAGE 6: Run M7 Minimizer ───────────────────────────────────────────
        log_stage("Executing M7 Minimizer and Generating Rollback Script")
        
        cmd = [
            "wsl.exe", "sh", "-c",
            f"cd /mnt/c/Users/nites/OneDrive/Desktop/cara-rbac/backend/minimizer && go run cmd/minimizer/main.go --scan-id {SCAN_ID} --db '{DB_URL}'"
        ]
        print("Running minimizer...")
        output = run_cmd(cmd)
        print(output)
        
        # Verify output has reduction results
        reduction_pct = run_sql(f"SELECT reduction_pct FROM minimization_results WHERE scan_id = '{SCAN_ID}';")
        reduction_pcts = [float(val.strip()) for val in reduction_pct.strip().splitlines() if val.strip()]
        print(f"Permission Reduction Percentages: {reduction_pcts}")
        for pct in reduction_pcts:
            assert pct >= 0, "RBAC minimization resulted in negative savings!"
        assert any(pct > 0 for pct in reduction_pcts), "No reduction was achieved for any pod!"
        
        # Mark scan as completed
        print("Marking scan as completed in DB...")
        run_sql(f"UPDATE scans SET status = 'completed', completed_at = NOW() WHERE id = '{SCAN_ID}';")
        
        print("\n=======================================================")
        print("ALL END-TO-END PIPELINE CHECKS PASSED SUCCESSFULLY!")
        print("=======================================================")
    finally:
        print("\nStopping runtime-monitor process...")
        monitor_proc.terminate()
        try:
            log_file.close()
        except:
            pass
        subprocess.run(["wsl.exe", "-u", "root", "sh", "-c", "fuser -k 8081/tcp || true"])
        subprocess.run(["wsl.exe", "-u", "root", "sh", "-c", "fuser -k 5060/tcp || true"])
        subprocess.run(["wsl.exe", "pkill", "-f", "cmd/monitor/main.go"])
        subprocess.run(["wsl.exe", "pkill", "-f", "monitor"])
        print("Cleanup completed.")

if __name__ == "__main__":
    main()
